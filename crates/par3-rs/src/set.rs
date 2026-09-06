//! Grouping packets into input sets and resolving their directory trees.
//!
//! Packets carry an InputSetID but no index, so a set is assembled rather than
//! read: collect every packet that shares an identifier, find the one Start and
//! the one Root packet, then walk the Root's children — File and Directory
//! packets named by their own header hashes — into paths.
//!
//! ```no_run
//! use par3_rs::{Par3Set, scan_packets_from_path};
//!
//! # fn main() -> par3_rs::Result<()> {
//! let packets = scan_packets_from_path("set.par3".as_ref())?
//!     .into_iter()
//!     .map(|(_offset, packet)| packet)
//!     .collect();
//! let sets = Par3Set::from_packets(packets)?;
//! for file in sets[0].files() {
//!     println!("{} ({} bytes)", file.path(), file.size());
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Par3Error, Result};
use crate::hash::{Fingerprint, FingerprintHasher, RollingHasher};
use crate::packet::{
    BlockChecksum, ChunkDescription, ChunkTail, DataPacket, DirectoryPacket, FilePacket,
    GaloisField, InputSetId, Packet, PacketBody, PacketType, ParseContext, RecoveryDataPacket,
    RecoveryExternalDataPacket, RootPacket, StartPacket,
};
use crate::scan::ScanLimits;

/// Bounds on resolving one set's directory tree.
///
/// The same File or Directory packet may legitimately appear under several
/// parents, which makes the tree a directed acyclic graph. A graph of `n`
/// directory packets can describe exponentially many paths, so the walk is
/// bounded rather than trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetLimits {
    /// Most files plus directories one set may resolve to.
    pub max_entries: usize,
    /// Deepest directory nesting the walk will follow.
    pub max_depth: usize,
    /// Most bytes of resolved path text one set may materialise.
    ///
    /// Counting entries is not enough on its own, because an entry costs its
    /// whole path rather than its own name: a graph two packets wide and `d`
    /// levels deep expands into `2^d` paths that are each `d` names long, so a
    /// set of a few kilobytes of packets with long names stays under
    /// [`max_entries`](SetLimits::max_entries) while asking for many gigabytes
    /// of strings. Every resolved file and directory path is charged against
    /// this, and exceeding it fails the set rather than truncating the tree.
    pub max_path_bytes: u64,
}

impl SetLimits {
    /// One million resolved entries.
    pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;
    /// 256 levels of nesting, comfortably beyond what any file system allows.
    pub const DEFAULT_MAX_DEPTH: usize = 256;
    /// 64 MiB of path text. A million files whose paths average 64 bytes fit
    /// inside it; the exponential expansion a directed acyclic tree can describe
    /// does not.
    pub const DEFAULT_MAX_PATH_BYTES: u64 = 64 << 20;
}

impl Default for SetLimits {
    fn default() -> Self {
        Self {
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_path_bytes: Self::DEFAULT_MAX_PATH_BYTES,
        }
    }
}

/// One input file, with the path resolved from the directory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par3File {
    path: String,
    packet_hash: Fingerprint,
    size: u64,
    packet: FilePacket,
}

impl Par3File {
    /// The file's path relative to the set's base directory, joined with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The file's own name, without any directory part.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.packet.name
    }

    /// The file's length: the sum of its chunk lengths.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The hash of the File packet, which is how the tree names this file.
    #[must_use]
    pub fn packet_hash(&self) -> Fingerprint {
        self.packet_hash
    }

    /// 16-byte BLAKE3 of the file's protected data. All zeros when unset.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.packet.fingerprint
    }

    /// CRC-64/GO-ISO of the file's first 16 KiB, or zero when unknown.
    #[must_use]
    pub fn quick_rolling_hash(&self) -> u64 {
        self.packet.quick_rolling_hash
    }

    /// The chunk descriptions, in file order.
    #[must_use]
    pub fn chunks(&self) -> &[ChunkDescription] {
        &self.packet.chunks
    }

    /// The underlying File packet.
    #[must_use]
    pub fn packet(&self) -> &FilePacket {
        &self.packet
    }
}

/// One input directory, with the path resolved from the directory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par3Directory {
    path: String,
    packet_hash: Fingerprint,
    packet: DirectoryPacket,
}

impl Par3Directory {
    /// The directory's path relative to the set's base directory.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The directory's own name, without any parent part.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.packet.name
    }

    /// The hash of the Directory packet.
    #[must_use]
    pub fn packet_hash(&self) -> Fingerprint {
        self.packet_hash
    }

    /// The underlying Directory packet.
    #[must_use]
    pub fn packet(&self) -> &DirectoryPacket {
        &self.packet
    }
}

/// One recovery block a set holds, from a Recovery Data packet that names the
/// set's own Root packet.
///
/// A Recovery Data packet is only meaningful together with the Root packet whose
/// input blocks it covers and the Matrix packet whose row produced it, so the
/// inventory records whether that Matrix packet is present. Nothing is computed
/// from the block; this says what recovery data exists, not how to use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBlock {
    index: u64,
    matrix_hash: Fingerprint,
    matrix_present: bool,
    packet: RecoveryDataPacket,
}

impl RecoveryBlock {
    /// The recovery block's index, which selects the matrix row it came from.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Hash of the Matrix packet whose row produced this block.
    #[must_use]
    pub fn matrix_hash(&self) -> Fingerprint {
        self.matrix_hash
    }

    /// Whether that Matrix packet is among the Matrix packets this crate
    /// recognises in the set.
    ///
    /// A recovery block whose matrix is missing cannot be interpreted, even
    /// though its bytes are intact. The check only sees the Matrix packets the
    /// crate parses — Cauchy, Sparse Random, Explicit and FFT — so a matrix of
    /// some type this crate does not know is reported absent even when its
    /// packet is sitting in the same file.
    #[must_use]
    pub fn matrix_present(&self) -> bool {
        self.matrix_present
    }

    /// The recovery block's stored bytes.
    ///
    /// Shorter than the set's block size when the writer trimmed trailing
    /// zeros; the reference implementation always writes a full block.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.packet.data
    }

    /// How many bytes the packet stores for this block.
    #[must_use]
    pub fn data_len(&self) -> usize {
        self.packet.data.len()
    }

    /// The Recovery Data packet this block came from.
    #[must_use]
    pub fn packet(&self) -> &RecoveryDataPacket {
        &self.packet
    }

    /// Whether the block matches a checksum from a Recovery External Data
    /// packet.
    ///
    /// Those checksums cover the block zero-padded to `block_size`, the same way
    /// input block checksums do, so the padding is hashed here rather than
    /// materialised. A block whose stored data is longer than `block_size`
    /// belongs to some other set's geometry and never matches.
    ///
    /// The cost is proportional to `block_size`, not to the stored data, because
    /// the padding still has to be hashed. `block_size` comes from a Start
    /// packet and is only as trustworthy as the file it was read from, so a
    /// `block_size` above [`ScanLimits::DEFAULT_MAX_PACKET_LEN`] returns `false`
    /// without hashing anything: a block that large could never have come out of
    /// a packet this crate reads with the default limits, and hashing towards
    /// `u64::MAX` would not finish.
    #[must_use]
    pub fn matches_checksum(&self, checksum: &BlockChecksum, block_size: u64) -> bool {
        if block_size > ScanLimits::DEFAULT_MAX_PACKET_LEN {
            return false;
        }
        let Some(padding) = block_size.checked_sub(self.data_len() as u64) else {
            return false;
        };
        let mut rolling = RollingHasher::new();
        rolling.update(self.data());
        rolling.update_zeros(padding);
        if rolling.finalize() != checksum.rolling_hash {
            return false;
        }
        let mut fingerprint = FingerprintHasher::new();
        fingerprint.update(self.data());
        fingerprint.update_zeros(padding);
        fingerprint.finalize() == checksum.fingerprint
    }
}

/// One PAR3 input set: everything that shares an InputSetID.
///
/// # What a set does not tell you
///
/// The parent InputSetID of an incremental backup is parsed and exposed, but this
/// crate does not follow it: a child set's files are resolved from its own Root
/// packet alone. Nor is anything computed from the Matrix or Recovery Data
/// packets — they are retained so a caller can see what recovery data exists, not
/// so it can be used.
#[derive(Debug, Clone)]
pub struct Par3Set {
    input_set_id: InputSetId,
    start: StartPacket,
    root: RootPacket,
    root_hash: Fingerprint,
    files: Vec<Par3File>,
    directories: Vec<Par3Directory>,
    block_checksums: BTreeMap<u64, BlockChecksum>,
    matrix_packets: Vec<Packet>,
    recovery_blocks: Vec<RecoveryBlock>,
    foreign_recovery_packets: Vec<RecoveryDataPacket>,
    conflicting_recovery_packets: usize,
    recovery_external_data: Vec<RecoveryExternalDataPacket>,
    recovery_block_checksums: BTreeMap<(Fingerprint, u64), BlockChecksum>,
    data_packets: Vec<DataPacket>,
    creator_texts: Vec<String>,
    comments: Vec<String>,
    option_packets: HashMap<Fingerprint, Packet>,
    duplicate_packet_count: usize,
    unknown_packet_count: usize,
    unparsed_packet_count: usize,
}

impl Par3Set {
    /// Build every input set described by `packets`, using default
    /// [`SetLimits`].
    ///
    /// Sets come back in ascending InputSetID order. Every set present must be
    /// well formed: a set missing its Start or Root packet, or carrying two
    /// different Root packets, fails the whole call rather than being dropped
    /// silently.
    pub fn from_packets(packets: Vec<Packet>) -> Result<Vec<Self>> {
        Self::from_packets_with_limits(packets, &SetLimits::default())
    }

    /// Build every input set described by `packets` under explicit limits.
    pub fn from_packets_with_limits(packets: Vec<Packet>, limits: &SetLimits) -> Result<Vec<Self>> {
        let mut grouped: BTreeMap<InputSetId, Vec<Packet>> = BTreeMap::new();
        for packet in packets {
            grouped
                .entry(packet.input_set_id())
                .or_default()
                .push(packet);
        }
        grouped
            .into_iter()
            .map(|(id, packets)| Self::build(id, packets, limits))
            .collect()
    }

    /// Build one named input set, ignoring packets belonging to any other.
    pub fn from_packets_for(packets: Vec<Packet>, input_set_id: InputSetId) -> Result<Self> {
        Self::from_packets_for_with_limits(packets, input_set_id, &SetLimits::default())
    }

    /// Build one named input set under explicit limits.
    pub fn from_packets_for_with_limits(
        packets: Vec<Packet>,
        input_set_id: InputSetId,
        limits: &SetLimits,
    ) -> Result<Self> {
        let mine: Vec<Packet> = packets
            .into_iter()
            .filter(|packet| packet.input_set_id() == input_set_id)
            .collect();
        if mine.is_empty() {
            return Err(Par3Error::UnknownInputSet { input_set_id });
        }
        Self::build(input_set_id, mine, limits)
    }

    fn build(input_set_id: InputSetId, packets: Vec<Packet>, limits: &SetLimits) -> Result<Self> {
        let mut seen: HashSet<(u64, Fingerprint)> = HashSet::new();
        let mut duplicate_packet_count = 0usize;
        let mut unique = Vec::with_capacity(packets.len());
        for packet in packets {
            if seen.insert((packet.len(), packet.hash())) {
                unique.push(packet);
            } else {
                duplicate_packet_count += 1;
            }
        }

        // The Start packet decides how File and Explicit Matrix packets read, so
        // it has to be found before anything else is interpreted.
        let mut start: Option<StartPacket> = None;
        for packet in &unique {
            if let PacketBody::Start(this) = packet.body() {
                match &start {
                    None => start = Some(this.clone()),
                    Some(existing) if existing == this => {}
                    Some(_) => return Err(Par3Error::ConflictingStartPackets { input_set_id }),
                }
            }
        }
        let start = start.ok_or(Par3Error::MissingStartPacket { input_set_id })?;
        let context = ParseContext::from_start(&start);

        let mut root: Option<(Fingerprint, RootPacket)> = None;
        let mut file_packets: HashMap<Fingerprint, FilePacket> = HashMap::new();
        let mut directory_packets: HashMap<Fingerprint, DirectoryPacket> = HashMap::new();
        let mut block_checksums: BTreeMap<u64, BlockChecksum> = BTreeMap::new();
        let mut matrix_packets = Vec::new();
        let mut recovery_packets = Vec::new();
        let mut recovery_external_data = Vec::new();
        let mut data_packets = Vec::new();
        let mut creator_texts = Vec::new();
        let mut comments = Vec::new();
        let mut option_packets: HashMap<Fingerprint, Packet> = HashMap::new();
        let mut unknown_packet_count = 0usize;
        let mut unparsed_packet_count = 0usize;

        for packet in unique {
            let hash = packet.hash();
            // A packet whose type needs the Start packet may have been read
            // before it was found; now that it has been, try again.
            let body = match packet.body() {
                PacketBody::Opaque { packet_type, body }
                    if PacketBody::needs_context(*packet_type) =>
                {
                    match PacketBody::parse(*packet_type, body, &context) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            tracing::debug!(%error, "PAR3 packet could not be parsed for its set");
                            unparsed_packet_count += 1;
                            continue;
                        }
                    }
                }
                other => other.clone(),
            };

            match body {
                PacketBody::Start(_) => {}
                PacketBody::Root(this) => match &root {
                    None => root = Some((hash, this)),
                    Some((_, existing)) if *existing == this => {}
                    Some(_) => return Err(Par3Error::ConflictingRootPackets { input_set_id }),
                },
                PacketBody::File(this) => {
                    file_packets.insert(hash, this);
                }
                PacketBody::Directory(this) => {
                    directory_packets.insert(hash, this);
                }
                PacketBody::ExternalData(this) => {
                    let first = this.first_block_index;
                    for (step, checksum) in this.checksums.into_iter().enumerate() {
                        let Some(index) = first.checked_add(step as u64) else {
                            break;
                        };
                        block_checksums.entry(index).or_insert(checksum);
                    }
                }
                PacketBody::CauchyMatrix(_)
                | PacketBody::SparseRandomMatrix(_)
                | PacketBody::ExplicitMatrix(_)
                | PacketBody::FftMatrix(_) => matrix_packets.push(packet),
                PacketBody::RecoveryData(this) => recovery_packets.push(this),
                PacketBody::RecoveryExternalData(this) => recovery_external_data.push(this),
                PacketBody::Data(this) => data_packets.push(this),
                PacketBody::Creator(this) => creator_texts.push(this.text().into_owned()),
                PacketBody::Comment(this) => comments.push(this.text().into_owned()),
                PacketBody::Opaque { packet_type, .. } => {
                    match packet_type {
                        PacketType::Link
                        | PacketType::UnixPermissions
                        | PacketType::FatPermissions => {
                            option_packets.insert(hash, packet);
                        }
                        PacketType::Unknown(_) => unknown_packet_count += 1,
                        // A reserved type this crate does know, but whose body
                        // did not parse. It is damage, not an extension.
                        _ => unparsed_packet_count += 1,
                    }
                }
            }
        }

        let (root_hash, root) = root.ok_or(Par3Error::MissingRootPacket { input_set_id })?;
        let block_count = root.lowest_unused_block_index;

        // Recovery data can only be placed once the Root packet is known, so the
        // inventory is built here rather than in the loop above. It takes
        // ownership of the packets instead of adding a second copy of each: a
        // recovery block is as large as an input block, and a set can hold
        // thousands of them.
        let matrix_hashes: HashSet<Fingerprint> = matrix_packets.iter().map(Packet::hash).collect();
        let mut recovery_blocks = Vec::new();
        let mut foreign_recovery_packets = Vec::new();
        for packet in recovery_packets {
            if packet.root_hash != root_hash {
                tracing::debug!(
                    index = packet.recovery_block_index,
                    "PAR3 recovery block names another set's Root packet"
                );
                foreign_recovery_packets.push(packet);
                continue;
            }
            recovery_blocks.push(RecoveryBlock {
                index: packet.recovery_block_index,
                matrix_hash: packet.matrix_hash,
                matrix_present: matrix_hashes.contains(&packet.matrix_hash),
                packet,
            });
        }
        // An index only means something against the matrix it selects a row of,
        // so two matrices in one set may each have a block 0. Sorting by index
        // first keeps the inventory in the order a caller expects to read it.
        recovery_blocks.sort_by_key(|block| (block.index, block.matrix_hash));
        let conflicting_recovery_packets =
            drop_conflicting_recovery_blocks(&mut recovery_blocks, input_set_id);

        let mut recovery_block_checksums: BTreeMap<(Fingerprint, u64), BlockChecksum> =
            BTreeMap::new();
        for external in &recovery_external_data {
            if external.root_hash != root_hash {
                continue;
            }
            let first = external.first_recovery_block_index;
            for (step, checksum) in external.checksums.iter().enumerate() {
                let Some(index) = first.checked_add(step as u64) else {
                    break;
                };
                recovery_block_checksums
                    .entry((external.matrix_hash, index))
                    .or_insert(*checksum);
            }
        }

        let mut walk = TreeWalk {
            input_set_id,
            limits,
            file_packets: &file_packets,
            directory_packets: &directory_packets,
            files: Vec::new(),
            directories: Vec::new(),
            path_bytes: 0,
        };
        walk.run(&root.children)?;
        let TreeWalk {
            mut files,
            mut directories,
            ..
        } = walk;

        for file in &files {
            check_block_indices(file, block_count, start.block_size)?;
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        directories.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self {
            input_set_id,
            start,
            root,
            root_hash,
            files,
            directories,
            block_checksums,
            matrix_packets,
            recovery_blocks,
            foreign_recovery_packets,
            conflicting_recovery_packets,
            recovery_external_data,
            recovery_block_checksums,
            data_packets,
            creator_texts,
            comments,
            option_packets,
            duplicate_packet_count,
            unknown_packet_count,
            unparsed_packet_count,
        })
    }

    /// The set's identifier.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        self.input_set_id
    }

    /// The set's Start packet.
    #[must_use]
    pub fn start(&self) -> &StartPacket {
        &self.start
    }

    /// The set's Root packet.
    #[must_use]
    pub fn root(&self) -> &RootPacket {
        &self.root
    }

    /// Hash of the Root packet, which Recovery Data packets refer back to.
    #[must_use]
    pub fn root_hash(&self) -> Fingerprint {
        self.root_hash
    }

    /// Input and recovery block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u64 {
        self.start.block_size
    }

    /// The set's input block count: the Root packet's lowest unused index.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.root.lowest_unused_block_index
    }

    /// The Galois field recovery data is computed over.
    #[must_use]
    pub fn galois_field(&self) -> GaloisField {
        self.start.galois_field
    }

    /// The parent set of an incremental backup, if there is one.
    ///
    /// The parent's packets are *not* followed: this set's files come from its
    /// own Root packet.
    #[must_use]
    pub fn parent_input_set_id(&self) -> Option<InputSetId> {
        self.start
            .has_parent()
            .then_some(self.start.parent_input_set_id)
    }

    /// Whether the tree describes an absolute path.
    #[must_use]
    pub fn is_absolute_path(&self) -> bool {
        self.root.is_absolute_path()
    }

    /// The input files, sorted by path.
    #[must_use]
    pub fn files(&self) -> &[Par3File] {
        &self.files
    }

    /// The input directories, sorted by path.
    #[must_use]
    pub fn directories(&self) -> &[Par3Directory] {
        &self.directories
    }

    /// Every input block checksum the set's External Data packets supply.
    ///
    /// Coverage is normally partial: the reference implementation omits blocks
    /// that hold chunk tails.
    #[must_use]
    pub fn block_checksums(&self) -> &BTreeMap<u64, BlockChecksum> {
        &self.block_checksums
    }

    /// The checksum for one input block, if the set carries it.
    #[must_use]
    pub fn block_checksum(&self, index: u64) -> Option<&BlockChecksum> {
        self.block_checksums.get(&index)
    }

    /// The set's Matrix packets, whichever kinds they are.
    #[must_use]
    pub fn matrix_packets(&self) -> &[Packet] {
        &self.matrix_packets
    }

    /// The recovery blocks this set holds, sorted by index and then by matrix
    /// hash, one per matrix and index.
    ///
    /// A recovery block index selects a row of the Matrix packet the block
    /// names, so a set holding two matrices — a Cauchy matrix and an FFT matrix,
    /// say — legitimately holds a block 0 for each. Only Recovery Data packets
    /// naming this set's Root packet are here.
    ///
    /// Identical copies — the reference implementation repeats packets across
    /// recovery volumes so that any one volume can stand alone — collapse into a
    /// single entry. Two packets that claim one matrix and index without sharing
    /// their contents cannot both be right, and nothing stored says which one is,
    /// so **neither** is listed: they are left out of the inventory and counted
    /// by
    /// [`conflicting_recovery_packet_count`](Par3Set::conflicting_recovery_packet_count).
    /// Damage to recovery data costs the caller that recovery data, not the set.
    #[must_use]
    pub fn recovery_blocks(&self) -> &[RecoveryBlock] {
        &self.recovery_blocks
    }

    /// How many Recovery Data packets were excluded for contradicting each
    /// other.
    ///
    /// Counts every packet in every group that claimed one matrix and index
    /// without agreeing on the bytes, not the number of groups — so two packets
    /// fighting over one index count as two.
    #[must_use]
    pub fn conflicting_recovery_packet_count(&self) -> usize {
        self.conflicting_recovery_packets
    }

    /// Recovery Data packets that named a Root packet other than this set's.
    ///
    /// An incremental backup's child set shares its parent's InputSetID lineage
    /// but has its own Root packet, so recovery data written for the parent can
    /// legitimately turn up alongside the child's packets. Such a block covers a
    /// different set of input blocks and must not be counted as this set's, but
    /// it is not damage either — so it is kept here, out of
    /// [`recovery_blocks`](Par3Set::recovery_blocks), rather than dropped or
    /// treated as an error.
    #[must_use]
    pub fn foreign_recovery_packets(&self) -> &[RecoveryDataPacket] {
        &self.foreign_recovery_packets
    }

    /// The set's Recovery External Data packets.
    #[must_use]
    pub fn recovery_external_data(&self) -> &[RecoveryExternalDataPacket] {
        &self.recovery_external_data
    }

    /// Checksums for recovery blocks held outside the set, keyed by the Matrix
    /// packet hash and the recovery block index.
    ///
    /// Built from the Recovery External Data packets that name this set's Root
    /// packet, the same way input block checksums are built from External Data
    /// packets. The matrix is part of the key for the same reason it is in
    /// [`recovery_blocks`](Par3Set::recovery_blocks): an index only picks out a
    /// row of the matrix its packet names. The reference implementation does not
    /// write these packets, so the map is usually empty.
    #[must_use]
    pub fn recovery_block_checksums(&self) -> &BTreeMap<(Fingerprint, u64), BlockChecksum> {
        &self.recovery_block_checksums
    }

    /// The checksum for one recovery block, if the set carries it.
    ///
    /// Pair it with [`RecoveryBlock::matches_checksum`] to check a block the set
    /// holds:
    ///
    /// ```no_run
    /// # fn example(set: &par3_rs::Par3Set) {
    /// for block in set.recovery_blocks() {
    ///     if let Some(checksum) = set.recovery_block_checksum(block.matrix_hash(), block.index()) {
    ///         assert!(block.matches_checksum(checksum, set.block_size()));
    ///     }
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn recovery_block_checksum(
        &self,
        matrix_hash: Fingerprint,
        index: u64,
    ) -> Option<&BlockChecksum> {
        self.recovery_block_checksums.get(&(matrix_hash, index))
    }

    /// Input blocks carried inside the set as Data packets.
    #[must_use]
    pub fn data_packets(&self) -> &[DataPacket] {
        &self.data_packets
    }

    /// Every Creator packet's text.
    ///
    /// The specification requires a client that cannot process a set to show
    /// this to the user, so it is returned rather than logged.
    #[must_use]
    pub fn creator_texts(&self) -> &[String] {
        &self.creator_texts
    }

    /// Every Comment packet's text.
    #[must_use]
    pub fn comments(&self) -> &[String] {
        &self.comments
    }

    /// An option packet — a link or a permissions packet — by its hash.
    ///
    /// These are retained verbatim; this crate does not interpret them.
    #[must_use]
    pub fn option_packet(&self, hash: &Fingerprint) -> Option<&Packet> {
        self.option_packets.get(hash)
    }

    /// How many packets were exact copies of one already seen.
    #[must_use]
    pub fn duplicate_packet_count(&self) -> usize {
        self.duplicate_packet_count
    }

    /// How many packets carried a type signature this crate does not know.
    #[must_use]
    pub fn unknown_packet_count(&self) -> usize {
        self.unknown_packet_count
    }

    /// How many packets carried a known type whose body could not be parsed.
    #[must_use]
    pub fn unparsed_packet_count(&self) -> usize {
        self.unparsed_packet_count
    }
}

/// Reject chunk descriptions that point outside the set's blocks, the way the
/// reference implementation does.
///
/// A chunk names a *range* of blocks, not just its first: `length / block_size`
/// full blocks starting at `first_block_index`. Checking the whole range here is
/// what lets verification walk it without a per-block guard, and is what stops a
/// chunk whose length says `u64::MAX` from claiming blocks the set never had.
fn check_block_indices(file: &Par3File, block_count: u64, block_size: u64) -> Result<()> {
    for chunk in file.chunks() {
        let ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } = chunk
        else {
            continue;
        };
        if let Some(index) = first_block_index
            && *index >= block_count
        {
            return Err(Par3Error::BlockIndexOutOfRange {
                index: *index,
                block_count,
            });
        }
        // The last full block the chunk claims. A zero block size describes no
        // blocks at all, and is rejected on its own terms by verification.
        if let Some(index) = first_block_index
            && block_size != 0
        {
            let blocks = length / block_size;
            if blocks != 0 {
                let last = index.checked_add(blocks - 1);
                if last.is_none_or(|last| last >= block_count) {
                    return Err(Par3Error::BlockIndexOutOfRange {
                        index: last.unwrap_or(u64::MAX),
                        block_count,
                    });
                }
            }
        }
        if let ChunkTail::Described { block_index, .. } = tail
            && *block_index >= block_count
        {
            return Err(Par3Error::BlockIndexOutOfRange {
                index: *block_index,
                block_count,
            });
        }
    }
    Ok(())
}

/// Depth-first walk of the Root packet's children into paths.
///
/// Iterative rather than recursive, so a deep or hostile tree cannot overflow
/// the stack, and bounded by [`SetLimits`] because the tree is a graph.
struct TreeWalk<'a> {
    input_set_id: InputSetId,
    limits: &'a SetLimits,
    file_packets: &'a HashMap<Fingerprint, FilePacket>,
    directory_packets: &'a HashMap<Fingerprint, DirectoryPacket>,
    files: Vec<Par3File>,
    directories: Vec<Par3Directory>,
    /// Path bytes resolved so far, charged against
    /// [`SetLimits::max_path_bytes`].
    path_bytes: u64,
}

struct Frame {
    hash: Option<Fingerprint>,
    path: String,
    children: Vec<Fingerprint>,
    next: usize,
}

impl TreeWalk<'_> {
    fn run(&mut self, root_children: &[Fingerprint]) -> Result<()> {
        let mut on_path: HashSet<Fingerprint> = HashSet::new();
        let mut stack = vec![Frame {
            hash: None,
            path: String::new(),
            children: root_children.to_vec(),
            next: 0,
        }];
        self.check_names(root_children, "")?;

        while let Some(frame) = stack.last_mut() {
            if frame.next >= frame.children.len() {
                if let Some(hash) = frame.hash {
                    on_path.remove(&hash);
                }
                stack.pop();
                continue;
            }
            let child = frame.children[frame.next];
            frame.next += 1;
            let parent_path = frame.path.clone();

            if self.files.len() + self.directories.len() >= self.limits.max_entries {
                return Err(Par3Error::ScanLimitExceeded {
                    reason: format!(
                        "input set {} resolves to more than {} entries",
                        self.input_set_id, self.limits.max_entries
                    ),
                });
            }

            if let Some(file) = self.file_packets.get(&child) {
                let size = file.file_size().ok_or_else(|| Par3Error::MalformedPacket {
                    packet: "File",
                    reason: format!("chunk lengths of {:?} overflow a u64", file.name),
                })?;
                let path = join_path(&parent_path, &file.name);
                self.charge_path(&path)?;
                self.files.push(Par3File {
                    path,
                    packet_hash: child,
                    size,
                    packet: file.clone(),
                });
                continue;
            }

            let Some(directory) = self.directory_packets.get(&child) else {
                return Err(Par3Error::MissingChildPacket {
                    input_set_id: self.input_set_id,
                    child: hex(&child),
                });
            };
            if !on_path.insert(child) {
                return Err(Par3Error::CyclicDirectoryTree {
                    input_set_id: self.input_set_id,
                });
            }
            let path = join_path(&parent_path, &directory.name);
            self.charge_path(&path)?;
            if stack.len() > self.limits.max_depth {
                return Err(Par3Error::ScanLimitExceeded {
                    reason: format!(
                        "input set {} nests deeper than {} directories",
                        self.input_set_id, self.limits.max_depth
                    ),
                });
            }
            self.check_names(&directory.children, &path)?;
            self.directories.push(Par3Directory {
                path: path.clone(),
                packet_hash: child,
                packet: directory.clone(),
            });
            stack.push(Frame {
                hash: Some(child),
                path,
                children: directory.children.clone(),
                next: 0,
            });
        }
        Ok(())
    }

    /// Charge one resolved path against [`SetLimits::max_path_bytes`].
    ///
    /// The entry count does not bound this: a path costs the whole chain of
    /// names above it, and the same packet may hang under many parents, so the
    /// text a graph expands into grows with both the number of paths and their
    /// depth. Charging here, where a path is first materialised, keeps the check
    /// off every other code path.
    fn charge_path(&mut self, path: &str) -> Result<()> {
        self.path_bytes = self.path_bytes.saturating_add(path.len() as u64);
        if self.path_bytes > self.limits.max_path_bytes {
            return Err(Par3Error::ScanLimitExceeded {
                reason: format!(
                    "input set {} resolves to more than {} bytes of paths",
                    self.input_set_id, self.limits.max_path_bytes
                ),
            });
        }
        Ok(())
    }

    /// Names inside one directory must be unique, and every child hash must
    /// resolve to a packet that is present.
    fn check_names(&self, children: &[Fingerprint], directory: &str) -> Result<()> {
        let mut names: HashSet<&str> = HashSet::new();
        for child in children {
            let name = if let Some(file) = self.file_packets.get(child) {
                file.name.as_str()
            } else if let Some(dir) = self.directory_packets.get(child) {
                dir.name.as_str()
            } else {
                return Err(Par3Error::MissingChildPacket {
                    input_set_id: self.input_set_id,
                    child: hex(child),
                });
            };
            if !names.insert(name) {
                return Err(Par3Error::DuplicateName {
                    name: name.to_owned(),
                    directory: directory.to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Drop every recovery block that shares its matrix and index with another, and
/// report how many packets that cost.
///
/// `blocks` must already be sorted by `(index, matrix_hash)`, so that blocks
/// claiming the same row of the same matrix sit next to each other.
fn drop_conflicting_recovery_blocks(
    blocks: &mut Vec<RecoveryBlock>,
    input_set_id: InputSetId,
) -> usize {
    let sorted = std::mem::take(blocks);
    let mut conflicting = 0;
    let mut run: Vec<RecoveryBlock> = Vec::new();
    for block in sorted {
        let key = (block.index, block.matrix_hash);
        if run
            .last()
            .is_some_and(|last| (last.index, last.matrix_hash) != key)
        {
            conflicting += flush_recovery_run(&mut run, blocks, input_set_id);
        }
        run.push(block);
    }
    conflicting + flush_recovery_run(&mut run, blocks, input_set_id)
}

/// Move one run of recovery blocks claiming the same matrix row into the
/// inventory, or, if the run holds more than one of them, drop the whole run and
/// report how many packets that was.
///
/// Identical packets are already collapsed by the packet-hash deduplication, so
/// a run longer than one means genuinely different bytes claiming one row.
/// Nothing stored says which of them is right, so none of them is kept: a set
/// with a junk recovery packet appended must still list and verify its files.
fn flush_recovery_run(
    run: &mut Vec<RecoveryBlock>,
    inventory: &mut Vec<RecoveryBlock>,
    input_set_id: InputSetId,
) -> usize {
    if run.len() < 2 {
        inventory.append(run);
        return 0;
    }
    tracing::debug!(
        %input_set_id,
        index = run[0].index,
        matrix = hex(&run[0].matrix_hash),
        packets = run.len(),
        "PAR3 recovery blocks contradict each other; excluding all of them"
    );
    let conflicting = run.len();
    run.clear();
    conflicting
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn hex(bytes: &Fingerprint) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{fingerprint, rolling_hash};
    use crate::packet::{
        BlockRange, CauchyMatrixPacket, CommentPacket, CreatorPacket, ExternalDataPacket,
        FftMatrixPacket, FilePacket, RootPacket,
    };

    fn start_packet() -> StartPacket {
        StartPacket {
            parent_input_set_id: InputSetId::ZERO,
            parent_root_hash: [0u8; 16],
            block_size: 2000,
            galois_field: GaloisField {
                size: 1,
                generator: 0x1d,
            },
            legacy_random: None,
        }
    }

    fn file_packet(name: &str, length: u64, first: Option<u64>) -> FilePacket {
        FilePacket {
            name: name.to_owned(),
            quick_rolling_hash: 0,
            fingerprint: [0u8; 16],
            option_hashes: Vec::new(),
            chunks: vec![ChunkDescription::Protected {
                length,
                first_block_index: first,
                tail: ChunkTail::None,
            }],
        }
    }

    const ID: InputSetId = InputSetId([1, 2, 3, 4, 5, 6, 7, 8]);

    fn packet(body: PacketBody) -> Packet {
        Packet::new(ID, body)
    }

    #[test]
    fn resolves_files_and_directories_into_paths() {
        let file = packet(PacketBody::File(file_packet("c.bin", 4000, Some(0))));
        let directory = packet(PacketBody::Directory(DirectoryPacket {
            name: "sub".to_owned(),
            option_hashes: Vec::new(),
            children: vec![file.hash()],
        }));
        let top = packet(PacketBody::File(file_packet("a.bin", 2000, Some(2))));
        let root = packet(PacketBody::Root(RootPacket {
            lowest_unused_block_index: 3,
            attributes: 0,
            option_hashes: Vec::new(),
            children: vec![directory.hash(), top.hash()],
        }));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Creator(CreatorPacket::new("test client"))),
            packet(PacketBody::Comment(CommentPacket::new("a comment"))),
            file,
            directory,
            top,
            root,
        ];

        let sets = Par3Set::from_packets(packets).expect("builds");
        assert_eq!(sets.len(), 1);
        let set = &sets[0];
        assert_eq!(set.block_size(), 2000);
        assert_eq!(set.block_count(), 3);
        assert_eq!(set.galois_field().polynomial(), Some(0x11d));
        assert_eq!(
            set.files().iter().map(Par3File::path).collect::<Vec<_>>(),
            vec!["a.bin", "sub/c.bin"]
        );
        assert_eq!(set.files()[1].name(), "c.bin");
        assert_eq!(set.files()[1].size(), 4000);
        assert_eq!(set.directories().len(), 1);
        assert_eq!(set.directories()[0].path(), "sub");
        assert_eq!(set.creator_texts(), ["test client"]);
        assert_eq!(set.comments(), ["a comment"]);
        assert_eq!(set.duplicate_packet_count(), 0);
    }

    #[test]
    fn duplicate_packets_are_counted_once() {
        let root = packet(PacketBody::Root(RootPacket {
            lowest_unused_block_index: 0,
            attributes: 0,
            option_hashes: Vec::new(),
            children: Vec::new(),
        }));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Start(start_packet())),
            root.clone(),
            root,
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.duplicate_packet_count(), 2);
        assert!(set.files().is_empty());
    }

    #[test]
    fn unknown_packets_are_retained_and_counted() {
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 0,
                attributes: 0,
                option_hashes: Vec::new(),
                children: Vec::new(),
            })),
            packet(PacketBody::Opaque {
                packet_type: PacketType::Unknown(*b"MINE\0abc"),
                body: b"payload".to_vec(),
            }),
            packet(PacketBody::Opaque {
                packet_type: PacketType::UnixPermissions,
                body: b"permissions".to_vec(),
            }),
        ];
        let option_hash = packets[3].hash();
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.unknown_packet_count(), 1);
        assert!(set.option_packet(&option_hash).is_some());
    }

    #[test]
    fn external_data_populates_the_block_checksums() {
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 5,
                attributes: 0,
                option_hashes: Vec::new(),
                children: Vec::new(),
            })),
            packet(PacketBody::ExternalData(ExternalDataPacket {
                first_block_index: 3,
                checksums: vec![
                    BlockChecksum {
                        rolling_hash: 30,
                        fingerprint: [3u8; 16],
                    },
                    BlockChecksum {
                        rolling_hash: 40,
                        fingerprint: [4u8; 16],
                    },
                ],
            })),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.block_checksums().len(), 2);
        assert_eq!(set.block_checksum(3).expect("present").rolling_hash, 30);
        assert_eq!(set.block_checksum(4).expect("present").rolling_hash, 40);
        assert!(set.block_checksum(2).is_none());
    }

    #[test]
    fn a_missing_start_packet_is_refused() {
        let packets = vec![packet(PacketBody::Root(RootPacket {
            lowest_unused_block_index: 0,
            attributes: 0,
            option_hashes: Vec::new(),
            children: Vec::new(),
        }))];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::MissingStartPacket { .. })
        ));
    }

    #[test]
    fn a_missing_root_packet_is_refused() {
        let packets = vec![packet(PacketBody::Start(start_packet()))];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::MissingRootPacket { .. })
        ));
    }

    #[test]
    fn two_distinct_root_packets_are_refused() {
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 0,
                attributes: 0,
                option_hashes: Vec::new(),
                children: Vec::new(),
            })),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 1,
                attributes: 0,
                option_hashes: Vec::new(),
                children: Vec::new(),
            })),
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::ConflictingRootPackets { .. })
        ));
    }

    #[test]
    fn two_distinct_start_packets_are_refused() {
        let mut other = start_packet();
        other.block_size = 4000;
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Start(other)),
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::ConflictingStartPackets { .. })
        ));
    }

    #[test]
    fn a_missing_child_packet_is_reported() {
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 1,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![[0xab; 16]],
            })),
        ];
        let error = Par3Set::from_packets(packets).expect_err("refused");
        match error {
            Par3Error::MissingChildPacket { child, .. } => {
                assert_eq!(child, "ab".repeat(16));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn duplicate_names_in_one_directory_are_refused() {
        let one = packet(PacketBody::File(file_packet("same", 2000, Some(0))));
        let two = packet(PacketBody::File(file_packet("same", 4000, Some(0))));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 3,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![one.hash(), two.hash()],
            })),
            one,
            two,
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::DuplicateName { .. })
        ));
    }

    #[test]
    fn a_block_index_beyond_the_block_count_is_refused() {
        let file = packet(PacketBody::File(file_packet("a.bin", 2000, Some(9))));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 3,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![file.hash()],
            })),
            file,
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::BlockIndexOutOfRange { index: 9, .. })
        ));
    }

    #[test]
    fn a_chunk_whose_block_range_ends_beyond_the_block_count_is_refused() {
        // The first index is inside the set, so only checking that one lets the
        // chunk claim every block after it as well: four 2000-byte blocks
        // starting at index 1, in a set that has three blocks in total.
        let file = packet(PacketBody::File(file_packet("a.bin", 8000, Some(1))));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 3,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![file.hash()],
            })),
            file,
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::BlockIndexOutOfRange {
                index: 4,
                block_count: 3
            })
        ));
    }

    #[test]
    fn a_chunk_length_that_overflows_the_block_range_is_refused() {
        // `length / block_size` blocks from the highest index there is: the end
        // of the range does not fit in a `u64` at all.
        let file = packet(PacketBody::File(file_packet(
            "a.bin",
            u64::MAX,
            Some(u64::MAX - 1),
        )));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: u64::MAX,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![file.hash()],
            })),
            file,
        ];
        assert!(matches!(
            Par3Set::from_packets(packets),
            Err(Par3Error::BlockIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn a_cyclic_directory_tree_is_refused() {
        // A directory whose child list names its own packet hash. Building that
        // by hand needs the hash before the packet exists, so instead two
        // directories point at each other through a fixed hash pair: the outer
        // one is reachable from the root and names the inner, which names the
        // outer straight back.
        let mut outer = DirectoryPacket {
            name: "outer".to_owned(),
            option_hashes: Vec::new(),
            children: Vec::new(),
        };
        let outer_hash = Packet::new(ID, PacketBody::Directory(outer.clone())).hash();
        let inner = DirectoryPacket {
            name: "inner".to_owned(),
            option_hashes: Vec::new(),
            children: vec![outer_hash],
        };
        let inner_packet = packet(PacketBody::Directory(inner));
        outer.children = vec![inner_packet.hash()];
        let outer_packet = packet(PacketBody::Directory(outer));

        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 1,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![outer_packet.hash()],
            })),
            outer_packet,
            inner_packet,
        ];
        // The cycle is only reachable if the placeholder hash happened to match,
        // which it will not; the walk instead reports the child it cannot find.
        assert!(Par3Set::from_packets(packets).is_err());
    }

    #[test]
    fn the_entry_limit_bounds_a_wide_tree() {
        let file = packet(PacketBody::File(file_packet("a.bin", 2000, Some(0))));
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(RootPacket {
                lowest_unused_block_index: 3,
                attributes: 0,
                option_hashes: Vec::new(),
                children: vec![file.hash()],
            })),
            file,
        ];
        let limits = SetLimits {
            max_entries: 0,
            ..SetLimits::default()
        };
        assert!(matches!(
            Par3Set::from_packets_with_limits(packets, &limits),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    /// A directed acyclic graph two packets wide and `levels` deep, with
    /// `name_len`-byte names: every packet on a level is a child of both packets
    /// on the level above, which is acyclic and repeats no name inside any one
    /// directory, yet describes `2^levels` distinct paths.
    fn wide_dag(levels: usize, name_len: usize) -> Vec<Packet> {
        let name = |level: usize, side: char| format!("{side}{level:02}{}", "n".repeat(name_len));
        let mut packets = Vec::new();
        let mut children: Vec<Fingerprint> = ['a', 'b']
            .into_iter()
            .map(|side| {
                let leaf = packet(PacketBody::File(file_packet(
                    &name(levels, side),
                    2000,
                    Some(0),
                )));
                let hash = leaf.hash();
                packets.push(leaf);
                hash
            })
            .collect();
        for level in (0..levels).rev() {
            children = ['a', 'b']
                .into_iter()
                .map(|side| {
                    let directory = packet(PacketBody::Directory(DirectoryPacket {
                        name: name(level, side),
                        option_hashes: Vec::new(),
                        children: children.clone(),
                    }));
                    let hash = directory.hash();
                    packets.push(directory);
                    hash
                })
                .collect();
        }
        packets.push(packet(PacketBody::Start(start_packet())));
        packets.push(packet(PacketBody::Root(RootPacket {
            lowest_unused_block_index: 1,
            attributes: 0,
            option_hashes: Vec::new(),
            children,
        })));
        packets
    }

    #[test]
    fn the_path_byte_limit_bounds_a_directory_graph() {
        // Eighteen levels of two 2 KiB names: under 80 KiB of packets, inside
        // both the entry and the depth limits, and worth 786,430 entries whose
        // paths come to more than seventeen gigabytes. Charging the bytes stops
        // it after a megabyte of them.
        let packets = wide_dag(18, 2048);
        assert!(packets.len() < 64);
        let limits = SetLimits {
            max_path_bytes: 1 << 20,
            ..SetLimits::default()
        };
        assert!(matches!(
            Par3Set::from_packets_with_limits(packets, &limits),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    #[test]
    fn a_graph_that_fits_the_path_budget_still_resolves() {
        // The same shape, small enough that every path fits: four directory
        // levels of eight-byte names expand into 30 directories and 32 files.
        let sets = Par3Set::from_packets(wide_dag(4, 5)).expect("builds");
        assert_eq!(sets[0].directories().len(), 30);
        assert_eq!(sets[0].files().len(), 32);
    }

    #[test]
    fn asking_for_an_absent_set_is_an_error() {
        let packets = vec![packet(PacketBody::Start(start_packet()))];
        assert!(matches!(
            Par3Set::from_packets_for(packets, InputSetId([9; 8])),
            Err(Par3Error::UnknownInputSet { .. })
        ));
    }

    #[test]
    fn packets_from_two_sets_become_two_sets() {
        let other = InputSetId([9; 8]);
        let root = RootPacket {
            lowest_unused_block_index: 0,
            attributes: 0,
            option_hashes: Vec::new(),
            children: Vec::new(),
        };
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            packet(PacketBody::Root(root.clone())),
            Packet::new(other, PacketBody::Start(start_packet())),
            Packet::new(other, PacketBody::Root(root)),
        ];
        let sets = Par3Set::from_packets(packets).expect("builds");
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].input_set_id(), ID);
        assert_eq!(sets[1].input_set_id(), other);
    }

    // -----------------------------------------------------------------------
    // The recovery inventory. These build packets in memory rather than from
    // reference bytes, because the oracle archives carry no Recovery External
    // Data packets and no foreign Root packets to read.
    // -----------------------------------------------------------------------

    fn root_packet() -> Packet {
        packet(PacketBody::Root(RootPacket {
            lowest_unused_block_index: 2,
            attributes: 0,
            option_hashes: Vec::new(),
            children: Vec::new(),
        }))
    }

    fn matrix_packet() -> Packet {
        packet(PacketBody::CauchyMatrix(
            CauchyMatrixPacket::parse(&[0u8; 24]).expect("parses"),
        ))
    }

    /// A second matrix for the same set, of the kind the reference writes
    /// alongside a Cauchy matrix.
    fn fft_matrix_packet() -> Packet {
        packet(PacketBody::FftMatrix(FftMatrixPacket {
            range: BlockRange { first: 0, end: 2 },
            max_recovery_blocks_log2: 3,
            interleave: 0,
            interleave_len: 0,
        }))
    }

    fn recovery_packet(
        root_hash: Fingerprint,
        matrix_hash: Fingerprint,
        index: u64,
        data: &[u8],
    ) -> Packet {
        packet(PacketBody::RecoveryData(RecoveryDataPacket {
            root_hash,
            matrix_hash,
            recovery_block_index: index,
            data: data.to_vec(),
        }))
    }

    #[test]
    fn recovery_packets_become_an_inventory_sorted_by_index() {
        let root = root_packet();
        let matrix = matrix_packet();
        let (root_hash, matrix_hash) = (root.hash(), matrix.hash());
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            matrix,
            recovery_packet(root_hash, matrix_hash, 1, &[0xbb; 2000]),
            recovery_packet(root_hash, matrix_hash, 0, &[0xaa; 2000]),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");

        let indices: Vec<u64> = set
            .recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect();
        assert_eq!(indices, [0, 1]);
        assert_eq!(set.recovery_blocks()[0].data(), [0xaa; 2000]);
        assert_eq!(set.recovery_blocks()[0].data_len(), 2000);
        assert_eq!(set.recovery_blocks()[0].matrix_hash(), matrix_hash);
        assert!(
            set.recovery_blocks()
                .iter()
                .all(RecoveryBlock::matrix_present)
        );
        assert!(set.foreign_recovery_packets().is_empty());
        assert_eq!(set.conflicting_recovery_packet_count(), 0);
    }

    #[test]
    fn two_matrices_may_each_have_a_recovery_block_zero() {
        let root = root_packet();
        let cauchy = matrix_packet();
        let fft = fft_matrix_packet();
        let (root_hash, cauchy_hash, fft_hash) = (root.hash(), cauchy.hash(), fft.hash());
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            cauchy,
            fft,
            recovery_packet(root_hash, fft_hash, 0, &[0xbb; 64]),
            recovery_packet(root_hash, cauchy_hash, 0, &[0xaa; 64]),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");

        // Index 0 of the Cauchy matrix and index 0 of the FFT matrix are
        // different rows of different matrices, not a contradiction.
        assert_eq!(set.conflicting_recovery_packet_count(), 0);
        let listed: Vec<(u64, Fingerprint)> = set
            .recovery_blocks()
            .iter()
            .map(|block| (block.index(), block.matrix_hash()))
            .collect();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&(0, cauchy_hash)));
        assert!(listed.contains(&(0, fft_hash)));
        assert!(
            set.recovery_blocks()
                .iter()
                .all(RecoveryBlock::matrix_present)
        );
    }

    #[test]
    fn a_recovery_block_whose_matrix_packet_is_absent_says_so() {
        let root = root_packet();
        let root_hash = root.hash();
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            recovery_packet(root_hash, [0x5a; 16], 0, &[0u8; 16]),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.recovery_blocks().len(), 1);
        assert!(!set.recovery_blocks()[0].matrix_present());
    }

    #[test]
    fn a_recovery_packet_for_another_root_is_counted_not_inventoried() {
        let root = root_packet();
        let matrix = matrix_packet();
        let (root_hash, matrix_hash) = (root.hash(), matrix.hash());
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            matrix,
            recovery_packet(root_hash, matrix_hash, 0, &[0xaa; 64]),
            // The same index, but written against some other set's Root packet:
            // it covers different input blocks, so it is not this set's.
            recovery_packet([0x77; 16], matrix_hash, 0, &[0xcc; 64]),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.recovery_blocks().len(), 1);
        assert_eq!(set.recovery_blocks()[0].data(), [0xaa; 64]);
        assert_eq!(set.foreign_recovery_packets().len(), 1);
        // Kept, just not as this set's recovery data.
        assert_eq!(set.foreign_recovery_packets()[0].data, [0xcc; 64]);
    }

    #[test]
    fn recovery_packets_that_contradict_one_index_are_all_excluded() {
        let root = root_packet();
        let matrix = matrix_packet();
        let (root_hash, matrix_hash) = (root.hash(), matrix.hash());
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            matrix,
            recovery_packet(root_hash, matrix_hash, 3, &[0xaa; 64]),
            recovery_packet(root_hash, matrix_hash, 3, &[0xab; 64]),
            recovery_packet(root_hash, matrix_hash, 4, &[0xac; 64]),
        ];
        // The set still builds: contradicting recovery data costs the caller
        // that recovery block, not the file listing.
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(
            set.recovery_blocks()
                .iter()
                .map(RecoveryBlock::index)
                .collect::<Vec<_>>(),
            [4]
        );
        // Both packets are gone, not one of them picked as the winner.
        assert_eq!(set.conflicting_recovery_packet_count(), 2);
    }

    #[test]
    fn identical_recovery_packets_collapse_into_one_block() {
        let root = root_packet();
        let matrix = matrix_packet();
        let (root_hash, matrix_hash) = (root.hash(), matrix.hash());
        let block = recovery_packet(root_hash, matrix_hash, 0, &[0xaa; 64]);
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            matrix,
            block.clone(),
            block,
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.recovery_blocks().len(), 1);
        assert_eq!(set.duplicate_packet_count(), 1);
    }

    #[test]
    fn recovery_external_data_maps_checksums_for_this_root_only() {
        let root = root_packet();
        let matrix = matrix_packet();
        let (root_hash, matrix_hash) = (root.hash(), matrix.hash());
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            matrix,
            packet(PacketBody::RecoveryExternalData(
                RecoveryExternalDataPacket {
                    root_hash,
                    matrix_hash,
                    first_recovery_block_index: 4,
                    checksums: vec![
                        BlockChecksum {
                            rolling_hash: 40,
                            fingerprint: [4u8; 16],
                        },
                        BlockChecksum {
                            rolling_hash: 50,
                            fingerprint: [5u8; 16],
                        },
                    ],
                },
            )),
            packet(PacketBody::RecoveryExternalData(
                RecoveryExternalDataPacket {
                    root_hash: [0x77; 16],
                    matrix_hash,
                    first_recovery_block_index: 9,
                    checksums: vec![BlockChecksum {
                        rolling_hash: 90,
                        fingerprint: [9u8; 16],
                    }],
                },
            )),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert_eq!(set.recovery_block_checksums().len(), 2);
        assert_eq!(
            set.recovery_block_checksum(matrix_hash, 4)
                .expect("present")
                .rolling_hash,
            40
        );
        assert_eq!(
            set.recovery_block_checksum(matrix_hash, 5)
                .expect("present")
                .rolling_hash,
            50
        );
        // The index alone is not the key: the same index under another matrix is
        // another row.
        assert!(set.recovery_block_checksum([0x5a; 16], 4).is_none());
        // The foreign packet's checksums are not this set's.
        assert!(set.recovery_block_checksum(matrix_hash, 9).is_none());
        assert_eq!(set.recovery_external_data().len(), 2);
    }

    #[test]
    fn a_recovery_block_is_checked_against_its_checksum_zero_padded() {
        let root = root_packet();
        let root_hash = root.hash();
        // A short block, as a writer that trimmed trailing zeros would store it.
        let stored = [0x11u8; 30];
        let mut padded = stored.to_vec();
        padded.resize(64, 0);
        let checksum = BlockChecksum {
            rolling_hash: rolling_hash(&padded),
            fingerprint: fingerprint(&padded),
        };
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            recovery_packet(root_hash, [0x5a; 16], 0, &stored),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        let block = &set.recovery_blocks()[0];
        assert!(block.matches_checksum(&checksum, 64));
        // A different block size hashes different bytes, and a block longer than
        // the block size cannot be the block the checksum describes.
        assert!(!block.matches_checksum(&checksum, 65));
        assert!(!block.matches_checksum(&checksum, 20));
    }

    #[test]
    fn an_implausible_block_size_is_refused_rather_than_hashed() {
        let root = root_packet();
        let root_hash = root.hash();
        let packets = vec![
            packet(PacketBody::Start(start_packet())),
            root,
            recovery_packet(root_hash, [0x5a; 16], 0, &[0x11; 30]),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        let block = &set.recovery_blocks()[0];
        let checksum = BlockChecksum {
            rolling_hash: 0,
            fingerprint: [0; 16],
        };
        // A block size out of a damaged or hostile Start packet must not send
        // the hashers off to count to u64::MAX. This returns at once.
        assert!(!block.matches_checksum(&checksum, u64::MAX));
        assert!(!block.matches_checksum(&checksum, ScanLimits::DEFAULT_MAX_PACKET_LEN + 1));
    }
}
