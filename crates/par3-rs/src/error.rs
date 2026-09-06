//! Error type for PAR3 parsing, set construction and verification.

use thiserror::Error;

use crate::packet::InputSetId;

/// Everything that can go wrong while reading or verifying a PAR3 set.
///
/// Damaged bytes inside a `.par3` file are deliberately *not* modelled here:
/// the scanner skips a packet whose header hash does not match and resynchronises
/// on the next magic sequence, because a partially damaged recovery set is still
/// useful. These variants describe inputs that cannot be interpreted at all, or
/// sets whose packets contradict each other.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Par3Error {
    /// The bytes at this offset do not begin with the PAR3 packet magic.
    #[error("no PAR3 packet magic at offset {offset}")]
    InvalidMagic {
        /// Byte offset the header parse was attempted at.
        offset: u64,
    },

    /// A packet header claims a length below the 48-byte header, or the input
    /// ends before the claimed length.
    #[error("packet at offset {offset} needs {expected} bytes, {actual} available")]
    PacketTooShort {
        /// Byte offset of the packet.
        offset: u64,
        /// Bytes the packet claims to need.
        expected: u64,
        /// Bytes actually available.
        actual: u64,
    },

    /// The header's 16-byte BLAKE3 fingerprint does not cover the packet bytes.
    #[error("packet hash mismatch at offset {offset}")]
    PacketHashMismatch {
        /// Byte offset of the packet.
        offset: u64,
    },

    /// A typed packet body did not match its documented layout.
    #[error("malformed {packet} packet: {reason}")]
    MalformedPacket {
        /// Human-readable packet kind, for example `Start` or `File`.
        packet: &'static str,
        /// What was wrong.
        reason: String,
    },

    /// A scan exceeded one of the [`ScanLimits`](crate::scan::ScanLimits).
    #[error("PAR3 scan limit exceeded: {reason}")]
    ScanLimitExceeded {
        /// Which budget ran out.
        reason: String,
    },

    /// No Start packet was found for an input set.
    #[error("input set {input_set_id} has no Start packet")]
    MissingStartPacket {
        /// The set that is missing its Start packet.
        input_set_id: InputSetId,
    },

    /// No Root packet was found for an input set.
    #[error("input set {input_set_id} has no Root packet")]
    MissingRootPacket {
        /// The set that is missing its Root packet.
        input_set_id: InputSetId,
    },

    /// Two Start packets with different contents claim the same input set.
    ///
    /// They would disagree about the block size or the Galois field, which
    /// decides how every File packet in the set is read, so there is no safe way
    /// to pick one.
    #[error("input set {input_set_id} has multiple distinct Start packets")]
    ConflictingStartPackets {
        /// The ambiguous set.
        input_set_id: InputSetId,
    },

    /// Two Root packets with different contents claim the same input set.
    ///
    /// The format allows any number of *identical* copies of the Root packet but
    /// exactly one distinct Root per InputSetID, so this is unrecoverable
    /// ambiguity rather than damage.
    #[error("input set {input_set_id} has multiple distinct Root packets")]
    ConflictingRootPackets {
        /// The ambiguous set.
        input_set_id: InputSetId,
    },

    /// A Root or Directory packet references a child packet that is not present.
    #[error("input set {input_set_id} references missing child packet {child}")]
    MissingChildPacket {
        /// The set whose tree could not be resolved.
        input_set_id: InputSetId,
        /// Hex of the 16-byte child packet fingerprint that was not found.
        child: String,
    },

    /// A File or Directory packet carries a name that cannot be used as a path
    /// component.
    #[error("unsafe PAR3 name {name:?}: {reason}")]
    UnsafeName {
        /// The offending name, as stored in the packet.
        name: String,
        /// Why it was refused.
        reason: &'static str,
    },

    /// Two entries in the same directory carry the same name.
    #[error("duplicate name {name:?} in directory {directory:?}")]
    DuplicateName {
        /// The repeated name.
        name: String,
        /// Path of the containing directory, empty for the root.
        directory: String,
    },

    /// A chunk description points at an input block index the Root packet does
    /// not cover.
    #[error("block index {index} is beyond the set's block count {block_count}")]
    BlockIndexOutOfRange {
        /// The offending index.
        index: u64,
        /// The set's lowest unused input block index.
        block_count: u64,
    },

    /// The directory tree revisits a packet that is already an ancestor.
    #[error("input set {input_set_id} has a cyclic directory tree")]
    CyclicDirectoryTree {
        /// The set whose tree could not be resolved.
        input_set_id: InputSetId,
    },

    /// The requested input set is not present in the supplied packets.
    #[error("no packets for input set {input_set_id}")]
    UnknownInputSet {
        /// The set that was asked for.
        input_set_id: InputSetId,
    },

    /// A Galois field this crate cannot compute in.
    ///
    /// Either the set declares a field size no codec here implements, or its
    /// generator polynomial is not one the field can be built from.
    #[error("unsupported Galois field: {reason}")]
    UnsupportedField {
        /// What was wrong with the field.
        reason: String,
    },

    /// A codec geometry that has no valid Cauchy matrix, or none this crate can
    /// work with.
    #[error("unusable PAR3 codec geometry: {reason}")]
    CodecGeometry {
        /// Why the block counts, block size or field do not fit together.
        reason: String,
    },

    /// A block a codec was handed does not belong where the caller put it.
    #[error("PAR3 codec block {index}: {reason}")]
    CodecBlock {
        /// The block index the caller named.
        index: u64,
        /// What was wrong with it.
        reason: String,
    },

    /// Fewer recovery blocks are available than there are input blocks to
    /// rebuild, so the system is underdetermined.
    #[error("cannot rebuild {lost} lost input blocks from {available} recovery blocks")]
    InsufficientRecovery {
        /// Input blocks that must be rebuilt.
        lost: u64,
        /// Recovery blocks on hand.
        available: u64,
    },

    /// The chosen recovery rows do not form an invertible system.
    ///
    /// A Cauchy matrix built over distinct, disjoint row and column values is
    /// always invertible, so this means the geometry or the chosen rows were
    /// not what they were taken to be, rather than that the data is damaged.
    #[error("the chosen recovery blocks do not form an invertible system")]
    SingularSystem,

    /// A codec asked for more memory than its [`CodecLimits`] allow.
    ///
    /// [`CodecLimits`]: crate::cauchy::CodecLimits
    #[error("PAR3 codec limit exceeded: {reason}")]
    CodecLimitExceeded {
        /// Which budget ran out.
        reason: String,
    },

    /// The set's own packets do not describe a layout a repair can work from.
    ///
    /// Two chunks claiming the same bytes of one input block, a block no file
    /// writes, a file the set cannot check at all, or recovery data computed
    /// with a matrix this crate does not implement: none of these is damage to
    /// the protected files, so none of them is reported as such.
    #[error("this PAR3 set cannot be repaired: {reason}")]
    UnrepairableSet {
        /// What about the set stands in the way.
        reason: String,
    },

    /// A repair exceeded one of the [`RepairLimits`](crate::repair::RepairLimits).
    #[error("PAR3 repair limit exceeded: {reason}")]
    RepairLimitExceeded {
        /// Which budget ran out.
        reason: String,
    },

    /// An input handed to [`create`](crate::create::create) cannot be used.
    ///
    /// The path is reported exactly as the caller named it, so a refusal points
    /// back at the argument that caused it rather than at a rewritten form.
    #[error("cannot protect {path:?}: {reason}")]
    CreateInput {
        /// The offending path or output name.
        path: String,
        /// Why it was refused.
        reason: String,
    },

    /// A create exceeded one of the [`CreateLimits`](crate::create::CreateLimits).
    #[error("PAR3 create limit exceeded: {reason}")]
    CreateLimitExceeded {
        /// Which budget ran out.
        reason: String,
    },

    /// An I/O operation on a named file failed.
    ///
    /// [`Io`](Par3Error::Io) carries what the standard library reported and
    /// nothing else; this variant names the file it happened on, which is what
    /// a create needs to say when one input among many cannot be read.
    #[error("I/O error on {path:?}: {source}")]
    FileIo {
        /// The file the operation was on.
        path: String,
        /// What the operating system reported.
        #[source]
        source: std::io::Error,
    },

    /// Reading a `.par3` file or an input file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for results carrying a [`Par3Error`].
pub type Result<T> = std::result::Result<T, Par3Error>;
