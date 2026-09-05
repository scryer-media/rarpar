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

    /// Reading a `.par3` file or an input file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for results carrying a [`Par3Error`].
pub type Result<T> = std::result::Result<T, Par3Error>;
