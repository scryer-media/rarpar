//! PAR3 packets: the 48-byte header, the typed bodies, and the framing that
//! joins them.
//!
//! A PAR3 file is a sequence of self-contained packets. Each carries its own
//! checksum, so damage to one packet does not spoil the rest of the file, and
//! packets belonging to one input set may be spread over any number of files.
//!
//! # Parsing needs a little context
//!
//! Two packet bodies cannot be read on their own. A File packet's chunk
//! descriptions depend on the set's block size, and an Explicit Matrix packet's
//! factors depend on the Galois field size — both of which live in the Start
//! packet. Supply what is known through [`ParseContext`]; a packet that needs
//! more than the context offers is retained as [`PacketBody::Opaque`], which
//! round-trips byte for byte, and [`Par3Set`](crate::set::Par3Set) parses it once
//! the Start packet has been found.

pub mod comment;
pub mod creator;
pub mod data;
pub mod directory;
pub mod external_data;
pub mod file;
pub mod header;
pub mod matrix;
mod reader;
pub mod recovery;
pub mod root;
pub mod start;

pub use comment::CommentPacket;
pub use creator::CreatorPacket;
pub use data::DataPacket;
pub use directory::DirectoryPacket;
pub use external_data::{BlockChecksum, CHECKSUM_PAIR_LEN, ExternalDataPacket};
pub use file::{ChunkDescription, ChunkTail, FilePacket};
pub use header::{HASHED_FROM, HEADER_SIZE, InputSetId, MAGIC, PacketHeader, PacketType};
pub use matrix::{
    BlockRange, CauchyMatrixPacket, ExplicitMatrixEntry, ExplicitMatrixPacket, FftMatrixPacket,
    SparseRandomMatrixPacket,
};
pub use recovery::{RecoveryDataPacket, RecoveryExternalDataPacket};
pub use root::{ATTRIBUTE_ABSOLUTE_PATH, RootPacket};
pub use start::{GaloisField, StartPacket};

use crate::error::{Par3Error, Result};
use crate::hash::Fingerprint;

/// What a body parse knows about the input set it belongs to.
///
/// Empty by default, which is correct for a first pass over bytes whose Start
/// packet has not been seen yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseContext {
    /// The set's input block size, from its Start packet.
    pub block_size: Option<u64>,
    /// The set's Galois field element size in bytes, from its Start packet.
    pub galois_field_size: Option<u8>,
}

impl ParseContext {
    /// A context that knows nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything a Start packet contributes.
    #[must_use]
    pub fn from_start(start: &StartPacket) -> Self {
        Self {
            block_size: Some(start.block_size),
            galois_field_size: Some(start.galois_field.size),
        }
    }

    /// Set the block size.
    #[must_use]
    pub fn with_block_size(mut self, block_size: u64) -> Self {
        self.block_size = Some(block_size);
        self
    }

    /// Set the Galois field element size.
    #[must_use]
    pub fn with_galois_field_size(mut self, size: u8) -> Self {
        self.galois_field_size = Some(size);
        self
    }
}

/// A parsed packet body.
///
/// `Opaque` covers three cases, all of which write back byte for byte: a packet
/// type this crate does not interpret ([`PacketType::Link`] and the permission
/// packets), a type it does not recognise at all, and a recognised type whose
/// body could not be parsed with the context available.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketBody {
    /// `PAR CRE\0`.
    Creator(CreatorPacket),
    /// `PAR COM\0`.
    Comment(CommentPacket),
    /// `PAR STA\0`.
    Start(StartPacket),
    /// `PAR DAT\0`.
    Data(DataPacket),
    /// `PAR EXT\0`.
    ExternalData(ExternalDataPacket),
    /// `PAR CAU\0`.
    CauchyMatrix(CauchyMatrixPacket),
    /// `PAR SPA\0`.
    SparseRandomMatrix(SparseRandomMatrixPacket),
    /// `PAR EXP\0`.
    ExplicitMatrix(ExplicitMatrixPacket),
    /// `PAR FFT\0`.
    FftMatrix(FftMatrixPacket),
    /// `PAR REC\0`.
    RecoveryData(RecoveryDataPacket),
    /// `PAR ERD\0`.
    RecoveryExternalData(RecoveryExternalDataPacket),
    /// `PAR FIL\0`.
    File(FilePacket),
    /// `PAR DIR\0`.
    Directory(DirectoryPacket),
    /// `PAR ROO\0`.
    Root(RootPacket),
    /// A body kept verbatim.
    Opaque {
        /// The packet's declared type.
        packet_type: PacketType,
        /// The body bytes, exactly as read.
        body: Vec<u8>,
    },
}

impl PacketBody {
    /// Parse a body of the given type.
    ///
    /// Types this crate keeps opaque by design — links and permissions — and
    /// unrecognised types both yield [`PacketBody::Opaque`]. Types that cannot be
    /// parsed with the supplied context yield an error, so a caller can decide
    /// whether to retain them opaquely and retry later.
    pub fn parse(packet_type: PacketType, body: &[u8], context: &ParseContext) -> Result<Self> {
        let opaque = || Self::Opaque {
            packet_type,
            body: body.to_vec(),
        };
        Ok(match packet_type {
            PacketType::Creator => Self::Creator(CreatorPacket::parse(body)),
            PacketType::Comment => Self::Comment(CommentPacket::parse(body)),
            PacketType::Start => Self::Start(StartPacket::parse(body)?),
            PacketType::Data => Self::Data(DataPacket::parse(body)?),
            PacketType::ExternalData => Self::ExternalData(ExternalDataPacket::parse(body)?),
            PacketType::CauchyMatrix => Self::CauchyMatrix(CauchyMatrixPacket::parse(body)?),
            PacketType::SparseRandomMatrix => {
                Self::SparseRandomMatrix(SparseRandomMatrixPacket::parse(body)?)
            }
            PacketType::ExplicitMatrix => {
                let size = context
                    .galois_field_size
                    .ok_or(Par3Error::MalformedPacket {
                        packet: "Explicit Matrix",
                        reason: "needs the input set's Galois field size".to_owned(),
                    })?;
                Self::ExplicitMatrix(ExplicitMatrixPacket::parse(body, size)?)
            }
            PacketType::FftMatrix => Self::FftMatrix(FftMatrixPacket::parse(body)?),
            PacketType::RecoveryData => Self::RecoveryData(RecoveryDataPacket::parse(body)?),
            PacketType::RecoveryExternalData => {
                Self::RecoveryExternalData(RecoveryExternalDataPacket::parse(body)?)
            }
            PacketType::File => {
                let block_size = context.block_size.ok_or(Par3Error::MalformedPacket {
                    packet: "File",
                    reason: "needs the input set's block size".to_owned(),
                })?;
                Self::File(FilePacket::parse(body, block_size)?)
            }
            PacketType::Directory => Self::Directory(DirectoryPacket::parse(body)?),
            PacketType::Root => Self::Root(RootPacket::parse(body)?),
            PacketType::Link
            | PacketType::UnixPermissions
            | PacketType::FatPermissions
            | PacketType::Unknown(_) => opaque(),
        })
    }

    /// Whether parsing this type requires information from a Start packet.
    #[must_use]
    pub fn needs_context(packet_type: PacketType) -> bool {
        matches!(packet_type, PacketType::File | PacketType::ExplicitMatrix)
    }

    /// The type signature this body is written under.
    #[must_use]
    pub fn packet_type(&self) -> PacketType {
        match self {
            Self::Creator(_) => PacketType::Creator,
            Self::Comment(_) => PacketType::Comment,
            Self::Start(_) => PacketType::Start,
            Self::Data(_) => PacketType::Data,
            Self::ExternalData(_) => PacketType::ExternalData,
            Self::CauchyMatrix(_) => PacketType::CauchyMatrix,
            Self::SparseRandomMatrix(_) => PacketType::SparseRandomMatrix,
            Self::ExplicitMatrix(_) => PacketType::ExplicitMatrix,
            Self::FftMatrix(_) => PacketType::FftMatrix,
            Self::RecoveryData(_) => PacketType::RecoveryData,
            Self::RecoveryExternalData(_) => PacketType::RecoveryExternalData,
            Self::File(_) => PacketType::File,
            Self::Directory(_) => PacketType::Directory,
            Self::Root(_) => PacketType::Root,
            Self::Opaque { packet_type, .. } => *packet_type,
        }
    }

    /// Append this body's bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Creator(packet) => packet.write_body(out),
            Self::Comment(packet) => packet.write_body(out),
            Self::Start(packet) => packet.write_body(out),
            Self::Data(packet) => packet.write_body(out),
            Self::ExternalData(packet) => packet.write_body(out),
            Self::CauchyMatrix(packet) => packet.write_body(out),
            Self::SparseRandomMatrix(packet) => packet.write_body(out),
            Self::ExplicitMatrix(packet) => packet.write_body(out),
            Self::FftMatrix(packet) => packet.write_body(out),
            Self::RecoveryData(packet) => packet.write_body(out),
            Self::RecoveryExternalData(packet) => packet.write_body(out),
            Self::File(packet) => packet.write_body(out),
            Self::Directory(packet) => packet.write_body(out),
            Self::Root(packet) => packet.write_body(out),
            Self::Opaque { body, .. } => out.extend_from_slice(body),
        }
    }

    /// This body's bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

/// A complete PAR3 packet: an input set, a body, and the header hash that binds
/// them together.
///
/// The hash is not a public field. A packet read from bytes has had it checked,
/// and a packet built with [`Packet::new`] has had it computed, so
/// [`Packet::hash`] always describes the body actually held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    input_set_id: InputSetId,
    hash: Fingerprint,
    length: u64,
    body: PacketBody,
}

impl Packet {
    /// Build a packet, computing its header hash from the body.
    #[must_use]
    pub fn new(input_set_id: InputSetId, body: PacketBody) -> Self {
        let bytes = body.to_body_bytes();
        let length = HEADER_SIZE as u64 + bytes.len() as u64;
        let hash = header::compute_packet_hash(length, input_set_id, body.packet_type(), &bytes);
        Self {
            input_set_id,
            hash,
            length,
            body,
        }
    }

    /// Parse one complete packet from the start of `data`.
    ///
    /// `data` must begin at the magic sequence and hold at least the packet's
    /// declared length. The header hash is verified before the body is
    /// interpreted, so a packet that parses has already been checked end to end.
    /// `offset` only feeds error reporting.
    pub fn parse(data: &[u8], offset: u64, context: &ParseContext) -> Result<Self> {
        let header = PacketHeader::parse(data, offset)?;
        let length = usize::try_from(header.length).map_err(|_| Par3Error::PacketTooShort {
            offset,
            expected: header.length,
            actual: data.len() as u64,
        })?;
        if data.len() < length {
            return Err(Par3Error::PacketTooShort {
                offset,
                expected: header.length,
                actual: data.len() as u64,
            });
        }
        let packet = &data[..length];
        header.validate_hash(packet, offset)?;
        let body_bytes = &packet[HEADER_SIZE..];
        let body = match PacketBody::parse(header.packet_type, body_bytes, context) {
            Ok(body) => body,
            Err(error) => {
                tracing::debug!(
                    offset,
                    packet_type = ?header.packet_type,
                    %error,
                    "retaining PAR3 packet opaquely"
                );
                PacketBody::Opaque {
                    packet_type: header.packet_type,
                    body: body_bytes.to_vec(),
                }
            }
        };
        Ok(Self {
            input_set_id: header.input_set_id,
            hash: header.hash,
            length: header.length,
            body,
        })
    }

    /// The input set this packet belongs to.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        self.input_set_id
    }

    /// The packet's 16-byte header hash.
    ///
    /// Root and Directory packets name their children by this value.
    #[must_use]
    pub fn hash(&self) -> Fingerprint {
        self.hash
    }

    /// Total packet length in bytes, including the 48-byte header.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether the packet carries no body at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == HEADER_SIZE as u64
    }

    /// The packet's type.
    #[must_use]
    pub fn packet_type(&self) -> PacketType {
        self.body.packet_type()
    }

    /// The parsed body.
    #[must_use]
    pub fn body(&self) -> &PacketBody {
        &self.body
    }

    /// Take the parsed body.
    #[must_use]
    pub fn into_body(self) -> PacketBody {
        self.body
    }

    /// Serialise the complete packet, header included.
    ///
    /// A packet read from a file writes back byte for byte.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length as usize);
        PacketHeader {
            hash: self.hash,
            length: self.length,
            input_set_id: self.input_set_id,
            packet_type: self.packet_type(),
        }
        .write(&mut out);
        self.body.write_body(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_packet_carries_a_hash_its_own_bytes_validate() {
        let packet = Packet::new(
            InputSetId([1, 2, 3, 4, 5, 6, 7, 8]),
            PacketBody::Comment(CommentPacket::new("hello")),
        );
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len() as u64, packet.len());
        let header = PacketHeader::parse(&bytes, 0).expect("parses");
        header.validate_hash(&bytes, 0).expect("hash is valid");
        assert_eq!(header.hash, packet.hash());
    }

    #[test]
    fn parsing_rejects_a_flipped_body_byte() {
        let packet = Packet::new(
            InputSetId::ZERO,
            PacketBody::Comment(CommentPacket::new("hello")),
        );
        let mut bytes = packet.to_bytes();
        bytes[HEADER_SIZE] ^= 0x20;
        assert!(matches!(
            Packet::parse(&bytes, 0, &ParseContext::new()),
            Err(Par3Error::PacketHashMismatch { .. })
        ));
    }

    #[test]
    fn a_file_packet_stays_opaque_without_a_block_size() {
        let file = FilePacket {
            name: "a.bin".to_owned(),
            quick_rolling_hash: 1,
            fingerprint: [2u8; 16],
            option_hashes: Vec::new(),
            chunks: vec![ChunkDescription::Protected {
                // Two whole 2000-byte blocks and a 10-byte tail.
                length: 4010,
                first_block_index: Some(0),
                tail: ChunkTail::Inline(vec![9; 10]),
            }],
        };
        let packet = Packet::new(InputSetId::ZERO, PacketBody::File(file.clone()));
        let bytes = packet.to_bytes();

        let opaque = Packet::parse(&bytes, 0, &ParseContext::new()).expect("parses");
        assert!(matches!(
            opaque.body(),
            PacketBody::Opaque {
                packet_type: PacketType::File,
                ..
            }
        ));
        assert_eq!(opaque.to_bytes(), bytes);

        let context = ParseContext::new().with_block_size(2000);
        let typed = Packet::parse(&bytes, 0, &context).expect("parses");
        assert_eq!(typed.body(), &PacketBody::File(file));
        assert_eq!(typed.to_bytes(), bytes);
    }

    #[test]
    fn an_unknown_type_is_retained_and_written_back() {
        let body = PacketBody::Opaque {
            packet_type: PacketType::Unknown(*b"MINE\0abc"),
            body: b"anything".to_vec(),
        };
        let packet = Packet::new(InputSetId::ZERO, body.clone());
        let bytes = packet.to_bytes();
        let parsed = Packet::parse(&bytes, 0, &ParseContext::new()).expect("parses");
        assert_eq!(parsed.body(), &body);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn a_declared_length_beyond_the_input_is_refused() {
        let packet = Packet::new(
            InputSetId::ZERO,
            PacketBody::Comment(CommentPacket::new("hello")),
        );
        let mut bytes = packet.to_bytes();
        bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            Packet::parse(&bytes, 0, &ParseContext::new()),
            Err(Par3Error::PacketTooShort { .. })
        ));
    }

    #[test]
    fn needs_context_names_the_two_dependent_types() {
        assert!(PacketBody::needs_context(PacketType::File));
        assert!(PacketBody::needs_context(PacketType::ExplicitMatrix));
        assert!(!PacketBody::needs_context(PacketType::Root));
    }
}
