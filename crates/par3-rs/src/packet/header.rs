//! The 48-byte packet header shared by every PAR3 packet.

use std::fmt;

use crate::error::{Par3Error, Result};
use crate::hash::{Fingerprint, fingerprint};

/// The 8-byte magic sequence that begins every PAR3 packet.
pub const MAGIC: &[u8; 8] = b"PAR3\x00PKT";

/// Size of the packet header in bytes, and so the smallest legal packet.
pub const HEADER_SIZE: usize = 48;

/// Offset within the header at which the header hash starts covering bytes.
///
/// The hash covers `[HASHED_FROM, length)`: the length, the InputSetID, the
/// packet type and the whole body. It deliberately excludes the magic sequence
/// and the hash field itself.
pub const HASHED_FROM: usize = 24;

/// Identifies the set of input files and directories a packet belongs to.
///
/// The reference implementation derives it from a random number that is not
/// stored anywhere, so it cannot be recomputed or validated from a Start
/// packet's body. Treat it purely as an opaque grouping key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputSetId(pub [u8; 8]);

impl InputSetId {
    /// The all-zero identifier, which Start packets use to mean "no parent".
    pub const ZERO: Self = Self([0u8; 8]);

    /// The raw eight bytes, in the order they appear in the packet header.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Whether this is the all-zero identifier.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 8]
    }
}

impl From<[u8; 8]> for InputSetId {
    fn from(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for InputSetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for InputSetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputSetId({self})")
    }
}

/// Packet type signature for the Creator packet.
pub const TYPE_CREATOR: &[u8; 8] = b"PAR CRE\x00";
/// Packet type signature for the Comment packet.
pub const TYPE_COMMENT: &[u8; 8] = b"PAR COM\x00";
/// Packet type signature for the Start packet.
pub const TYPE_START: &[u8; 8] = b"PAR STA\x00";
/// Packet type signature for the Data packet.
pub const TYPE_DATA: &[u8; 8] = b"PAR DAT\x00";
/// Packet type signature for the External Data packet.
pub const TYPE_EXTERNAL_DATA: &[u8; 8] = b"PAR EXT\x00";
/// Packet type signature for the Cauchy Matrix packet.
pub const TYPE_CAUCHY_MATRIX: &[u8; 8] = b"PAR CAU\x00";
/// Packet type signature for the Sparse Random Matrix packet.
pub const TYPE_SPARSE_RANDOM_MATRIX: &[u8; 8] = b"PAR SPA\x00";
/// Packet type signature for the Explicit Matrix packet.
pub const TYPE_EXPLICIT_MATRIX: &[u8; 8] = b"PAR EXP\x00";
/// Packet type signature for the FFT Matrix packet, which the reference
/// implementation writes but no published specification defines.
pub const TYPE_FFT_MATRIX: &[u8; 8] = b"PAR FFT\x00";
/// Packet type signature for the Recovery Data packet.
pub const TYPE_RECOVERY_DATA: &[u8; 8] = b"PAR REC\x00";
/// Packet type signature for the Recovery External Data packet.
pub const TYPE_RECOVERY_EXTERNAL_DATA: &[u8; 8] = b"PAR ERD\x00";
/// Packet type signature for the File packet.
pub const TYPE_FILE: &[u8; 8] = b"PAR FIL\x00";
/// Packet type signature for the Directory packet.
pub const TYPE_DIRECTORY: &[u8; 8] = b"PAR DIR\x00";
/// Packet type signature for the Root packet.
pub const TYPE_ROOT: &[u8; 8] = b"PAR ROO\x00";
/// Packet type signature for the Link packet, retained opaquely.
pub const TYPE_LINK: &[u8; 8] = b"PAR LNK\x00";
/// Packet type signature for the UNIX Permissions packet, retained opaquely.
pub const TYPE_UNIX_PERMISSIONS: &[u8; 8] = b"PAR UNX\x00";
/// Packet type signature for the FAT Permissions packet, retained opaquely.
pub const TYPE_FAT_PERMISSIONS: &[u8; 8] = b"PAR FAT\x00";

/// The type of a PAR3 packet, from the 8-byte signature in its header.
///
/// Every signature beginning `"PAR "` is reserved by the specification.
/// Unrecognised signatures are kept rather than rejected, because an unknown
/// packet type must never fail a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PacketType {
    /// `PAR CRE\0`, the required client-identification text.
    Creator,
    /// `PAR COM\0`, a user comment.
    Comment,
    /// `PAR STA\0`, block size and Galois field parameters.
    Start,
    /// `PAR DAT\0`, one input block's data.
    Data,
    /// `PAR EXT\0`, checksums for input blocks stored outside the set.
    ExternalData,
    /// `PAR CAU\0`, a Cauchy code matrix.
    CauchyMatrix,
    /// `PAR SPA\0`, a sparse random code matrix.
    SparseRandomMatrix,
    /// `PAR EXP\0`, one explicitly listed code-matrix row.
    ExplicitMatrix,
    /// `PAR FFT\0`, the reference implementation's FFT code matrix.
    FftMatrix,
    /// `PAR REC\0`, one recovery block's data.
    RecoveryData,
    /// `PAR ERD\0`, checksums for recovery blocks stored outside the set.
    RecoveryExternalData,
    /// `PAR FIL\0`, one input file.
    File,
    /// `PAR DIR\0`, one input sub-directory.
    Directory,
    /// `PAR ROO\0`, the top of the input set's directory tree.
    Root,
    /// `PAR LNK\0`, a hard or symbolic link. Retained opaquely.
    Link,
    /// `PAR UNX\0`, UNIX permissions. Retained opaquely.
    UnixPermissions,
    /// `PAR FAT\0`, FAT permissions. Retained opaquely.
    FatPermissions,
    /// Any other signature, retained verbatim.
    Unknown([u8; 8]),
}

impl PacketType {
    /// Classify an 8-byte type signature.
    #[must_use]
    pub fn from_signature(signature: &[u8; 8]) -> Self {
        match signature {
            s if s == TYPE_CREATOR => Self::Creator,
            s if s == TYPE_COMMENT => Self::Comment,
            s if s == TYPE_START => Self::Start,
            s if s == TYPE_DATA => Self::Data,
            s if s == TYPE_EXTERNAL_DATA => Self::ExternalData,
            s if s == TYPE_CAUCHY_MATRIX => Self::CauchyMatrix,
            s if s == TYPE_SPARSE_RANDOM_MATRIX => Self::SparseRandomMatrix,
            s if s == TYPE_EXPLICIT_MATRIX => Self::ExplicitMatrix,
            s if s == TYPE_FFT_MATRIX => Self::FftMatrix,
            s if s == TYPE_RECOVERY_DATA => Self::RecoveryData,
            s if s == TYPE_RECOVERY_EXTERNAL_DATA => Self::RecoveryExternalData,
            s if s == TYPE_FILE => Self::File,
            s if s == TYPE_DIRECTORY => Self::Directory,
            s if s == TYPE_ROOT => Self::Root,
            s if s == TYPE_LINK => Self::Link,
            s if s == TYPE_UNIX_PERMISSIONS => Self::UnixPermissions,
            s if s == TYPE_FAT_PERMISSIONS => Self::FatPermissions,
            other => Self::Unknown(*other),
        }
    }

    /// The 8-byte signature this type is written as.
    #[must_use]
    pub fn signature(&self) -> [u8; 8] {
        match self {
            Self::Creator => *TYPE_CREATOR,
            Self::Comment => *TYPE_COMMENT,
            Self::Start => *TYPE_START,
            Self::Data => *TYPE_DATA,
            Self::ExternalData => *TYPE_EXTERNAL_DATA,
            Self::CauchyMatrix => *TYPE_CAUCHY_MATRIX,
            Self::SparseRandomMatrix => *TYPE_SPARSE_RANDOM_MATRIX,
            Self::ExplicitMatrix => *TYPE_EXPLICIT_MATRIX,
            Self::FftMatrix => *TYPE_FFT_MATRIX,
            Self::RecoveryData => *TYPE_RECOVERY_DATA,
            Self::RecoveryExternalData => *TYPE_RECOVERY_EXTERNAL_DATA,
            Self::File => *TYPE_FILE,
            Self::Directory => *TYPE_DIRECTORY,
            Self::Root => *TYPE_ROOT,
            Self::Link => *TYPE_LINK,
            Self::UnixPermissions => *TYPE_UNIX_PERMISSIONS,
            Self::FatPermissions => *TYPE_FAT_PERMISSIONS,
            Self::Unknown(signature) => *signature,
        }
    }

    /// Whether the signature is in the `"PAR "` namespace the specification
    /// reserves for itself.
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        self.signature().starts_with(b"PAR ")
    }
}

/// A parsed 48-byte packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// First 16 bytes of the BLAKE3 hash over `[24, length)` of the packet.
    pub hash: Fingerprint,
    /// Total packet length in bytes, including this header. Never below 48, and
    /// not required to be aligned in any way.
    pub length: u64,
    /// The input set this packet belongs to.
    pub input_set_id: InputSetId,
    /// The packet's type.
    pub packet_type: PacketType,
}

impl PacketHeader {
    /// Parse a header from the start of `data`.
    ///
    /// `offset` only feeds error reporting. This checks the magic and that the
    /// claimed length is at least [`HEADER_SIZE`]; it does not look at the body
    /// and does not validate the hash — use [`PacketHeader::validate_hash`] once
    /// the whole packet is available.
    pub fn parse(data: &[u8], offset: u64) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Par3Error::PacketTooShort {
                offset,
                expected: HEADER_SIZE as u64,
                actual: data.len() as u64,
            });
        }
        if &data[0..8] != MAGIC {
            return Err(Par3Error::InvalidMagic { offset });
        }

        let mut hash = [0u8; 16];
        hash.copy_from_slice(&data[8..24]);
        let length = u64::from_le_bytes(data[24..32].try_into().expect("8 bytes"));
        if length < HEADER_SIZE as u64 {
            return Err(Par3Error::PacketTooShort {
                offset,
                expected: HEADER_SIZE as u64,
                actual: length,
            });
        }
        let input_set_id = InputSetId(data[32..40].try_into().expect("8 bytes"));
        let signature: [u8; 8] = data[40..48].try_into().expect("8 bytes");

        Ok(Self {
            hash,
            length,
            input_set_id,
            packet_type: PacketType::from_signature(&signature),
        })
    }

    /// Append this header's 48 bytes to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(self.input_set_id.as_bytes());
        out.extend_from_slice(&self.packet_type.signature());
    }

    /// Check the header hash against the complete packet bytes.
    ///
    /// `packet` must be exactly the packet: `self.length` bytes starting at the
    /// magic sequence.
    pub fn validate_hash(&self, packet: &[u8], offset: u64) -> Result<()> {
        if packet.len() as u64 != self.length {
            return Err(Par3Error::PacketTooShort {
                offset,
                expected: self.length,
                actual: packet.len() as u64,
            });
        }
        if fingerprint(&packet[HASHED_FROM..]) == self.hash {
            Ok(())
        } else {
            Err(Par3Error::PacketHashMismatch { offset })
        }
    }
}

/// The hash a packet with this body and identity would carry.
pub(crate) fn compute_packet_hash(
    length: u64,
    input_set_id: InputSetId,
    packet_type: PacketType,
    body: &[u8],
) -> Fingerprint {
    let mut hasher = crate::hash::FingerprintHasher::new();
    hasher.update(&length.to_le_bytes());
    hasher.update(input_set_id.as_bytes());
    hasher.update(&packet_type.signature());
    hasher.update(body);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(body: &[u8]) -> Vec<u8> {
        let length = (HEADER_SIZE + body.len()) as u64;
        let id = InputSetId([1, 2, 3, 4, 5, 6, 7, 8]);
        let header = PacketHeader {
            hash: compute_packet_hash(length, id, PacketType::Comment, body),
            length,
            input_set_id: id,
            packet_type: PacketType::Comment,
        };
        let mut out = Vec::new();
        header.write(&mut out);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn header_round_trips() {
        let packet = sample_packet(b"hello");
        let header = PacketHeader::parse(&packet, 0).expect("parses");
        assert_eq!(header.length, 53);
        assert_eq!(header.packet_type, PacketType::Comment);
        assert_eq!(header.input_set_id, InputSetId([1, 2, 3, 4, 5, 6, 7, 8]));
        header.validate_hash(&packet, 0).expect("hash is valid");

        let mut written = Vec::new();
        header.write(&mut written);
        assert_eq!(written, packet[..HEADER_SIZE]);
    }

    #[test]
    fn a_flipped_body_byte_fails_the_hash() {
        let mut packet = sample_packet(b"hello");
        let header = PacketHeader::parse(&packet, 0).expect("parses");
        packet[HEADER_SIZE] ^= 0x01;
        assert!(matches!(
            header.validate_hash(&packet, 0),
            Err(Par3Error::PacketHashMismatch { offset: 0 })
        ));
    }

    #[test]
    fn the_length_field_is_covered_by_the_hash() {
        // Shorten the declared length and hand over exactly that many bytes, so
        // the length check passes and only the hash can catch the change.
        let mut packet = sample_packet(b"hello");
        let shortened = HEADER_SIZE as u64;
        packet[24..32].copy_from_slice(&shortened.to_le_bytes());
        let header = PacketHeader::parse(&packet, 0).expect("parses");
        assert_eq!(header.length, shortened);
        assert!(matches!(
            header.validate_hash(&packet[..HEADER_SIZE], 0),
            Err(Par3Error::PacketHashMismatch { offset: 0 })
        ));
    }

    #[test]
    fn short_input_is_rejected_without_panic() {
        let packet = sample_packet(b"hello");
        for len in 0..HEADER_SIZE {
            assert!(matches!(
                PacketHeader::parse(&packet[..len], 7),
                Err(Par3Error::PacketTooShort { offset: 7, .. })
            ));
        }
    }

    #[test]
    fn a_length_below_the_header_is_rejected() {
        let mut packet = sample_packet(b"hello");
        packet[24..32].copy_from_slice(&47u64.to_le_bytes());
        assert!(matches!(
            PacketHeader::parse(&packet, 0),
            Err(Par3Error::PacketTooShort { actual: 47, .. })
        ));
    }

    #[test]
    fn a_wrong_magic_is_rejected() {
        let mut packet = sample_packet(b"hello");
        packet[3] = b'2';
        assert!(matches!(
            PacketHeader::parse(&packet, 9),
            Err(Par3Error::InvalidMagic { offset: 9 })
        ));
    }

    #[test]
    fn unknown_types_survive_a_round_trip() {
        let signature = *b"XYZ\0abcd";
        let packet_type = PacketType::from_signature(&signature);
        assert_eq!(packet_type, PacketType::Unknown(signature));
        assert_eq!(packet_type.signature(), signature);
        assert!(!packet_type.is_reserved());
        assert!(PacketType::Root.is_reserved());
    }

    #[test]
    fn input_set_id_formats_as_hex() {
        let id = InputSetId([0x24, 0xa1, 0xad, 0x60, 0x1a, 0xe5, 0xbc, 0x72]);
        assert_eq!(id.to_string(), "24a1ad601ae5bc72");
        assert!(InputSetId::ZERO.is_zero());
        assert!(!id.is_zero());
    }
}
