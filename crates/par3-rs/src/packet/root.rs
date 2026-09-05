//! `PAR ROO\0` — the top of an input set's directory tree.

use crate::error::Result;
use crate::hash::Fingerprint;
use crate::packet::reader::BodyReader;

const PACKET: &str = "Root";

/// Bit 0 of the Root packet's attribute byte: the tree describes an absolute
/// path rather than a relative one.
pub const ATTRIBUTE_ABSOLUTE_PATH: u8 = 1;

/// The Root packet: exactly one per input set.
///
/// Its own hash is a checksum for the whole input set, because every file's and
/// directory's hash feeds into it. Two Root packets with different contents under
/// the same InputSetID are unresolvable ambiguity, not damage.
///
/// Permission packets are not allowed as Root options; only Link packets are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootPacket {
    /// Lowest unused input block index. For a set that is not an incremental
    /// backup this is the set's block count.
    pub lowest_unused_block_index: u64,
    /// The attribute bit field. Only [`ATTRIBUTE_ABSOLUTE_PATH`] is defined.
    pub attributes: u8,
    /// Hashes of the Root's option packets — links only.
    pub option_hashes: Vec<Fingerprint>,
    /// Hashes of the File and Directory packets in the top-level directory.
    pub children: Vec<Fingerprint>,
}

impl RootPacket {
    /// Parse a Root packet body.
    ///
    /// Refuses an attribute byte with any bit set beyond
    /// [`ATTRIBUTE_ABSOLUTE_PATH`], which the specification requires to be zero.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let lowest_unused_block_index = reader.u64()?;
        let attributes = reader.u8()?;
        if attributes & !ATTRIBUTE_ABSOLUTE_PATH != 0 {
            return Err(reader.malformed(format!(
                "attribute byte {attributes:#04x} sets bits the format reserves as zero"
            )));
        }
        let option_count = reader.u32()?;
        let option_hashes = reader.fingerprints(u64::from(option_count), "option")?;
        let remaining = reader.remaining();
        if !remaining.is_multiple_of(16) {
            return Err(reader.malformed(format!(
                "{remaining} bytes of child hashes is not a multiple of 16"
            )));
        }
        let children = reader.fingerprints((remaining / 16) as u64, "child")?;
        Ok(Self {
            lowest_unused_block_index,
            attributes,
            option_hashes,
            children,
        })
    }

    /// Whether the tree describes an absolute path.
    #[must_use]
    pub fn is_absolute_path(&self) -> bool {
        self.attributes & ATTRIBUTE_ABSOLUTE_PATH != 0
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.lowest_unused_block_index.to_le_bytes());
        out.push(self.attributes);
        out.extend_from_slice(&(self.option_hashes.len() as u32).to_le_bytes());
        for hash in &self.option_hashes {
            out.extend_from_slice(hash);
        }
        for hash in &self.children {
            out.extend_from_slice(hash);
        }
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle_root() -> Vec<u8> {
        let mut body = 5u64.to_le_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0x75; 16]);
        body.extend_from_slice(&[0xa4; 16]);
        body.extend_from_slice(&[0xdf; 16]);
        body
    }

    #[test]
    fn parses_the_oracle_root() {
        let body = oracle_root();
        let packet = RootPacket::parse(&body).expect("parses");
        assert_eq!(packet.lowest_unused_block_index, 5);
        assert!(!packet.is_absolute_path());
        assert_eq!(packet.children.len(), 3);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn the_absolute_path_bit_is_accepted() {
        let mut body = oracle_root();
        body[8] = ATTRIBUTE_ABSOLUTE_PATH;
        let packet = RootPacket::parse(&body).expect("parses");
        assert!(packet.is_absolute_path());
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn reserved_attribute_bits_are_refused() {
        let mut body = oracle_root();
        body[8] = 0x02;
        assert!(RootPacket::parse(&body).is_err());
    }

    #[test]
    fn a_ragged_child_list_is_refused() {
        let mut body = oracle_root();
        body.pop();
        assert!(RootPacket::parse(&body).is_err());
    }

    #[test]
    fn an_absurd_option_count_is_refused_without_allocating() {
        let mut body = 5u64.to_le_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(RootPacket::parse(&body).is_err());
    }

    #[test]
    fn a_truncated_body_is_refused() {
        assert!(RootPacket::parse(&[0u8; 12]).is_err());
    }
}
