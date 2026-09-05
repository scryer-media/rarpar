//! `PAR DIR\0` — one sub-directory of the input set.

use crate::error::Result;
use crate::hash::Fingerprint;
use crate::packet::reader::{BodyReader, decode_name};

const PACKET: &str = "Directory";

/// The Directory packet: a name, option packets, and the children it contains.
///
/// Children are named by the hash of their own File or Directory packet, sorted
/// ascending by those bytes. The same child hash may appear in more than one
/// directory, which represents a complete copy rather than a link.
///
/// Note the option count is four bytes wide here, where the File packet uses one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryPacket {
    /// The directory's name. A single path component, never a path.
    pub name: String,
    /// Hashes of this directory's option packets — links and permissions.
    pub option_hashes: Vec<Fingerprint>,
    /// Hashes of the File and Directory packets this directory contains.
    pub children: Vec<Fingerprint>,
}

impl DirectoryPacket {
    /// Parse a Directory packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let name_len = reader.u16()?;
        let name = decode_name(reader.take(usize::from(name_len))?, PACKET)?;
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
            name,
            option_hashes,
            children,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        let name = self.name.as_bytes();
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
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

    /// The Directory packet body for `sub` from the oracle `set.par3`.
    fn oracle_sub() -> Vec<u8> {
        let mut body = 3u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"sub");
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[
            0xb1, 0xff, 0x9d, 0x1b, 0xd6, 0xe2, 0xba, 0xcb, 0xa5, 0xf2, 0x22, 0x63, 0x65, 0x69,
            0xb1, 0xab,
        ]);
        body
    }

    #[test]
    fn parses_the_oracle_directory() {
        let body = oracle_sub();
        let packet = DirectoryPacket::parse(&body).expect("parses");
        assert_eq!(packet.name, "sub");
        assert!(packet.option_hashes.is_empty());
        assert_eq!(packet.children.len(), 1);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn an_empty_directory_is_accepted() {
        let mut body = 3u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"sub");
        body.extend_from_slice(&0u32.to_le_bytes());
        let packet = DirectoryPacket::parse(&body).expect("parses");
        assert!(packet.children.is_empty());
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn a_ragged_child_list_is_refused() {
        let mut body = oracle_sub();
        body.pop();
        assert!(DirectoryPacket::parse(&body).is_err());
    }

    #[test]
    fn an_absurd_option_count_is_refused_without_allocating() {
        let mut body = 3u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"sub");
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(DirectoryPacket::parse(&body).is_err());
    }

    #[test]
    fn an_unsafe_name_is_refused() {
        let mut body = 2u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"..");
        body.extend_from_slice(&0u32.to_le_bytes());
        assert!(DirectoryPacket::parse(&body).is_err());
    }
}
