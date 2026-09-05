//! `PAR DAT\0` — one input block's data carried inside the set.

use crate::error::Result;
use crate::packet::reader::BodyReader;

const PACKET: &str = "Data";

/// The Data packet: an input block index followed by that block's bytes.
///
/// The data may be shorter than the set's block size, in which case the block is
/// zero-filled to that size. This crate does not check the length against the
/// block size at parse time, because a Data packet can be read from a file that
/// carries no Start packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Index of the input block this data belongs to.
    pub block_index: u64,
    /// The block's stored bytes, before any zero padding.
    pub data: Vec<u8>,
}

impl DataPacket {
    /// Parse a Data packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let block_index = reader.u64()?;
        let data = reader.rest().to_vec();
        Ok(Self { block_index, data })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.block_index.to_le_bytes());
        out.extend_from_slice(&self.data);
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

    #[test]
    fn round_trips() {
        let mut body = 7u64.to_le_bytes().to_vec();
        body.extend_from_slice(b"block bytes");
        let packet = DataPacket::parse(&body).expect("parses");
        assert_eq!(packet.block_index, 7);
        assert_eq!(packet.data, b"block bytes");
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn an_empty_payload_is_legal() {
        let body = 0u64.to_le_bytes();
        let packet = DataPacket::parse(&body).expect("parses");
        assert!(packet.data.is_empty());
    }

    #[test]
    fn a_body_without_an_index_is_refused() {
        assert!(DataPacket::parse(&[0u8; 7]).is_err());
    }
}
