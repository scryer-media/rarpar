//! `PAR EXT\0` — checksums for input blocks that live outside the set.

use crate::error::Result;
use crate::hash::Fingerprint;
use crate::packet::reader::BodyReader;

const PACKET: &str = "External Data";

/// Bytes one block's checksum pair occupies: an 8-byte rolling hash and a
/// 16-byte fingerprint.
pub const CHECKSUM_PAIR_LEN: usize = 24;

/// The rolling hash and fingerprint of one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockChecksum {
    /// CRC-64/GO-ISO of the block, zero-padded to the set's block size.
    pub rolling_hash: u64,
    /// 16-byte BLAKE3 of the same bytes.
    pub fingerprint: Fingerprint,
}

/// The External Data packet: consecutive block checksums from a starting index.
///
/// # Coverage is not guaranteed
///
/// The reference implementation deliberately omits blocks that hold chunk tails,
/// emitting one packet per run of full-size blocks, so a set's External Data
/// packets normally do *not* cover every block. Parsers must accept any
/// coverage, and verification must fall back to the File packet's own hashes for
/// whatever is not covered.
///
/// Block hashes are taken over the block zero-padded to the full block size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDataPacket {
    /// Index of the input block the first checksum pair describes.
    pub first_block_index: u64,
    /// Checksums for consecutive blocks starting at `first_block_index`.
    pub checksums: Vec<BlockChecksum>,
}

impl ExternalDataPacket {
    /// Parse an External Data packet body.
    ///
    /// The body must be `8 + 24 * n` bytes for some `n`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let first_block_index = reader.u64()?;
        let remaining = reader.remaining();
        if !remaining.is_multiple_of(CHECKSUM_PAIR_LEN) {
            return Err(reader.malformed(format!(
                "{remaining} checksum bytes is not a multiple of {CHECKSUM_PAIR_LEN}"
            )));
        }
        // Bounded by the body length that was already read, so this reservation
        // cannot be inflated by a value inside the packet.
        let mut checksums = Vec::with_capacity(remaining / CHECKSUM_PAIR_LEN);
        while reader.remaining() > 0 {
            checksums.push(BlockChecksum {
                rolling_hash: reader.u64()?,
                fingerprint: reader.fingerprint()?,
            });
        }
        Ok(Self {
            first_block_index,
            checksums,
        })
    }

    /// The block indices this packet describes.
    pub fn block_indices(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.checksums.len() as u64).map(move |i| self.first_block_index.wrapping_add(i))
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.first_block_index.to_le_bytes());
        for checksum in &self.checksums {
            out.extend_from_slice(&checksum.rolling_hash.to_le_bytes());
            out.extend_from_slice(&checksum.fingerprint);
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

    fn body(first: u64, pairs: usize) -> Vec<u8> {
        let mut out = first.to_le_bytes().to_vec();
        for i in 0..pairs {
            out.extend_from_slice(&(i as u64).to_le_bytes());
            out.extend_from_slice(&[i as u8; 16]);
        }
        out
    }

    #[test]
    fn round_trips() {
        let bytes = body(3, 2);
        let packet = ExternalDataPacket::parse(&bytes).expect("parses");
        assert_eq!(packet.first_block_index, 3);
        assert_eq!(packet.checksums.len(), 2);
        assert_eq!(packet.block_indices().collect::<Vec<_>>(), vec![3, 4]);
        assert_eq!(packet.to_body_bytes(), bytes);
    }

    #[test]
    fn an_empty_checksum_list_is_accepted() {
        let packet = ExternalDataPacket::parse(&body(0, 0)).expect("parses");
        assert!(packet.checksums.is_empty());
    }

    #[test]
    fn a_partial_checksum_pair_is_refused() {
        let mut bytes = body(0, 1);
        bytes.pop();
        assert!(ExternalDataPacket::parse(&bytes).is_err());
    }

    #[test]
    fn a_body_without_an_index_is_refused() {
        assert!(ExternalDataPacket::parse(&[0u8; 4]).is_err());
    }
}
