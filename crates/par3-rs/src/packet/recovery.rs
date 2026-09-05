//! `PAR REC\0` and `PAR ERD\0` — recovery blocks and their checksums.

use crate::error::Result;
use crate::hash::Fingerprint;
use crate::packet::external_data::{BlockChecksum, CHECKSUM_PAIR_LEN};
use crate::packet::reader::BodyReader;

/// The Recovery Data packet: one recovery block, with the Root and Matrix packet
/// hashes that say how it was computed.
///
/// The data may be shorter than the block size, in which case it is zero-filled.
/// This crate retains the bytes but computes nothing from them: PAR3 repair is
/// out of scope for `0.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDataPacket {
    /// Hash of the Root packet whose input blocks this recovery block covers.
    pub root_hash: Fingerprint,
    /// Hash of the Matrix packet whose row produced this recovery block.
    pub matrix_hash: Fingerprint,
    /// Index of the recovery block, which selects the matrix row.
    pub recovery_block_index: u64,
    /// The recovery block's stored bytes, before any zero padding.
    pub data: Vec<u8>,
}

impl RecoveryDataPacket {
    /// Body length excluding the recovery data itself.
    pub const BODY_BASE_LEN: usize = 40;

    /// Parse a Recovery Data packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, "Recovery Data");
        let root_hash = reader.fingerprint()?;
        let matrix_hash = reader.fingerprint()?;
        let recovery_block_index = reader.u64()?;
        let data = reader.rest().to_vec();
        Ok(Self {
            root_hash,
            matrix_hash,
            recovery_block_index,
            data,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.root_hash);
        out.extend_from_slice(&self.matrix_hash);
        out.extend_from_slice(&self.recovery_block_index.to_le_bytes());
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

/// The Recovery External Data packet: checksums for recovery blocks held outside
/// the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExternalDataPacket {
    /// Hash of the Root packet whose input blocks the recovery blocks cover.
    pub root_hash: Fingerprint,
    /// Hash of the Matrix packet whose rows produced the recovery blocks.
    pub matrix_hash: Fingerprint,
    /// Index of the recovery block the first checksum pair describes.
    pub first_recovery_block_index: u64,
    /// Checksums for consecutive recovery blocks.
    pub checksums: Vec<BlockChecksum>,
}

impl RecoveryExternalDataPacket {
    /// Parse a Recovery External Data packet body.
    ///
    /// The body must be `40 + 24 * n` bytes for some `n`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, "Recovery External Data");
        let root_hash = reader.fingerprint()?;
        let matrix_hash = reader.fingerprint()?;
        let first_recovery_block_index = reader.u64()?;
        let remaining = reader.remaining();
        if !remaining.is_multiple_of(CHECKSUM_PAIR_LEN) {
            return Err(reader.malformed(format!(
                "{remaining} checksum bytes is not a multiple of {CHECKSUM_PAIR_LEN}"
            )));
        }
        // Bounded by the body length already read.
        let mut checksums = Vec::with_capacity(remaining / CHECKSUM_PAIR_LEN);
        while reader.remaining() > 0 {
            checksums.push(BlockChecksum {
                rolling_hash: reader.u64()?,
                fingerprint: reader.fingerprint()?,
            });
        }
        Ok(Self {
            root_hash,
            matrix_hash,
            first_recovery_block_index,
            checksums,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.root_hash);
        out.extend_from_slice(&self.matrix_hash);
        out.extend_from_slice(&self.first_recovery_block_index.to_le_bytes());
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

    fn base() -> Vec<u8> {
        let mut out = vec![1u8; 16];
        out.extend_from_slice(&[2u8; 16]);
        out.extend_from_slice(&3u64.to_le_bytes());
        out
    }

    #[test]
    fn recovery_data_round_trips() {
        let mut body = base();
        body.extend_from_slice(b"recovery");
        let packet = RecoveryDataPacket::parse(&body).expect("parses");
        assert_eq!(packet.root_hash, [1u8; 16]);
        assert_eq!(packet.matrix_hash, [2u8; 16]);
        assert_eq!(packet.recovery_block_index, 3);
        assert_eq!(packet.data, b"recovery");
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn recovery_data_refuses_a_truncated_header() {
        assert!(RecoveryDataPacket::parse(&base()[..39]).is_err());
    }

    #[test]
    fn recovery_external_data_round_trips() {
        let mut body = base();
        body.extend_from_slice(&7u64.to_le_bytes());
        body.extend_from_slice(&[8u8; 16]);
        let packet = RecoveryExternalDataPacket::parse(&body).expect("parses");
        assert_eq!(packet.first_recovery_block_index, 3);
        assert_eq!(packet.checksums.len(), 1);
        assert_eq!(packet.checksums[0].rolling_hash, 7);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn recovery_external_data_refuses_a_partial_pair() {
        let mut body = base();
        body.extend_from_slice(&[0u8; 23]);
        assert!(RecoveryExternalDataPacket::parse(&body).is_err());
    }
}
