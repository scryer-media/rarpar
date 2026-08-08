//! Packet encoding primitives used by the PAR2 creator.
//!
//! Parsing is intentionally kept separate from creation.  These helpers are
//! crate-private because callers should use the higher-level creation API,
//! while the writer needs the exact wire-format header and hash semantics.

use std::io::Write;

use crate::checksum::Md5State;
use crate::error::{Par2Error, Result};
use crate::types::RecoverySetId;

use super::header::{HEADER_SIZE, MAGIC};

/// Build a complete, in-memory packet with its PAR2 packet hash populated.
pub(crate) fn encode_packet(
    packet_type: &[u8; 16],
    recovery_set_id: RecoverySetId,
    body: &[u8],
) -> Result<Vec<u8>> {
    let length =
        HEADER_SIZE
            .checked_add(body.len())
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "packet length overflows addressable memory".to_string(),
            })?;
    if !length.is_multiple_of(4) {
        return Err(Par2Error::InvalidPacketLength {
            length: length as u64,
        });
    }

    let packet_hash = packet_hash(recovery_set_id, packet_type, body);
    let mut packet = Vec::with_capacity(length);
    packet.extend_from_slice(&MAGIC[..]);
    packet.extend_from_slice(&(length as u64).to_le_bytes());
    packet.extend_from_slice(&packet_hash);
    packet.extend_from_slice(recovery_set_id.as_bytes());
    packet.extend_from_slice(packet_type);
    packet.extend_from_slice(body);
    Ok(packet)
}

/// Return the MD5 covered by a packet header (bytes 32..length).
pub(crate) fn packet_hash(
    recovery_set_id: RecoverySetId,
    packet_type: &[u8; 16],
    body: &[u8],
) -> [u8; 16] {
    let mut hasher = Md5State::new();
    hasher.update(recovery_set_id.as_bytes());
    hasher.update(packet_type);
    hasher.update(body);
    hasher.finalize()
}

/// Start a streamed recovery-packet hash.  The caller feeds the exponent and
/// every data stripe in packet order, then uses [`finish_streamed_header`].
pub(crate) fn start_streamed_hash(
    recovery_set_id: RecoverySetId,
    packet_type: &[u8; 16],
) -> Md5State {
    let mut hasher = Md5State::new();
    hasher.update(recovery_set_id.as_bytes());
    hasher.update(packet_type);
    hasher
}

/// Encode a header whose packet hash is supplied by a streamed writer.
pub(crate) fn encode_header(
    packet_type: &[u8; 16],
    recovery_set_id: RecoverySetId,
    length: u64,
    packet_hash: [u8; 16],
) -> Result<[u8; HEADER_SIZE]> {
    if length < HEADER_SIZE as u64 || !length.is_multiple_of(4) {
        return Err(Par2Error::InvalidPacketLength { length });
    }

    let mut header = [0u8; HEADER_SIZE];
    header[0..8].copy_from_slice(&MAGIC[..]);
    header[8..16].copy_from_slice(&length.to_le_bytes());
    header[16..32].copy_from_slice(&packet_hash);
    header[32..48].copy_from_slice(recovery_set_id.as_bytes());
    header[48..64].copy_from_slice(packet_type);
    Ok(header)
}

/// Write a complete in-memory packet at the current stream position.
#[allow(dead_code)]
pub(crate) fn write_packet<W: Write>(
    writer: &mut W,
    packet_type: &[u8; 16],
    recovery_set_id: RecoverySetId,
    body: &[u8],
) -> Result<()> {
    writer
        .write_all(&encode_packet(packet_type, recovery_set_id, body)?)
        .map_err(Par2Error::Io)
}
