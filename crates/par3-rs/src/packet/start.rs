//! `PAR STA\0` — block size and Galois field parameters.

use crate::error::Result;
use crate::hash::Fingerprint;
use crate::packet::header::InputSetId;
use crate::packet::reader::BodyReader;

const PACKET: &str = "Start";

/// Body length of the current Start packet form, excluding the generator bytes.
const BODY_BASE: usize = 8 + 16 + 8 + 1;

/// Body length at or above which the reference implementation reads the body as
/// the superseded form that begins with eight random bytes.
const LEGACY_BODY_MIN: usize = 8 + BODY_BASE;

/// The Galois field a set's recovery data is computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GaloisField {
    /// Size of one field element in bytes. `0` means no field at all: recovery
    /// data, if any, is a plain XOR sum. The reference implementation writes
    /// only 0, 1 or 2.
    pub size: u8,
    /// The generator polynomial with its leading 1 removed, as stored.
    pub generator: u64,
}

impl GaloisField {
    /// The full generator polynomial, with the leading 1 restored.
    ///
    /// `None` when the set declares no Galois field, and also for the
    /// hypothetical 8-byte field, whose leading 1 does not fit in a `u64`.
    /// `GF(2^8)` with a stored generator of `0x1D` yields `0x11D`; `GF(2^16)`
    /// with `0x100B` yields `0x1100B`.
    #[must_use]
    pub fn polynomial(&self) -> Option<u64> {
        match self.size {
            1..=7 => Some(self.generator | 1u64 << (u32::from(self.size) * 8)),
            _ => None,
        }
    }
}

/// The Start packet: one per input set, naming the block size and field.
///
/// # Two body layouts
///
/// The 2022-03-21 draft opens the body with eight random bytes. The reference
/// implementation removed that field — the random number only ever randomised
/// the InputSetID, and was never read back — and its parser now recognises the
/// older form by body length. This type does the same, and retains the bytes of
/// an old-form packet so it can be written back unchanged.
///
/// # The InputSetID is not derived from this body
///
/// The published specification says the InputSetID is the first eight bytes of
/// the BLAKE3 hash of this body. The reference implementation hashes eight random
/// bytes *and* the body, and stores only the result. The identifier therefore
/// cannot be recomputed from anything on disk, and this crate never tries: it is
/// an opaque grouping key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPacket {
    /// The parent set for an incremental backup, or [`InputSetId::ZERO`].
    pub parent_input_set_id: InputSetId,
    /// The parent set's Root packet hash, or all zeros.
    pub parent_root_hash: Fingerprint,
    /// Input and recovery block size in bytes.
    pub block_size: u64,
    /// The Galois field.
    pub galois_field: GaloisField,
    /// The eight leading random bytes of the superseded body layout, present
    /// only when the packet was written in that form.
    pub legacy_random: Option<[u8; 8]>,
}

impl StartPacket {
    /// Parse a Start packet body.
    ///
    /// Bodies of `33 + field size` bytes are the current layout; bodies of
    /// `41 + field size` are the superseded one. Any other length is refused,
    /// as are field sizes a `u64` generator cannot hold.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let legacy_random = if body.len() >= LEGACY_BODY_MIN {
            Some(<[u8; 8]>::try_from(reader.take(8)?).expect("8 bytes"))
        } else {
            None
        };

        let parent_input_set_id = InputSetId(reader.take(8)?.try_into().expect("8 bytes"));
        let parent_root_hash = reader.fingerprint()?;
        let block_size = reader.u64()?;
        let size = reader.u8()?;
        if size > 8 {
            return Err(reader.malformed(format!("Galois field size {size} exceeds 8 bytes")));
        }
        let generator_bytes = reader.take(usize::from(size))?;
        let mut generator = [0u8; 8];
        generator[..generator_bytes.len()].copy_from_slice(generator_bytes);
        let generator = u64::from_le_bytes(generator);
        reader.finish()?;

        if !parent_input_set_id.is_zero() && parent_root_hash == [0u8; 16] {
            return Err(crate::error::Par3Error::MalformedPacket {
                packet: PACKET,
                reason: format!(
                    "declares parent set {parent_input_set_id} but no parent Root packet hash"
                ),
            });
        }

        Ok(Self {
            parent_input_set_id,
            parent_root_hash,
            block_size,
            galois_field: GaloisField { size, generator },
            legacy_random,
        })
    }

    /// Whether this set is an incremental backup of another one.
    #[must_use]
    pub fn has_parent(&self) -> bool {
        !self.parent_input_set_id.is_zero()
    }

    /// Append the body bytes to `out`, in whichever layout this packet was read.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        if let Some(random) = self.legacy_random {
            out.extend_from_slice(&random);
        }
        out.extend_from_slice(self.parent_input_set_id.as_bytes());
        out.extend_from_slice(&self.parent_root_hash);
        out.extend_from_slice(&self.block_size.to_le_bytes());
        out.push(self.galois_field.size);
        out.extend_from_slice(
            &self.galois_field.generator.to_le_bytes()[..usize::from(self.galois_field.size)],
        );
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

    /// The Start packet body from the oracle `set.par3`.
    const ORACLE_GF8: [u8; 34] = [
        0, 0, 0, 0, 0, 0, 0, 0, // parent InputSetID
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // parent Root hash
        0xd0, 0x07, 0, 0, 0, 0, 0, 0,    // block size 2000
        0x01, // Galois field size
        0x1d, // generator 0x11D without its leading 1
    ];

    #[test]
    fn parses_the_oracle_gf8_start_packet() {
        let packet = StartPacket::parse(&ORACLE_GF8).expect("parses");
        assert_eq!(packet.block_size, 2000);
        assert_eq!(packet.galois_field.size, 1);
        assert_eq!(packet.galois_field.generator, 0x1d);
        assert_eq!(packet.galois_field.polynomial(), Some(0x11d));
        assert!(!packet.has_parent());
        assert_eq!(packet.legacy_random, None);
        assert_eq!(packet.to_body_bytes(), ORACLE_GF8);
    }

    #[test]
    fn parses_a_gf16_start_packet() {
        let mut body = ORACLE_GF8[..33].to_vec();
        body[24..32].copy_from_slice(&100u64.to_le_bytes());
        body[32] = 2;
        body.extend_from_slice(&[0x0b, 0x10]);
        let packet = StartPacket::parse(&body).expect("parses");
        assert_eq!(packet.block_size, 100);
        assert_eq!(packet.galois_field.polynomial(), Some(0x1_100b));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn parses_a_field_free_start_packet() {
        let body = &ORACLE_GF8[..33];
        let mut body = body.to_vec();
        body[32] = 0;
        let packet = StartPacket::parse(&body).expect("parses");
        assert_eq!(packet.galois_field.size, 0);
        assert_eq!(packet.galois_field.polynomial(), None);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn parses_and_preserves_the_superseded_layout() {
        let mut body = vec![9, 8, 7, 6, 5, 4, 3, 2];
        body.extend_from_slice(&ORACLE_GF8);
        assert_eq!(body.len(), 42);
        let packet = StartPacket::parse(&body).expect("parses");
        assert_eq!(packet.block_size, 2000);
        assert_eq!(packet.legacy_random, Some([9, 8, 7, 6, 5, 4, 3, 2]));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn rejects_every_other_body_length() {
        for len in 0..ORACLE_GF8.len() {
            assert!(
                StartPacket::parse(&ORACLE_GF8[..len]).is_err(),
                "length {len} should be refused"
            );
        }
        let mut too_long = ORACLE_GF8.to_vec();
        too_long.push(0);
        assert!(StartPacket::parse(&too_long).is_err());
    }

    #[test]
    fn rejects_an_oversized_field() {
        let mut body = ORACLE_GF8[..33].to_vec();
        body[32] = 9;
        body.extend_from_slice(&[0u8; 9]);
        assert!(StartPacket::parse(&body).is_err());
    }

    #[test]
    fn rejects_a_parent_set_without_a_parent_root_hash() {
        let mut body = ORACLE_GF8;
        body[0] = 1;
        assert!(StartPacket::parse(&body).is_err());
    }

    #[test]
    fn accepts_a_parent_set_with_a_parent_root_hash() {
        let mut body = ORACLE_GF8;
        body[0] = 1;
        body[8] = 2;
        let packet = StartPacket::parse(&body).expect("parses");
        assert!(packet.has_parent());
        assert_eq!(packet.to_body_bytes(), body);
    }
}
