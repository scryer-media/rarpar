//! `PAR FIL\0` — one input file and the mapping of its bytes to input blocks.

use crate::error::Result;
use crate::hash::{Fingerprint, TAIL_HASH_LEN};
use crate::packet::reader::{BodyReader, decode_name};

const PACKET: &str = "File";

/// How a chunk's trailing partial block is described.
///
/// A chunk whose length is not a whole number of blocks ends in a "tail" shorter
/// than one block. Tails are stored differently depending on how small they are.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkTail {
    /// The chunk length is a whole number of blocks; there is no tail.
    None,
    /// A tail of 1 to 39 bytes, stored verbatim inside the chunk description.
    ///
    /// Nothing else describes these bytes: they are the data, so verifying them
    /// is a direct comparison rather than a hash check.
    Inline(Vec<u8>),
    /// A tail of at least 40 bytes, described by hashes and a location.
    ///
    /// Many tails may be packed into a single input block, and the specification
    /// even allows them to overlap, so the block index alone does not identify
    /// the tail.
    Described {
        /// CRC-64/GO-ISO of the tail's first 40 bytes, used to locate it.
        rolling_hash: u64,
        /// 16-byte BLAKE3 of the whole tail.
        fingerprint: Fingerprint,
        /// Index of the input block holding the tail.
        block_index: u64,
        /// Byte offset of the tail within that block.
        offset: u64,
    },
}

/// One chunk description from a File packet.
///
/// Chunks cover every byte of the file in order and never overlap, so a chunk's
/// position in the file is the sum of the lengths before it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkDescription {
    /// A chunk that is covered by input blocks and contributes to the file hash.
    Protected {
        /// Length of the chunk in bytes; always greater than zero.
        length: u64,
        /// Index of the first input block holding the chunk, present only when
        /// the chunk is at least one block long. Block-sized pieces occupy
        /// consecutive indices from there.
        first_block_index: Option<u64>,
        /// How the trailing partial block is described.
        tail: ChunkTail,
    },
    /// A chunk that no input block covers.
    ///
    /// Its bytes are hashed as zeros when computing the file's fingerprint, and
    /// it is not recoverable. These come from the "Par inside" feature.
    Unprotected {
        /// Length of the chunk in bytes.
        length: u64,
    },
}

impl ChunkDescription {
    /// Length of the chunk in bytes.
    #[must_use]
    pub fn length(&self) -> u64 {
        match self {
            Self::Protected { length, .. } | Self::Unprotected { length } => *length,
        }
    }

    /// Whether input blocks cover this chunk.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Protected { .. })
    }

    /// Indices of the whole input blocks this chunk occupies.
    ///
    /// Empty for unprotected chunks and for protected chunks shorter than one
    /// block. The tail block, if any, is not included: it may hold several tails
    /// from different files and is described separately.
    #[must_use]
    pub fn full_block_indices(&self, block_size: u64) -> Vec<u64> {
        let Self::Protected {
            length,
            first_block_index: Some(first),
            ..
        } = self
        else {
            return Vec::new();
        };
        if block_size == 0 {
            return Vec::new();
        }
        let count = length / block_size;
        (0..count).map(|i| first.wrapping_add(i)).collect()
    }
}

/// The File packet: a name, whole-file checksums, and chunk descriptions.
///
/// # Reading needs the block size
///
/// Whether a chunk description carries a first-block index, and how long its
/// tail is, both follow from the set's block size. A File packet therefore
/// cannot be parsed without the Start packet of its input set — the scanner
/// keeps such a packet opaque until a block size is known, and
/// [`Par3Set`](crate::set::Par3Set) parses it then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePacket {
    /// The file's name. A single path component, never a path.
    pub name: String,
    /// CRC-64/GO-ISO of the file's first 16 KiB, or of the whole file when it is
    /// shorter. Zero when unknown. Only a hint: it may cover unprotected bytes,
    /// and it is not unique.
    pub quick_rolling_hash: u64,
    /// 16-byte BLAKE3 of the file's protected data, with unprotected chunks
    /// hashed as zeros. All zeros when the producer did not compute it.
    pub fingerprint: Fingerprint,
    /// Hashes of this file's option packets — UNIX and FAT permissions.
    pub option_hashes: Vec<Fingerprint>,
    /// The chunk descriptions, in file order.
    pub chunks: Vec<ChunkDescription>,
}

impl FilePacket {
    /// Parse a File packet body for a set whose block size is `block_size`.
    pub fn parse(body: &[u8], block_size: u64) -> Result<Self> {
        let mut reader = BodyReader::new(body, PACKET);
        let name_len = reader.u16()?;
        let name = decode_name(reader.take(usize::from(name_len))?, PACKET)?;
        let quick_rolling_hash = reader.u64()?;
        let fingerprint = reader.fingerprint()?;
        let option_count = reader.u8()?;
        let option_hashes = reader.fingerprints(u64::from(option_count), "option")?;

        let mut chunks = Vec::new();
        while reader.remaining() > 0 {
            let length = reader.u64()?;
            if length == 0 {
                chunks.push(ChunkDescription::Unprotected {
                    length: reader.u64()?,
                });
                continue;
            }
            if block_size == 0 {
                return Err(reader.malformed(
                    "a protected chunk needs a block size greater than zero".to_owned(),
                ));
            }
            let first_block_index = if length >= block_size {
                Some(reader.u64()?)
            } else {
                None
            };
            let tail_size = length % block_size;
            let tail = if tail_size == 0 {
                ChunkTail::None
            } else if tail_size < TAIL_HASH_LEN as u64 {
                // Under 40, so the cast and the read are both bounded.
                ChunkTail::Inline(reader.take(tail_size as usize)?.to_vec())
            } else {
                ChunkTail::Described {
                    rolling_hash: reader.u64()?,
                    fingerprint: reader.fingerprint()?,
                    block_index: reader.u64()?,
                    offset: reader.u64()?,
                }
            };
            chunks.push(ChunkDescription::Protected {
                length,
                first_block_index,
                tail,
            });
        }

        Ok(Self {
            name,
            quick_rolling_hash,
            fingerprint,
            option_hashes,
            chunks,
        })
    }

    /// The file's length: the sum of its chunk lengths.
    ///
    /// `None` if that sum overflows, which only a corrupt or hostile packet can
    /// manage.
    #[must_use]
    pub fn file_size(&self) -> Option<u64> {
        self.chunks
            .iter()
            .try_fold(0u64, |total, chunk| total.checked_add(chunk.length()))
    }

    /// Whether any of the file's bytes are outside the protected set.
    #[must_use]
    pub fn has_unprotected_data(&self) -> bool {
        self.chunks.iter().any(|chunk| !chunk.is_protected())
    }

    /// Whether the producer left the protected-data fingerprint unset.
    #[must_use]
    pub fn fingerprint_is_unset(&self) -> bool {
        self.fingerprint == [0u8; 16]
    }

    /// Append the body bytes to `out`.
    ///
    /// The chunk descriptions are written exactly as the variants describe them:
    /// a `first_block_index` of `None` emits no index, and the tail form follows
    /// the [`ChunkTail`] variant. A packet read from a set therefore writes back
    /// byte for byte.
    ///
    /// The format's option count is one byte here, and the name length is two, so
    /// a hand-built packet with more than 255 options or a name longer than
    /// 65,535 bytes cannot be represented; both are truncated to what fits rather
    /// than emitting a count that disagrees with the bytes that follow it.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        let name = self.name.as_bytes();
        let name = &name[..name.len().min(u16::MAX as usize)];
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.quick_rolling_hash.to_le_bytes());
        out.extend_from_slice(&self.fingerprint);
        let options = &self.option_hashes[..self.option_hashes.len().min(u8::MAX as usize)];
        out.push(options.len() as u8);
        for hash in options {
            out.extend_from_slice(hash);
        }
        for chunk in &self.chunks {
            match chunk {
                ChunkDescription::Unprotected { length } => {
                    out.extend_from_slice(&0u64.to_le_bytes());
                    out.extend_from_slice(&length.to_le_bytes());
                }
                ChunkDescription::Protected {
                    length,
                    first_block_index,
                    tail,
                } => {
                    out.extend_from_slice(&length.to_le_bytes());
                    if let Some(index) = first_block_index {
                        out.extend_from_slice(&index.to_le_bytes());
                    }
                    match tail {
                        ChunkTail::None => {}
                        ChunkTail::Inline(bytes) => out.extend_from_slice(bytes),
                        ChunkTail::Described {
                            rolling_hash,
                            fingerprint,
                            block_index,
                            offset,
                        } => {
                            out.extend_from_slice(&rolling_hash.to_le_bytes());
                            out.extend_from_slice(fingerprint);
                            out.extend_from_slice(&block_index.to_le_bytes());
                            out.extend_from_slice(&offset.to_le_bytes());
                        }
                    }
                }
            }
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

    /// The File packet body for `b.txt` from the oracle `set.par3`: a ten-byte
    /// file that fits entirely in an inline tail.
    fn oracle_b_txt() -> Vec<u8> {
        let mut body = 5u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"b.txt");
        body.extend_from_slice(&0x7004_253A_AB19_C87Cu64.to_le_bytes());
        body.extend_from_slice(&[
            0xbc, 0x09, 0x4a, 0x87, 0x03, 0xd2, 0xce, 0x99, 0x64, 0x03, 0xc1, 0x32, 0x25, 0xb9,
            0x7a, 0x81,
        ]);
        body.push(0);
        body.extend_from_slice(&10u64.to_le_bytes());
        body.extend_from_slice(b"qrstuvwxyz");
        body
    }

    #[test]
    fn parses_an_inline_tail() {
        let body = oracle_b_txt();
        let packet = FilePacket::parse(&body, 2000).expect("parses");
        assert_eq!(packet.name, "b.txt");
        assert_eq!(packet.file_size(), Some(10));
        assert!(!packet.has_unprotected_data());
        assert!(!packet.fingerprint_is_unset());
        assert_eq!(
            packet.chunks,
            vec![ChunkDescription::Protected {
                length: 10,
                first_block_index: None,
                tail: ChunkTail::Inline(b"qrstuvwxyz".to_vec()),
            }]
        );
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn parses_a_described_tail_and_a_first_block_index() {
        let mut body = 5u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"a.bin");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.push(0);
        body.extend_from_slice(&5000u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0x1122u64.to_le_bytes());
        body.extend_from_slice(&[7u8; 16]);
        body.extend_from_slice(&2u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());

        let packet = FilePacket::parse(&body, 2000).expect("parses");
        assert!(packet.fingerprint_is_unset());
        let chunk = &packet.chunks[0];
        assert_eq!(chunk.length(), 5000);
        assert_eq!(chunk.full_block_indices(2000), vec![0, 1]);
        assert!(matches!(
            chunk,
            ChunkDescription::Protected {
                first_block_index: Some(0),
                tail: ChunkTail::Described {
                    block_index: 2,
                    offset: 0,
                    ..
                },
                ..
            }
        ));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn parses_a_block_aligned_chunk_without_a_tail() {
        let mut body = 5u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"c.bin");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[1u8; 16]);
        body.push(0);
        body.extend_from_slice(&4000u64.to_le_bytes());
        body.extend_from_slice(&3u64.to_le_bytes());

        let packet = FilePacket::parse(&body, 2000).expect("parses");
        assert_eq!(packet.chunks[0].full_block_indices(2000), vec![3, 4]);
        assert!(matches!(
            packet.chunks[0],
            ChunkDescription::Protected {
                tail: ChunkTail::None,
                ..
            }
        ));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn parses_unprotected_chunks() {
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"x");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.push(0);
        body.extend_from_slice(&2000u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&6000u64.to_le_bytes());
        body.extend_from_slice(&2000u64.to_le_bytes());
        body.extend_from_slice(&1u64.to_le_bytes());

        let packet = FilePacket::parse(&body, 2000).expect("parses");
        assert_eq!(packet.chunks.len(), 3);
        assert!(packet.has_unprotected_data());
        assert_eq!(packet.file_size(), Some(10_000));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn option_hashes_are_retained() {
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"x");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.push(2);
        body.extend_from_slice(&[3u8; 16]);
        body.extend_from_slice(&[4u8; 16]);
        let packet = FilePacket::parse(&body, 2000).expect("parses");
        assert_eq!(packet.option_hashes, vec![[3u8; 16], [4u8; 16]]);
        assert!(packet.chunks.is_empty());
        assert_eq!(packet.file_size(), Some(0));
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn an_absurd_option_count_is_refused_without_allocating() {
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"x");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.push(255);
        assert!(FilePacket::parse(&body, 2000).is_err());
    }

    #[test]
    fn an_unsafe_name_is_refused() {
        let mut body = 3u16.to_le_bytes().to_vec();
        body.extend_from_slice(b"../");
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.push(0);
        assert!(FilePacket::parse(&body, 2000).is_err());
    }

    #[test]
    fn a_protected_chunk_needs_a_block_size() {
        let body = oracle_b_txt();
        assert!(FilePacket::parse(&body, 0).is_err());
    }

    #[test]
    fn a_truncated_body_is_refused_without_panicking() {
        let body = oracle_b_txt();
        for len in 0..body.len() {
            let _ = FilePacket::parse(&body[..len], 2000);
        }
        assert!(FilePacket::parse(&body[..body.len() - 1], 2000).is_err());
    }
}
