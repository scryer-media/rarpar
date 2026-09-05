//! Finding packets in bytes.
//!
//! PAR3 packets are located by their magic sequence, not by a table of contents,
//! so a `.par3` file can be read even when parts of it are missing or damaged and
//! packets for several input sets can share one file. The scanner walks the
//! bytes, keeps every packet whose header hash checks out, and resynchronises on
//! the next magic sequence when one does not.
//!
//! ```no_run
//! use par3_rs::{Par3Set, scan_packets_from_path};
//!
//! # fn main() -> par3_rs::Result<()> {
//! let scanned = scan_packets_from_path("set.par3".as_ref())?;
//! let packets = scanned.into_iter().map(|(_offset, packet)| packet).collect();
//! for set in Par3Set::from_packets(packets)? {
//!     println!("{} files, block size {}", set.files().len(), set.block_size());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Packets come back in the order they appear, duplicates included, so the result
//! is a faithful view of the bytes: writing every packet back out reproduces the
//! file. Deduplication belongs to [`Par3Set`](crate::set::Par3Set), which is where
//! packets from several files are combined.

use std::collections::HashMap;
use std::path::Path;

use crate::error::{Par3Error, Result};
use crate::packet::{HEADER_SIZE, InputSetId, MAGIC, Packet, PacketBody, ParseContext};

/// Bounds on one scan.
///
/// The scanner never allocates from a length it has not first checked against
/// the input, so most of these guard against a large *valid* input rather than
/// against a malicious small one. The exception is
/// [`max_failed_hash_passes`](ScanLimits::max_failed_hash_passes), which bounds
/// the work a small hostile input can ask for. Exceeding any of them fails the
/// scan with [`Par3Error::ScanLimitExceeded`]; the result is never silently
/// truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanLimits {
    /// Largest packet the scanner will accept. Larger packets are skipped as if
    /// damaged, matching what the reference implementation does with a packet
    /// bigger than its read buffer.
    pub max_packet_len: u64,
    /// Most packets one scan may return.
    pub max_packets: usize,
    /// Most body bytes one scan may retain.
    pub max_retained_bytes: u64,
    /// How many times over the input the scanner may hash bytes belonging to
    /// candidates that turn out not to be packets.
    ///
    /// A header that looks plausible can claim a range reaching to the end of
    /// the input, and the only way to find out that the claim is a lie is to
    /// hash that range. Rejecting a candidate only steps eight bytes, so an
    /// input made of nothing but overlapping candidates would otherwise cost
    /// work quadratic in its length. Genuine damage costs at most one pass over
    /// the bytes it covers, so a small multiple leaves real files alone.
    ///
    /// The budget is checked once a candidate has been hashed rather than
    /// before, so that a valid packet is never refused because of the damage
    /// ahead of it; at most one candidate is hashed past the budget.
    pub max_failed_hash_passes: u64,
}

impl ScanLimits {
    /// 1 GiB: far above any plausible block size, and small enough that a single
    /// packet cannot ask for an unreasonable allocation.
    pub const DEFAULT_MAX_PACKET_LEN: u64 = 1 << 30;
    /// One million packets. A set with a million packets is already implausible;
    /// this only stops a pathological file from being walked forever.
    pub const DEFAULT_MAX_PACKETS: usize = 1_000_000;
    /// 4 GiB of retained bodies.
    pub const DEFAULT_MAX_RETAINED_BYTES: u64 = 4 << 30;
    /// Eight passes. A `.par3` file damaged from end to end still only costs
    /// one, so this is generous for real recovery data and still turns the
    /// quadratic worst case into a linear one.
    pub const DEFAULT_MAX_FAILED_HASH_PASSES: u64 = 8;
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_packet_len: Self::DEFAULT_MAX_PACKET_LEN,
            max_packets: Self::DEFAULT_MAX_PACKETS,
            max_retained_bytes: Self::DEFAULT_MAX_RETAINED_BYTES,
            max_failed_hash_passes: Self::DEFAULT_MAX_FAILED_HASH_PASSES,
        }
    }
}

/// Scan `data` for PAR3 packets, using the default [`ScanLimits`].
///
/// Returns each packet with the byte offset it was found at, in file order.
pub fn scan_packets(data: &[u8]) -> Result<Vec<(u64, Packet)>> {
    scan_packets_with_limits(data, &ScanLimits::default())
}

/// Scan `data` for PAR3 packets under explicit limits.
pub fn scan_packets_with_limits(data: &[u8], limits: &ScanLimits) -> Result<Vec<(u64, Packet)>> {
    let mut found: Vec<(u64, Packet)> = Vec::new();
    let mut retained_bytes: u64 = 0;
    // Block size and Galois field size per input set, filled in as Start packets
    // turn up so that later File and Explicit Matrix packets can be typed on the
    // first pass. Anything that arrives before its Start packet is resolved below.
    let mut contexts: HashMap<InputSetId, ParseContext> = HashMap::new();
    // Work spent hashing candidates that turned out to be damage or noise, and
    // the budget it is charged against.
    let failed_hash_budget = (data.len() as u64).saturating_mul(limits.max_failed_hash_passes);
    let mut failed_hash_bytes: u64 = 0;

    let mut offset = 0usize;
    while let Some(position) = find_magic(data, offset) {
        // The header alone rules most candidates out, and doing so reads a
        // handful of fixed fields. Only a candidate that survives it is hashed,
        // and only that hashing is charged.
        let end = match candidate_end(data, position, limits) {
            Ok(end) => end,
            Err(error) => {
                tracing::debug!(offset = position, %error, "skipping PAR3 packet");
                offset = position + 8;
                continue;
            }
        };
        match parse_candidate(data, position, end, &contexts) {
            Ok(packet) => {
                if found.len() >= limits.max_packets {
                    return Err(Par3Error::ScanLimitExceeded {
                        reason: format!("more than {} packets", limits.max_packets),
                    });
                }
                retained_bytes = retained_bytes.saturating_add(packet.len());
                if retained_bytes > limits.max_retained_bytes {
                    return Err(Par3Error::ScanLimitExceeded {
                        reason: format!("more than {} retained bytes", limits.max_retained_bytes),
                    });
                }
                if let PacketBody::Start(start) = packet.body() {
                    contexts.insert(packet.input_set_id(), ParseContext::from_start(start));
                }
                offset = position + packet.len() as usize;
                found.push((position as u64, packet));
            }
            Err(error) => {
                tracing::debug!(offset = position, %error, "skipping PAR3 packet");
                failed_hash_bytes = failed_hash_bytes.saturating_add((end - position) as u64);
                if failed_hash_bytes > failed_hash_budget {
                    return Err(Par3Error::ScanLimitExceeded {
                        reason: format!(
                            "candidate packets that did not check out were hashed more than {} times over the input",
                            limits.max_failed_hash_passes
                        ),
                    });
                }
                // Same resynchronisation the reference implementation uses: step
                // past this magic sequence and look for the next one.
                offset = position + 8;
            }
        }
    }

    resolve_deferred(&mut found, &contexts);
    Ok(found)
}

/// Read a `.par3` file and scan it, using the default [`ScanLimits`].
///
/// The whole file is read into memory. For `0.1` that is the only mode; a
/// recovery volume is as large as the recovery data it carries.
pub fn scan_packets_from_path(path: &Path) -> Result<Vec<(u64, Packet)>> {
    scan_packets_from_path_with_limits(path, &ScanLimits::default())
}

/// Read a `.par3` file and scan it under explicit limits.
pub fn scan_packets_from_path_with_limits(
    path: &Path,
    limits: &ScanLimits,
) -> Result<Vec<(u64, Packet)>> {
    let data = std::fs::read(path)?;
    scan_packets_with_limits(&data, limits)
}

/// Index of the next magic sequence at or after `from`.
fn find_magic(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    let last_start = data.len().checked_sub(MAGIC.len())?;
    let mut index = from;
    while index <= last_start {
        let step = data[index..=last_start]
            .iter()
            .position(|&byte| byte == MAGIC[0])?;
        let candidate = index + step;
        if data[candidate..].starts_with(MAGIC) {
            return Some(candidate);
        }
        index = candidate + 1;
    }
    None
}

/// Where the candidate packet at `position` ends, or why its header alone rules
/// it out.
///
/// Every test here reads a fixed header field, so rejecting a candidate costs
/// nothing while hashing one costs its whole declared length. Keeping the two
/// apart is what lets the scan charge only the candidates it actually hashed.
fn candidate_end(data: &[u8], position: usize, limits: &ScanLimits) -> Result<usize> {
    if data.len() - position < HEADER_SIZE {
        return Err(Par3Error::PacketTooShort {
            offset: position as u64,
            expected: HEADER_SIZE as u64,
            actual: (data.len() - position) as u64,
        });
    }
    let length = u64::from_le_bytes(
        data[position + 24..position + 32]
            .try_into()
            .expect("8 bytes"),
    );
    if length < HEADER_SIZE as u64 {
        return Err(Par3Error::PacketTooShort {
            offset: position as u64,
            expected: HEADER_SIZE as u64,
            actual: length,
        });
    }
    if length > limits.max_packet_len {
        return Err(Par3Error::ScanLimitExceeded {
            reason: format!(
                "packet at offset {position} claims {length} bytes, over the {} byte limit",
                limits.max_packet_len
            ),
        });
    }
    // Bounds-checked against the real input before any body is copied, and
    // before anything is hashed: a packet running past the end of the input
    // cannot be one.
    position
        .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
        .filter(|end| *end <= data.len())
        .ok_or(Par3Error::PacketTooShort {
            offset: position as u64,
            expected: length,
            actual: (data.len() - position) as u64,
        })
}

/// Hash and parse the candidate spanning `position..end`.
fn parse_candidate(
    data: &[u8],
    position: usize,
    end: usize,
    contexts: &HashMap<InputSetId, ParseContext>,
) -> Result<Packet> {
    let set_id = InputSetId(
        data[position + 32..position + 40]
            .try_into()
            .expect("8 bytes"),
    );
    let context = contexts.get(&set_id).copied().unwrap_or_default();
    Packet::parse(&data[position..end], position as u64, &context)
}

/// Re-parse packets that were read before their input set's Start packet.
fn resolve_deferred(found: &mut [(u64, Packet)], contexts: &HashMap<InputSetId, ParseContext>) {
    for (offset, packet) in found.iter_mut() {
        let (packet_type, body) = match packet.body() {
            PacketBody::Opaque { packet_type, body } if PacketBody::needs_context(*packet_type) => {
                (*packet_type, body.clone())
            }
            _ => continue,
        };
        let Some(context) = contexts.get(&packet.input_set_id()) else {
            continue;
        };
        match PacketBody::parse(packet_type, &body, context) {
            Ok(parsed) => *packet = Packet::new(packet.input_set_id(), parsed),
            Err(error) => {
                tracing::debug!(offset, ?packet_type, %error, "PAR3 packet stays opaque");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{CommentPacket, CreatorPacket, StartPacket};

    fn comment(id: InputSetId, text: &str) -> Packet {
        Packet::new(id, PacketBody::Comment(CommentPacket::new(text)))
    }

    fn concat(packets: &[Packet]) -> Vec<u8> {
        let mut out = Vec::new();
        for packet in packets {
            out.extend_from_slice(&packet.to_bytes());
        }
        out
    }

    #[test]
    fn finds_every_packet_in_order() {
        let id = InputSetId([9; 8]);
        let packets = vec![
            Packet::new(id, PacketBody::Creator(CreatorPacket::new("test"))),
            comment(id, "one"),
            comment(id, "two"),
        ];
        let bytes = concat(&packets);
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].0, 0);
        assert_eq!(found[1].0, packets[0].len());
        assert_eq!(
            concat(&found.into_iter().map(|(_, p)| p).collect::<Vec<_>>()),
            bytes
        );
    }

    #[test]
    fn duplicates_are_kept_so_the_bytes_round_trip() {
        let id = InputSetId([1; 8]);
        let packets = vec![comment(id, "same"), comment(id, "same")];
        let bytes = concat(&packets);
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn junk_between_packets_is_skipped() {
        let id = InputSetId([2; 8]);
        let mut bytes = vec![0u8; 64];
        bytes.extend_from_slice(&comment(id, "one").to_bytes());
        bytes.extend_from_slice(b"PAR3\0PKTnot really a packet at all");
        bytes.extend_from_slice(&comment(id, "two").to_bytes());
        bytes.extend_from_slice(&[0xff; 10]);
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_damaged_packet_is_skipped_and_the_next_one_is_found() {
        let id = InputSetId([3; 8]);
        let good = comment(id, "survivor");
        let mut bytes = comment(id, "damaged").to_bytes();
        let damaged_len = bytes.len();
        bytes[HEADER_SIZE] ^= 0xff;
        bytes.extend_from_slice(&good.to_bytes());
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, damaged_len as u64);
        assert_eq!(found[0].1.hash(), good.hash());
    }

    #[test]
    fn a_truncated_final_packet_is_skipped() {
        let id = InputSetId([4; 8]);
        let mut bytes = comment(id, "complete").to_bytes();
        bytes.extend_from_slice(&comment(id, "truncated").to_bytes());
        bytes.truncate(bytes.len() - 3);
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_file_packet_before_its_start_packet_is_still_typed() {
        use crate::packet::{ChunkDescription, ChunkTail, FilePacket, GaloisField};

        let id = InputSetId([5; 8]);
        let file = FilePacket {
            name: "a.bin".to_owned(),
            quick_rolling_hash: 0,
            fingerprint: [0u8; 16],
            option_hashes: Vec::new(),
            chunks: vec![ChunkDescription::Protected {
                length: 10,
                first_block_index: None,
                tail: ChunkTail::Inline(b"qrstuvwxyz".to_vec()),
            }],
        };
        let start = StartPacket {
            parent_input_set_id: InputSetId::ZERO,
            parent_root_hash: [0u8; 16],
            block_size: 2000,
            galois_field: GaloisField {
                size: 1,
                generator: 0x1d,
            },
            legacy_random: None,
        };
        let packets = vec![
            Packet::new(id, PacketBody::File(file.clone())),
            Packet::new(id, PacketBody::Start(start)),
        ];
        let bytes = concat(&packets);
        let found = scan_packets(&bytes).expect("scans");
        assert_eq!(found[0].1.body(), &PacketBody::File(file));
        assert_eq!(
            concat(&found.into_iter().map(|(_, p)| p).collect::<Vec<_>>()),
            bytes
        );
    }

    #[test]
    fn the_packet_limit_is_enforced() {
        let id = InputSetId([6; 8]);
        let bytes = concat(&[comment(id, "a"), comment(id, "b")]);
        let limits = ScanLimits {
            max_packets: 1,
            ..ScanLimits::default()
        };
        assert!(matches!(
            scan_packets_with_limits(&bytes, &limits),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    #[test]
    fn the_retained_byte_limit_is_enforced() {
        let id = InputSetId([7; 8]);
        let bytes = concat(&[comment(id, "a")]);
        let limits = ScanLimits {
            max_retained_bytes: 8,
            ..ScanLimits::default()
        };
        assert!(matches!(
            scan_packets_with_limits(&bytes, &limits),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    #[test]
    fn overlapping_invalid_candidates_are_bounded() {
        // Twenty thousand 48-byte headers, each claiming a packet that runs to
        // the end of the input and each carrying a hash that cannot match.
        // Every one of them has to be hashed to be refused, and refusing one
        // only steps eight bytes, so without a budget this is quadratic: about
        // ten gigabytes of hashing for a one-megabyte input. The default budget
        // stops it after eight passes, which is why this test finishes.
        let mut data = vec![0u8; HEADER_SIZE * 20_000];
        for position in (0..data.len()).step_by(HEADER_SIZE) {
            data[position..position + MAGIC.len()].copy_from_slice(MAGIC);
            let length = (data.len() - position) as u64;
            data[position + 24..position + 32].copy_from_slice(&length.to_le_bytes());
        }
        assert!(matches!(
            scan_packets(&data),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    #[test]
    fn candidates_ruled_out_by_their_header_are_never_charged() {
        // Declared lengths past the end of the input, and below the header, are
        // both refused without hashing, so no budget is spent on them.
        let mut data = Vec::new();
        for step in 0..64u64 {
            let mut header = vec![0u8; HEADER_SIZE];
            header[..MAGIC.len()].copy_from_slice(MAGIC);
            let length = if step.is_multiple_of(2) { u64::MAX } else { 1 };
            header[24..32].copy_from_slice(&length.to_le_bytes());
            data.extend_from_slice(&header);
        }
        let limits = ScanLimits {
            max_failed_hash_passes: 0,
            ..ScanLimits::default()
        };
        assert!(
            scan_packets_with_limits(&data, &limits)
                .expect("scans")
                .is_empty()
        );
    }

    #[test]
    fn the_failed_candidate_budget_is_configurable() {
        let id = InputSetId([10; 8]);
        let mut bytes = comment(id, "damaged").to_bytes();
        bytes[HEADER_SIZE] ^= 0xff;
        bytes.extend_from_slice(&comment(id, "survivor").to_bytes());
        // One damaged packet is well inside the default budget.
        assert_eq!(scan_packets(&bytes).expect("scans").len(), 1);
        let limits = ScanLimits {
            max_failed_hash_passes: 0,
            ..ScanLimits::default()
        };
        assert!(matches!(
            scan_packets_with_limits(&bytes, &limits),
            Err(Par3Error::ScanLimitExceeded { .. })
        ));
    }

    #[test]
    fn an_oversized_packet_is_skipped_not_allocated() {
        let id = InputSetId([8; 8]);
        let mut bytes = comment(id, "small").to_bytes();
        bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(scan_packets(&bytes).expect("scans").is_empty());
    }

    #[test]
    fn garbage_never_panics() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for size in [0usize, 1, 7, 8, 47, 48, 49, 200, 4096] {
            for _ in 0..32 {
                let data: Vec<u8> = (0..size)
                    .map(|_| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        (state >> 33) as u8
                    })
                    .collect();
                let _ = scan_packets(&data);
            }
        }
    }

    #[test]
    fn magic_shaped_garbage_never_panics() {
        let mut data = Vec::new();
        for _ in 0..64 {
            data.extend_from_slice(MAGIC);
            data.extend_from_slice(&[0xff; 40]);
        }
        assert!(scan_packets(&data).expect("scans").is_empty());
    }

    #[test]
    fn find_magic_handles_partial_matches() {
        assert_eq!(find_magic(b"PAR3\0PK", 0), None);
        assert_eq!(find_magic(b"PPAR3\0PKT", 0), Some(1));
        assert_eq!(find_magic(b"PAR3\0PKT", 1), None);
        assert_eq!(find_magic(b"", 0), None);
        assert_eq!(find_magic(b"PAR3\0PKT", 99), None);
    }
}
