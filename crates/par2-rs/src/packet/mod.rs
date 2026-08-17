pub mod budget;
pub mod creator;
pub(crate) mod encode;
pub mod file_desc;
pub mod file_verify;
pub mod header;
pub mod main;
pub mod recovery;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use tracing::{debug, trace, warn};

use crate::checksum::Md5State;
use crate::error::{Par2Error, Result};
use crate::types::{CancellationToken, MAX_FILES_PER_SET, RecoverySetId};

pub use budget::{
    DEFAULT_MAX_EXAMINED_PACKETS, DEFAULT_MAX_RETAINED_METADATA_BYTES,
    DEFAULT_MAX_RETAINED_PACKETS, MAX_RECOVERY_EXPONENT, PacketScanBudget, PacketScanLimits,
    RECOVERY_EXPONENT_DOMAIN,
};

const MAX_MAIN_BODY_BYTES: usize = 12 + MAX_FILES_PER_SET * 16;
const MAX_FILE_DESC_BODY_BYTES: usize = 56 + 100_000;
const MAX_IFSC_BODY_BYTES: usize = 16 + 32_768 * 20;
const MAX_CREATOR_BODY_BYTES: usize = 100_000;

pub use creator::CreatorPacket;
pub use file_desc::FileDescriptionPacket;
pub use file_verify::IfscPacket;
pub use header::{HEADER_SIZE, MAGIC, PacketHeader, PacketType};
pub use main::MainPacket;
pub use recovery::{RecoverySliceData, RecoverySlicePacket};

/// A parsed PAR2 packet (any type).
#[derive(Debug, Clone)]
pub enum Packet {
    Main(MainPacket),
    FileDescription(FileDescriptionPacket),
    InputFileSliceChecksum(IfscPacket),
    RecoverySlice(RecoverySlicePacket),
    Creator(CreatorPacket),
    Unknown {
        packet_type: [u8; 16],
        body: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct ScannedPacket {
    pub packet: Packet,
    pub offset: u64,
    pub recovery_set_id: RecoverySetId,
}

/// Where a bounded scan delivers each accepted packet.
///
/// The scanners hand packets over one at a time instead of returning a vector,
/// so a caller that deduplicates — [`crate::par2_set::Par2FileSet`]'s builder,
/// or the repairer's inventory loader — can drop a packet the moment it decides
/// not to keep it. Nothing accumulates on the scanner's side, so the peak is
/// whatever the sink itself retains, and that is what the shared
/// [`PacketScanBudget`] meters.
///
/// Returning an error aborts the scan; the error reaches the caller unchanged.
pub trait PacketSink {
    fn accept(&mut self, packet: Packet, offset: u64, recovery_set_id: RecoverySetId)
    -> Result<()>;
}

impl<F> PacketSink for F
where
    F: FnMut(Packet, u64, RecoverySetId) -> Result<()>,
{
    fn accept(
        &mut self,
        packet: Packet,
        offset: u64,
        recovery_set_id: RecoverySetId,
    ) -> Result<()> {
        self(packet, offset, recovery_set_id)
    }
}

/// Sink that keeps every packet it is handed, charging each one to the budget.
///
/// This is the shape the vector-returning scanners are built from. It applies
/// no deduplication, so its retained-packet meter counts the raw stream.
struct CollectingSink<'a> {
    budget: &'a PacketScanBudget,
    packets: Vec<ScannedPacket>,
}

impl<'a> CollectingSink<'a> {
    fn new(budget: &'a PacketScanBudget) -> Self {
        Self {
            budget,
            packets: Vec::new(),
        }
    }
}

impl PacketSink for CollectingSink<'_> {
    fn accept(
        &mut self,
        packet: Packet,
        offset: u64,
        recovery_set_id: RecoverySetId,
    ) -> Result<()> {
        self.budget
            .charge_retained(budget::packet_retained_bytes(&packet))?;
        // `Vec` growth is amortised doubling, so charge the slot the packet is
        // about to occupy on top of the packet's own metadata.
        self.budget.charge_bytes(size_of::<ScannedPacket>())?;
        budget::reserve_fallible(&mut self.packets, 1)?;
        self.packets.push(ScannedPacket {
            packet,
            offset,
            recovery_set_id,
        });
        Ok(())
    }
}

/// Parse a single packet from a byte slice that starts at the packet header.
///
/// Returns the parsed packet and the number of bytes consumed.
/// `offset` is used for error reporting (position in the file/stream).
fn parse_packet_internal(
    data: &[u8],
    offset: u64,
    recovery_path: Option<&Arc<Path>>,
) -> Result<(Packet, usize)> {
    let header = PacketHeader::parse(data, offset)?;
    let total_len =
        usize::try_from(header.length).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: format!("packet length {} exceeds addressable memory", header.length),
        })?;

    if data.len() < total_len {
        return Err(Par2Error::PacketTooShort {
            expected: header.length,
            actual: data.len() as u64,
        });
    }

    // Validate packet hash
    header.validate_hash(&data[..total_len], offset)?;

    let body = &data[HEADER_SIZE..total_len];

    let packet = match header.packet_type {
        PacketType::Main => {
            debug!("parsed Main packet at offset {offset}");
            Packet::Main(MainPacket::parse(body, header.recovery_set_id)?)
        }
        PacketType::FileDescription => {
            debug!("parsed FileDescription packet at offset {offset}");
            Packet::FileDescription(FileDescriptionPacket::parse(body)?)
        }
        PacketType::InputFileSliceChecksum => {
            debug!("parsed IFSC packet at offset {offset}");
            Packet::InputFileSliceChecksum(IfscPacket::parse(body)?)
        }
        PacketType::RecoverySlice => {
            debug!("parsed RecoverySlice packet at offset {offset}");
            if let Some(path) = recovery_path {
                if body.len() <= 4 {
                    return Err(Par2Error::InvalidRecoveryPacket {
                        reason: format!("body too short: {} bytes, need more than 4", body.len()),
                    });
                }
                let exponent = u32::from_le_bytes(body[0..4].try_into().unwrap());
                Packet::RecoverySlice(RecoverySlicePacket {
                    exponent,
                    data: RecoverySliceData::file_backed_shared(
                        Arc::clone(path),
                        offset + HEADER_SIZE as u64 + 4,
                        body.len() - 4,
                        None,
                    ),
                })
            } else {
                Packet::RecoverySlice(RecoverySlicePacket::parse(body)?)
            }
        }
        PacketType::Creator => {
            debug!("parsed Creator packet at offset {offset}");
            Packet::Creator(CreatorPacket::parse(body)?)
        }
        PacketType::Unknown(sig) => {
            debug!("parsed Unknown packet type at offset {offset}");
            Packet::Unknown {
                packet_type: sig,
                body: body.to_vec(),
            }
        }
    };

    Ok((packet, total_len))
}

pub fn parse_packet(data: &[u8], offset: u64) -> Result<(Packet, usize)> {
    parse_packet_internal(data, offset, None)
}

fn parse_packet_body(header: &PacketHeader, body: Vec<u8>) -> Result<Packet> {
    Ok(match header.packet_type {
        PacketType::Main => Packet::Main(MainPacket::parse(&body, header.recovery_set_id)?),
        PacketType::FileDescription => {
            Packet::FileDescription(FileDescriptionPacket::parse(&body)?)
        }
        PacketType::InputFileSliceChecksum => {
            Packet::InputFileSliceChecksum(IfscPacket::parse(&body)?)
        }
        PacketType::RecoverySlice => Packet::RecoverySlice(RecoverySlicePacket::parse(&body)?),
        PacketType::Creator => Packet::Creator(CreatorPacket::parse(&body)?),
        PacketType::Unknown(sig) => Packet::Unknown {
            packet_type: sig,
            body,
        },
    })
}

/// Scan an in-memory byte stream for PAR2 packets under the default limits.
///
/// Scans through `data` looking for valid PAR2 packets. When a valid packet is
/// found it is parsed and collected; when invalid data is encountered the scan
/// steps forward byte by byte looking for the next magic sequence.
///
/// `base_offset` is the offset of `data[0]` in the original file (for error
/// reporting).
///
/// The result is complete or it is an error. A stream that would exceed
/// [`PacketScanLimits::default`] yields [`Par2Error::ResourceLimitExceeded`]
/// rather than a silently truncated vector — a caller cannot tell a truncated
/// inventory from a small one, and acting on a truncated inventory means
/// repairing from recovery data that was quietly dropped.
pub fn scan_packets(data: &[u8], base_offset: u64) -> Result<Vec<(Packet, u64)>> {
    scan_packets_with_limits(data, base_offset, PacketScanLimits::default())
}

/// [`scan_packets`] under caller-chosen limits.
pub fn scan_packets_with_limits(
    data: &[u8],
    base_offset: u64,
    limits: PacketScanLimits,
) -> Result<Vec<(Packet, u64)>> {
    let budget = PacketScanBudget::new(limits);
    let mut sink = CollectingSink::new(&budget);
    scan_packets_bounded(data, base_offset, &budget, &mut sink)?;
    Ok(sink
        .packets
        .into_iter()
        .map(|scanned| (scanned.packet, scanned.offset))
        .collect())
}

/// Stream the packets of an in-memory byte range into `sink` under `budget`.
///
/// Nothing accumulates here: each packet is parsed, charged to the budget's
/// examined meter, and handed straight to the sink.
pub fn scan_packets_bounded(
    data: &[u8],
    base_offset: u64,
    budget: &PacketScanBudget,
    sink: &mut dyn PacketSink,
) -> Result<()> {
    scan_packets_internal(data, base_offset, None, budget, sink)
}

fn scan_packets_internal(
    data: &[u8],
    base_offset: u64,
    recovery_path: Option<&Arc<Path>>,
    budget: &PacketScanBudget,
    sink: &mut dyn PacketSink,
) -> Result<()> {
    let mut pos = 0;

    while pos + HEADER_SIZE <= data.len() {
        budget.check_cancelled()?;
        // Try to parse a packet at the current position
        let offset = base_offset + pos as u64;

        match parse_packet_internal(&data[pos..], offset, recovery_path) {
            Ok((packet, consumed)) => {
                trace!("packet at offset {offset}, size {consumed}");
                budget.charge_examined()?;
                // Unknown packet bodies are never usable, and their length is
                // bounded only by the input, so drop them here exactly as the
                // streaming path does rather than handing a sink something it
                // would only throw away.
                match packet {
                    Packet::Unknown { packet_type, .. } => {
                        debug!(
                            "ignoring unknown packet type {packet_type:02x?} at offset {offset}"
                        );
                    }
                    packet => {
                        let recovery_set_id = header_recovery_set_id(&data[pos..]);
                        sink.accept(packet, offset, recovery_set_id)?;
                    }
                }
                pos += consumed;
            }
            Err(Par2Error::ResourceLimitExceeded { reason }) => {
                return Err(Par2Error::ResourceLimitExceeded { reason });
            }
            Err(Par2Error::Cancelled) => return Err(Par2Error::Cancelled),
            Err(_) => {
                // Scan forward to find the next magic sequence
                match find_next_magic(&data[pos + 1..]) {
                    Some(skip) => {
                        let skipped = skip + 1;
                        warn!("skipped {skipped} bytes at offset {offset} looking for next packet");
                        pos += skipped;
                    }
                    None => {
                        // No more magic sequences found
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// The recovery set ID of a packet whose header has already parsed cleanly.
fn header_recovery_set_id(packet: &[u8]) -> RecoverySetId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&packet[32..48]);
    RecoverySetId::from_bytes(bytes)
}

fn find_next_magic_in_reader(
    reader: &mut BufReader<File>,
    offset: &mut u64,
    budget: &PacketScanBudget,
) -> Result<Option<u64>> {
    let mut matched = 0usize;

    loop {
        budget.check_cancelled()?;
        let mut found = None;
        let mut consumed = 0usize;

        {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                return Ok(None);
            }

            while consumed < buf.len() {
                let byte = buf[consumed];
                if byte == MAGIC[matched] {
                    matched += 1;
                    if matched == MAGIC.len() {
                        found = Some(*offset + consumed as u64 + 1 - MAGIC.len() as u64);
                        consumed += 1;
                        break;
                    }
                } else {
                    matched = if byte == MAGIC[0] { 1 } else { 0 };
                }
                consumed += 1;
            }
        }

        reader.consume(consumed);
        *offset += consumed as u64;

        if let Some(found) = found {
            return Ok(Some(found));
        }
    }
}

fn validate_streamed_hash(
    header: &PacketHeader,
    header_bytes: &[u8; HEADER_SIZE],
    body: &[u8],
    offset: u64,
) -> Result<()> {
    let mut hasher = Md5State::new();
    hasher.update(&header_bytes[32..HEADER_SIZE]);
    hasher.update(body);
    let computed = hasher.finalize();
    if computed != header.packet_hash {
        return Err(Par2Error::PacketHashMismatch { offset });
    }
    Ok(())
}

fn validate_streamed_packet_from_reader(
    reader: &mut BufReader<File>,
    header: &PacketHeader,
    header_bytes: &[u8; HEADER_SIZE],
    body_len: usize,
    offset: u64,
    budget: &PacketScanBudget,
) -> Result<()> {
    let mut hasher = Md5State::new();
    hasher.update(&header_bytes[32..HEADER_SIZE]);

    let mut remaining = body_len;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        budget.check_cancelled()?;
        let take = remaining.min(buf.len());
        reader.read_exact(&mut buf[..take]).map_err(Par2Error::Io)?;
        hasher.update(&buf[..take]);
        remaining -= take;
    }

    let computed = hasher.finalize();
    if computed != header.packet_hash {
        return Err(Par2Error::PacketHashMismatch { offset });
    }
    Ok(())
}

fn read_exact_cancellable(
    reader: &mut BufReader<File>,
    destination: &mut [u8],
    budget: &PacketScanBudget,
) -> Result<()> {
    let mut offset = 0usize;
    while offset < destination.len() {
        budget.check_cancelled()?;
        let take = (destination.len() - offset).min(64 * 1024);
        reader
            .read_exact(&mut destination[offset..offset + take])
            .map_err(Par2Error::Io)?;
        offset += take;
    }
    Ok(())
}

fn max_buffered_non_recovery_body_len(packet_type: PacketType) -> Option<usize> {
    match packet_type {
        PacketType::Main => Some(MAX_MAIN_BODY_BYTES),
        PacketType::FileDescription => Some(MAX_FILE_DESC_BODY_BYTES),
        PacketType::InputFileSliceChecksum => Some(MAX_IFSC_BODY_BYTES),
        PacketType::Creator => Some(MAX_CREATOR_BODY_BYTES),
        PacketType::RecoverySlice | PacketType::Unknown(_) => None,
    }
}

fn parse_non_recovery_packet_from_reader(
    reader: &mut BufReader<File>,
    header: &PacketHeader,
    header_bytes: &[u8; HEADER_SIZE],
    offset: u64,
    budget: &PacketScanBudget,
) -> Result<Option<Packet>> {
    let body_len =
        usize::try_from(header.body_length()).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: format!(
                "packet body length {} exceeds addressable memory",
                header.body_length()
            ),
        })?;
    let Some(max_body_len) = max_buffered_non_recovery_body_len(header.packet_type) else {
        validate_streamed_packet_from_reader(
            reader,
            header,
            header_bytes,
            body_len,
            offset,
            budget,
        )?;
        return Ok(None);
    };
    if body_len > max_body_len {
        validate_streamed_packet_from_reader(
            reader,
            header,
            header_bytes,
            body_len,
            offset,
            budget,
        )?;
        return Ok(None);
    }

    let mut body = vec![0u8; body_len];
    read_exact_cancellable(reader, &mut body, budget)?;
    validate_streamed_hash(header, header_bytes, &body, offset)?;
    parse_packet_body(header, body).map(Some).or(Ok(None))
}

fn parse_recovery_packet_from_reader(
    reader: &mut BufReader<File>,
    header: &PacketHeader,
    offset: u64,
    path: &Arc<Path>,
    budget: &PacketScanBudget,
) -> Result<Packet> {
    let body_len =
        usize::try_from(header.body_length()).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: format!(
                "packet body length {} exceeds addressable memory",
                header.body_length()
            ),
        })?;
    if body_len <= 4 {
        return Err(Par2Error::InvalidRecoveryPacket {
            reason: format!("body too short: {body_len} bytes, need more than 4"),
        });
    }

    let mut exponent_bytes = [0u8; 4];
    read_exact_cancellable(reader, &mut exponent_bytes, budget)?;
    let exponent = u32::from_le_bytes(exponent_bytes);
    let payload_len = body_len - 4;
    let payload_offset = offset + HEADER_SIZE as u64 + 4;
    reader
        .seek(SeekFrom::Start(payload_offset + payload_len as u64))
        .map_err(Par2Error::Io)?;

    Ok(Packet::RecoverySlice(RecoverySlicePacket {
        exponent,
        // The streaming scanner seeks past recovery payloads without hashing
        // them, so keep the packet hash around for lazy validation at repair
        // time (damaged .vol files are routine on Usenet).
        data: RecoverySliceData::file_backed_shared(
            Arc::clone(path),
            payload_offset,
            payload_len,
            Some(header.packet_hash),
        ),
    }))
}

/// Collect every packet of an on-disk PAR2 file under the default limits.
///
/// Prefer [`scan_packets_from_path_bounded`] when the packets are going to be
/// deduplicated anyway: this variant retains the raw stream, duplicates
/// included, and so meters the physical packet count rather than the logical
/// inventory.
pub fn scan_packets_from_path_with_set_ids(path: &Path) -> Result<Vec<ScannedPacket>> {
    scan_packets_from_path_with_set_ids_limited(path, PacketScanLimits::default())
}

/// [`scan_packets_from_path_with_set_ids`] under caller-chosen limits.
pub fn scan_packets_from_path_with_set_ids_limited(
    path: &Path,
    limits: PacketScanLimits,
) -> Result<Vec<ScannedPacket>> {
    let budget = PacketScanBudget::new(limits);
    collect_packets_from_path(path, &budget)
}

pub(crate) fn scan_packets_from_path_with_set_ids_cancellable(
    path: &Path,
    limits: PacketScanLimits,
    cancellation: &CancellationToken,
) -> Result<Vec<ScannedPacket>> {
    let budget = PacketScanBudget::with_cancellation(limits, Some(cancellation.clone()));
    collect_packets_from_path(path, &budget)
}

fn collect_packets_from_path(path: &Path, budget: &PacketScanBudget) -> Result<Vec<ScannedPacket>> {
    let mut sink = CollectingSink::new(budget);
    scan_packets_from_path_bounded(path, budget, &mut sink)?;
    Ok(sink.packets)
}

/// Stream the packets of an on-disk PAR2 file into `sink` under `budget`.
///
/// The scanner holds one packet at a time. Recovery payloads are never read:
/// each recovery packet is recorded as a file-backed span into `path`, and all
/// of them share a single interned `Arc<Path>` so a file holding tens of
/// thousands of recovery packets costs one path allocation rather than one per
/// packet. Oversized known packets and unknown packets are hash-validated and
/// discarded without being buffered.
pub fn scan_packets_from_path_bounded(
    path: &Path,
    budget: &PacketScanBudget,
    sink: &mut dyn PacketSink,
) -> Result<()> {
    let file = File::open(path).map_err(Par2Error::Io)?;
    let file_len = file.metadata().map_err(Par2Error::Io)?.len();
    crate::file_cache::advise_sequential(&file, path, file_len);
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let shared_path: Arc<Path> = Arc::from(path);
    let mut interned_path_charged = false;
    let mut offset = 0u64;

    while let Some(packet_offset) = find_next_magic_in_reader(&mut reader, &mut offset, budget)? {
        budget.check_cancelled()?;
        let mut header_bytes = [0u8; HEADER_SIZE];
        header_bytes[..MAGIC.len()].copy_from_slice(MAGIC);

        match read_exact_cancellable(&mut reader, &mut header_bytes[MAGIC.len()..], budget) {
            Ok(()) => {}
            Err(Par2Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }

        let header = match PacketHeader::parse(&header_bytes, packet_offset) {
            Ok(header) => header,
            Err(_) => {
                reader
                    .seek(SeekFrom::Start(packet_offset + 1))
                    .map_err(Par2Error::Io)?;
                offset = packet_offset + 1;
                continue;
            }
        };
        if packet_offset
            .checked_add(header.length)
            .is_none_or(|packet_end| packet_end > file_len)
        {
            reader
                .seek(SeekFrom::Start(packet_offset + 1))
                .map_err(Par2Error::Io)?;
            offset = packet_offset + 1;
            continue;
        }

        if matches!(header.packet_type, PacketType::RecoverySlice) && !interned_path_charged {
            budget.charge_bytes(budget::interned_path_bytes(path))?;
            interned_path_charged = true;
        }

        let packet = match header.packet_type {
            PacketType::RecoverySlice => parse_recovery_packet_from_reader(
                &mut reader,
                &header,
                packet_offset,
                &shared_path,
                budget,
            )
            .map(Some),
            _ => parse_non_recovery_packet_from_reader(
                &mut reader,
                &header,
                &header_bytes,
                packet_offset,
                budget,
            ),
        };

        match packet {
            Ok(packet) => {
                // Charged even when the packet is discarded here: an unknown or
                // oversized packet still cost a full hash pass, and a stream of
                // nothing but those must stay bounded.
                budget.charge_examined()?;
                if let Some(packet) = packet {
                    sink.accept(packet, packet_offset, header.recovery_set_id)?;
                }
                offset = packet_offset + header.length;
            }
            Err(Par2Error::Cancelled) => return Err(Par2Error::Cancelled),
            Err(error @ Par2Error::ResourceLimitExceeded { .. }) => return Err(error),
            Err(_) => {
                reader
                    .seek(SeekFrom::Start(packet_offset + 1))
                    .map_err(Par2Error::Io)?;
                offset = packet_offset + 1;
            }
        }
    }

    crate::file_cache::drop_touched_file_cache(
        reader.get_ref(),
        path,
        file_len,
        0,
        offset.min(file_len),
    );
    Ok(())
}

pub fn scan_packets_from_path(path: &Path) -> Result<Vec<(Packet, u64)>> {
    scan_packets_from_path_with_set_ids(path).map(|packets| {
        packets
            .into_iter()
            .map(|packet| (packet.packet, packet.offset))
            .collect()
    })
}

/// Find the byte offset of the next PAR2 magic sequence in `data`.
fn find_next_magic(data: &[u8]) -> Option<usize> {
    if data.len() < MAGIC.len() {
        return None;
    }
    for i in 0..=data.len() - MAGIC.len() {
        if &data[i..i + MAGIC.len()] == MAGIC {
            return Some(i);
        }
    }
    None
}

/// Extract the recovery set ID from the first Main packet found in the data.
pub fn find_recovery_set_id(packets: &[(Packet, u64)]) -> Option<RecoverySetId> {
    for (packet, _) in packets {
        if let Packet::Main(main) = packet {
            return Some(main.recovery_set_id);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper to build a complete valid packet (header + body).
    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (HEADER_SIZE + body.len()) as u64;

        // Build bytes 32..length for hashing
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);

        let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    fn make_creator_packet(creator: &str, rsid: [u8; 16]) -> Vec<u8> {
        // Pad creator to multiple of 4 for body alignment
        let mut body = creator.as_bytes().to_vec();
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        make_full_packet(header::TYPE_CREATOR, &body, rsid)
    }

    fn make_main_packet_bytes(slice_size: u64, rsid: [u8; 16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&slice_size.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 recovery file IDs
        make_full_packet(header::TYPE_MAIN, &body, rsid)
    }

    #[test]
    fn parse_creator_packet() {
        let rsid = [0x42; 16];
        let data = make_creator_packet("TestCreator", rsid);
        let (packet, consumed) = parse_packet(&data, 0).unwrap();
        assert_eq!(consumed, data.len());
        match packet {
            Packet::Creator(c) => assert_eq!(c.creator_id, "TestCreator"),
            other => panic!("expected Creator, got {other:?}"),
        }
    }

    #[test]
    fn scan_multiple_packets() {
        let rsid = [0x11; 16];
        let mut stream = Vec::new();
        stream.extend_from_slice(&make_creator_packet("App1", rsid));
        stream.extend_from_slice(&make_main_packet_bytes(4096, rsid));
        stream.extend_from_slice(&make_creator_packet("App2", rsid));

        let packets = scan_packets(&stream, 0).unwrap();
        assert_eq!(packets.len(), 3);
        assert!(matches!(&packets[0].0, Packet::Creator(_)));
        assert!(matches!(&packets[1].0, Packet::Main(_)));
        assert!(matches!(&packets[2].0, Packet::Creator(_)));
    }

    #[test]
    fn scan_skips_garbage() {
        let rsid = [0x22; 16];
        let mut stream = Vec::new();
        // Some garbage bytes before the first packet
        stream.extend_from_slice(&[0xFF; 37]);
        stream.extend_from_slice(&make_creator_packet("Found", rsid));

        let packets = scan_packets(&stream, 0).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, 37); // offset should be 37
        match &packets[0].0 {
            Packet::Creator(c) => assert_eq!(c.creator_id, "Found"),
            other => panic!("expected Creator, got {other:?}"),
        }
    }

    #[test]
    fn scan_handles_garbage_between_packets() {
        let rsid = [0x33; 16];
        let mut stream = Vec::new();
        stream.extend_from_slice(&make_creator_packet("First", rsid));
        // Garbage between packets
        stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        stream.extend_from_slice(&make_creator_packet("Second", rsid));

        let packets = scan_packets(&stream, 100).unwrap();
        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn scan_empty_data() {
        let packets = scan_packets(&[], 0).unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn scan_short_data() {
        let packets = scan_packets(&[0u8; 10], 0).unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn find_next_magic_works() {
        let mut data = vec![0u8; 20];
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&[0u8; 10]);
        assert_eq!(find_next_magic(&data), Some(20));
    }

    #[test]
    fn find_next_magic_at_start() {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        assert_eq!(find_next_magic(&data), Some(0));
    }

    #[test]
    fn find_next_magic_not_found() {
        let data = [0u8; 100];
        assert_eq!(find_next_magic(&data), None);
    }

    #[test]
    fn parse_packet_hash_mismatch() {
        let rsid = [0; 16];
        let mut data = make_creator_packet("test", rsid);
        // Corrupt a body byte
        let last = data.len() - 1;
        data[last] ^= 0x01;
        let err = parse_packet(&data, 5).unwrap_err();
        assert!(matches!(err, Par2Error::PacketHashMismatch { offset: 5 }));
    }

    #[test]
    fn parse_unknown_packet_type() {
        let custom_type = b"PAR 2.0\x00TestType";
        let body = [0u8; 16]; // 16 bytes body
        let rsid = [0; 16];
        let data = make_full_packet(custom_type, &body, rsid);

        let (packet, _) = parse_packet(&data, 0).unwrap();
        match packet {
            Packet::Unknown {
                packet_type,
                body: b,
            } => {
                assert_eq!(packet_type, *custom_type);
                assert_eq!(b.len(), 16);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn path_scanner_streams_and_ignores_large_unknown_packets() {
        let custom_type = b"PAR 2.0\x00TestType";
        let rsid = [0x55; 16];
        let unknown_body = vec![0xA5; 1024 * 1024 + 4];
        let mut stream = make_full_packet(custom_type, &unknown_body, rsid);
        stream.extend_from_slice(&make_main_packet_bytes(4096, rsid));

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let packets = scan_packets_from_path(file.path()).unwrap();
        assert_eq!(packets.len(), 1);
        assert!(matches!(&packets[0].0, Packet::Main(_)));
    }

    #[test]
    fn path_scanner_walks_large_valid_packet_inventory() {
        let rsid = [0x5A; 16];
        let creator = make_creator_packet("stress", rsid);
        let mut stream = Vec::with_capacity(creator.len() * 70_000 + HEADER_SIZE + 12);
        for _ in 0..70_000 {
            stream.extend_from_slice(&creator);
        }
        stream.extend_from_slice(&make_main_packet_bytes(4096, rsid));

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let packets = scan_packets_from_path(file.path()).unwrap();
        assert_eq!(packets.len(), 70_001);
        assert!(matches!(&packets[70_000].0, Packet::Main(_)));
    }

    #[test]
    fn path_scanner_skips_valid_hash_oversized_known_packets_by_boundary() {
        let rsid = [0x66; 16];
        let embedded_rsid = [0x99; 16];
        let embedded_main = make_main_packet_bytes(8192, embedded_rsid);
        let mut oversized_creator_body = vec![0u8; MAX_CREATOR_BODY_BYTES + 4];
        oversized_creator_body[..embedded_main.len()].copy_from_slice(&embedded_main);

        let mut stream = make_full_packet(header::TYPE_CREATOR, &oversized_creator_body, rsid);
        stream.extend_from_slice(&make_main_packet_bytes(4096, rsid));

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let packets = scan_packets_from_path(file.path()).unwrap();
        assert_eq!(packets.len(), 1);
        match &packets[0].0 {
            Packet::Main(main) => assert_eq!(*main.recovery_set_id.as_bytes(), rsid),
            other => panic!("expected Main, got {other:?}"),
        }
    }

    #[test]
    fn find_recovery_set_id_works() {
        let rsid = [0x77; 16];
        let stream = make_main_packet_bytes(1024, rsid);
        let packets = scan_packets(&stream, 0).unwrap();
        let found = find_recovery_set_id(&packets).unwrap();
        assert_eq!(*found.as_bytes(), rsid);
    }

    #[test]
    fn find_recovery_set_id_none() {
        let rsid = [0; 16];
        let stream = make_creator_packet("test", rsid);
        let packets = scan_packets(&stream, 0).unwrap();
        assert!(find_recovery_set_id(&packets).is_none());
    }

    fn make_recovery_packet(exponent: u32, payload: &[u8], rsid: [u8; 16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&exponent.to_le_bytes());
        body.extend_from_slice(payload);
        make_full_packet(header::TYPE_RECOVERY, &body, rsid)
    }

    /// `count` distinct creator packets, so nothing collapses under dedup.
    fn creator_run(count: usize, rsid: [u8; 16]) -> Vec<u8> {
        let mut stream = Vec::new();
        for i in 0..count {
            stream.extend_from_slice(&make_creator_packet(&format!("app-{i}"), rsid));
        }
        stream
    }

    #[test]
    fn in_memory_scan_refuses_one_packet_past_the_configured_limit() {
        let rsid = [0x81; 16];
        let limits = PacketScanLimits::default()
            .with_max_retained_packets(8)
            .with_max_examined_packets(8);

        let at_limit = creator_run(8, rsid);
        assert_eq!(
            scan_packets_with_limits(&at_limit, 0, limits)
                .unwrap()
                .len(),
            8
        );

        let over_limit = creator_run(9, rsid);
        let error = scan_packets_with_limits(&over_limit, 0, limits).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn disk_scan_refuses_one_packet_past_the_configured_limit() {
        let rsid = [0x82; 16];
        let limits = PacketScanLimits::default()
            .with_max_retained_packets(8)
            .with_max_examined_packets(8);

        let mut at_limit = NamedTempFile::new().unwrap();
        at_limit.write_all(&creator_run(8, rsid)).unwrap();
        assert_eq!(
            scan_packets_from_path_with_set_ids_limited(at_limit.path(), limits)
                .unwrap()
                .len(),
            8
        );

        let mut over_limit = NamedTempFile::new().unwrap();
        over_limit.write_all(&creator_run(9, rsid)).unwrap();
        let error =
            scan_packets_from_path_with_set_ids_limited(over_limit.path(), limits).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    /// Exhaustion must be distinguishable from "this file held nothing". A
    /// caller that saw an empty vector would carry on with a set that quietly
    /// lost recovery data.
    #[test]
    fn limit_exhaustion_never_looks_like_an_empty_scan() {
        let rsid = [0x83; 16];
        let limits = PacketScanLimits::default().with_max_retained_packets(1);
        let stream = creator_run(4, rsid);

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        assert!(matches!(
            scan_packets_with_limits(&stream, 0, limits),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
        assert!(matches!(
            scan_packets_from_path_with_set_ids_limited(file.path(), limits),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn the_byte_meter_alone_can_refuse_a_scan() {
        let rsid = [0x84; 16];
        let stream = creator_run(64, rsid);
        let limits = PacketScanLimits::default().with_max_retained_metadata_bytes(256);
        let error = scan_packets_with_limits(&stream, 0, limits).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn duplicate_packets_spend_work_budget_but_not_retention_budget() {
        // The collecting scanners keep every packet, so the raw stream is what
        // they meter; the deduplicating sinks are covered where they live.
        let rsid = [0x85; 16];
        let identical = make_creator_packet("same", rsid);
        let mut stream = Vec::new();
        for _ in 0..16 {
            stream.extend_from_slice(&identical);
        }

        let budget = PacketScanBudget::new(PacketScanLimits::default());
        let mut kept = 0usize;
        let mut sink = |_packet: Packet, _offset: u64, _set: RecoverySetId| -> Result<()> {
            // A deduplicating sink retains only the first of the run.
            if kept == 0 {
                kept += 1;
                budget.charge_retained(64)?;
            }
            Ok(())
        };
        scan_packets_bounded(&stream, 0, &budget, &mut sink).unwrap();

        assert_eq!(budget.examined(), 16, "every duplicate is work");
        assert_eq!(budget.retained_packets(), 1, "only one is retention");
    }

    #[test]
    fn scanning_stops_on_cancellation_rather_than_running_to_the_end() {
        let rsid = [0x86; 16];
        let stream = creator_run(64, rsid);
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let cancel = CancellationToken::new();
        cancel.cancel();
        let budget =
            PacketScanBudget::with_cancellation(PacketScanLimits::default(), Some(cancel.clone()));
        let mut sink = CollectingSink::new(&budget);
        assert!(matches!(
            scan_packets_from_path_bounded(file.path(), &budget, &mut sink),
            Err(Par2Error::Cancelled)
        ));

        let budget = PacketScanBudget::with_cancellation(PacketScanLimits::default(), Some(cancel));
        let mut sink = CollectingSink::new(&budget);
        assert!(matches!(
            scan_packets_bounded(&stream, 0, &budget, &mut sink),
            Err(Par2Error::Cancelled)
        ));
    }

    /// Cancellation asserted partway through: the scan must stop, and it must
    /// not hand back the packets it had already collected.
    #[test]
    fn cancellation_mid_scan_aborts_instead_of_truncating() {
        let rsid = [0x87; 16];
        let stream = creator_run(64, rsid);
        let cancel = CancellationToken::new();
        let budget =
            PacketScanBudget::with_cancellation(PacketScanLimits::default(), Some(cancel.clone()));

        let mut seen = 0usize;
        let mut sink = |_packet: Packet, _offset: u64, _set: RecoverySetId| -> Result<()> {
            seen += 1;
            if seen == 4 {
                cancel.cancel();
            }
            Ok(())
        };
        let error = scan_packets_bounded(&stream, 0, &budget, &mut sink).unwrap_err();
        assert!(matches!(error, Par2Error::Cancelled));
        assert!(seen < 64, "the scan stopped early, seen={seen}");
    }

    #[test]
    fn in_memory_scan_drops_unknown_packet_bodies() {
        let custom_type = b"PAR 2.0\x00TestType";
        let rsid = [0x88; 16];
        let mut stream = make_full_packet(custom_type, &vec![0xA5; 4096], rsid);
        stream.extend_from_slice(&make_main_packet_bytes(4096, rsid));

        let packets = scan_packets(&stream, 0).unwrap();
        assert_eq!(packets.len(), 1, "the unknown packet is not delivered");
        assert!(matches!(&packets[0].0, Packet::Main(_)));
    }

    /// Unknown packets still cost the examined meter: a stream of nothing but
    /// unknown packets must not be able to run unbounded just because none of
    /// them is retained.
    #[test]
    fn unknown_packets_still_spend_the_examined_meter() {
        let custom_type = b"PAR 2.0\x00TestType";
        let rsid = [0x89; 16];
        let mut stream = Vec::new();
        for i in 0..12u8 {
            stream.extend_from_slice(&make_full_packet(custom_type, &[i; 16], rsid));
        }
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let limits = PacketScanLimits::default().with_max_examined_packets(8);
        assert!(matches!(
            scan_packets_with_limits(&stream, 0, limits),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
        assert!(matches!(
            scan_packets_from_path_with_set_ids_limited(file.path(), limits),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn every_recovery_packet_in_a_volume_shares_one_interned_path() {
        let rsid = [0x8A; 16];
        let mut stream = make_main_packet_bytes(4, rsid);
        for exponent in 0..64u32 {
            stream.extend_from_slice(&make_recovery_packet(exponent, &[0xAB; 4], rsid));
        }
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let packets = scan_packets_from_path_with_set_ids(file.path()).unwrap();
        let paths: Vec<Arc<Path>> = packets
            .iter()
            .filter_map(|scanned| match &scanned.packet {
                Packet::RecoverySlice(slice) => match &slice.data {
                    RecoverySliceData::FileBacked { path, .. } => Some(Arc::clone(path)),
                    RecoverySliceData::InMemory(_) => None,
                },
                _ => None,
            })
            .collect();

        assert_eq!(paths.len(), 64);
        for path in &paths[1..] {
            assert!(
                Arc::ptr_eq(&paths[0], path),
                "recovery packets must share one allocation for the volume path"
            );
        }
    }

    /// The streaming scanner never hashes recovery payloads, so it records the
    /// packet hash for later. That deferred validation has to still work
    /// against the interned path.
    #[test]
    fn file_backed_recovery_payloads_still_validate_their_packet_hash() {
        let rsid = [0x8B; 16];
        let mut stream = make_main_packet_bytes(8, rsid);
        stream.extend_from_slice(&make_recovery_packet(7, &[0xC3; 8], rsid));
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&stream).unwrap();

        let packets = scan_packets_from_path(file.path()).unwrap();
        let Packet::RecoverySlice(slice) = &packets[1].0 else {
            panic!("expected a recovery packet, got {:?}", packets[1].0);
        };
        assert!(slice.data.as_bytes().is_none(), "payload stays file-backed");
        assert_eq!(slice.data.to_vec().unwrap(), vec![0xC3; 8]);
        assert!(slice.data.validate_packet_hash(&rsid, 7).unwrap());

        // Corrupt the payload on disk and the same check must now fail.
        let mut corrupted = stream.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        std::fs::write(file.path(), &corrupted).unwrap();
        assert!(!slice.data.validate_packet_hash(&rsid, 7).unwrap());
    }
}
