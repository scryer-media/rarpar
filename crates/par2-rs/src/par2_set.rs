use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use tracing::{debug, warn};

use crate::checksum;
use crate::error::{Par2Error, Result};
use crate::packet::budget::packet_retained_bytes;
use crate::packet::{
    MAX_RECOVERY_EXPONENT, Packet, PacketScanBudget, PacketScanLimits, PacketSink,
    RecoverySliceData, scan_packets_bounded, scan_packets_from_path_bounded,
};
use crate::types::{FileId, MAX_FILES_PER_SET, RecoveryExponent, RecoverySetId, SliceChecksum};

/// Description of a single file in the PAR2 set.
#[derive(Debug, Clone)]
pub struct FileDescription {
    pub file_id: FileId,
    pub hash_full: [u8; 16],
    pub hash_16k: [u8; 16],
    pub length: u64,
    pub par2_name: String,
    pub filename: String,
}

/// A recovery slice: exponent + data.
#[derive(Debug, Clone)]
pub struct RecoverySlice {
    pub exponent: RecoveryExponent,
    pub data: RecoverySliceData,
}

/// Aggregated state from one or more .par2 files.
///
/// Collects Main, FileDescription, IFSC, RecoverySlice, and Creator packets
/// into a unified view of the PAR2 recovery set.
#[derive(Debug, Clone)]
pub struct Par2FileSet {
    /// The recovery set ID (MD5 of the main packet body).
    pub recovery_set_id: RecoverySetId,
    /// Block/slice size in bytes.
    pub slice_size: u64,
    /// File IDs that are in the recovery set (order matters for RS coding).
    pub recovery_file_ids: Vec<FileId>,
    /// File IDs that are NOT in the recovery set.
    pub non_recovery_file_ids: Vec<FileId>,
    /// File descriptions keyed by file ID.
    pub files: HashMap<FileId, FileDescription>,
    /// Slice checksums (IFSC data) keyed by file ID.
    pub slice_checksums: HashMap<FileId, Vec<SliceChecksum>>,
    /// Recovery slices keyed by exponent.
    pub recovery_slices: BTreeMap<RecoveryExponent, RecoverySlice>,
    /// Creator application identifier, if found.
    pub creator: Option<String>,
}

impl Par2FileSet {
    /// Create a new Par2FileSet by parsing packets from one or more .par2 file contents.
    ///
    /// Each element of `par2_files` is the raw bytes of a .par2 file. Packets
    /// stream straight into the builder, which deduplicates as it goes, so the
    /// peak is the deduplicated inventory rather than the packet stream. One
    /// [`PacketScanBudget`] spans every input, under the default limits.
    pub fn from_files(par2_files: &[&[u8]]) -> Result<Self> {
        Self::from_files_with_limits(par2_files, PacketScanLimits::default())
    }

    /// [`Self::from_files`] under caller-chosen limits.
    pub fn from_files_with_limits(par2_files: &[&[u8]], limits: PacketScanLimits) -> Result<Self> {
        let budget = PacketScanBudget::new(limits);
        let mut sink = BuilderSink::new(&budget);

        for (i, data) in par2_files.iter().enumerate() {
            debug!("scanning par2 file {} ({} bytes)", i, data.len());
            scan_packets_bounded(data, 0, &budget, &mut sink)?;
        }

        sink.into_builder().build()
    }

    /// Create a new Par2FileSet by parsing packets directly from one or more
    /// on-disk .par2 files. Recovery slice payloads are kept file-backed.
    pub fn from_paths<P: AsRef<Path>>(par2_files: &[P]) -> Result<Self> {
        Self::from_paths_with_limits(par2_files, PacketScanLimits::default())
    }

    /// [`Self::from_paths`] under caller-chosen limits.
    pub fn from_paths_with_limits<P: AsRef<Path>>(
        par2_files: &[P],
        limits: PacketScanLimits,
    ) -> Result<Self> {
        let budget = PacketScanBudget::new(limits);
        let mut sink = BuilderSink::new(&budget);

        for (i, path) in par2_files.iter().enumerate() {
            debug!("scanning par2 file {} ({})", i, path.as_ref().display());
            scan_packets_from_path_bounded(path.as_ref(), &budget, &mut sink)?;
        }

        sink.into_builder().build()
    }

    /// Create a Par2FileSet with diagnostic information about parse errors.
    ///
    /// Unlike [`Self::from_files`], this does not fail on individual file parse errors.
    /// Instead, errors are collected into [`Par2Diagnostic`]. Returns an error
    /// only if no valid main packet was found across all files — or if the
    /// shared budget is exhausted, which is never downgraded to a diagnostic
    /// because a partial inventory is indistinguishable from a small one.
    pub fn from_files_with_diagnostics(par2_files: &[&[u8]]) -> Result<Par2ParseResult> {
        let budget = PacketScanBudget::new(PacketScanLimits::default());
        let mut builder = Par2FileSetBuilder::new();
        let mut diagnostic = Par2Diagnostic::default();

        for (i, data) in par2_files.iter().enumerate() {
            debug!("scanning par2 file {} ({} bytes)", i, data.len());
            let mut accepted = 0usize;
            let mut sink = |packet: Packet, offset: u64, _set_id: RecoverySetId| -> Result<()> {
                accepted += 1;
                match builder.add_packet_budgeted(packet, offset, &budget) {
                    Ok(_) => {}
                    // A budget refusal is the caller's problem, not a per-file
                    // diagnostic: it means the inventory would be incomplete.
                    Err(
                        error @ (Par2Error::ResourceLimitExceeded { .. } | Par2Error::Cancelled),
                    ) => {
                        return Err(error);
                    }
                    Err(error) => {
                        diagnostic
                            .damaged_files
                            .push((i, format!("packet error at offset {offset}: {error}")));
                        diagnostic.skipped_packets += 1;
                    }
                }
                Ok(())
            };
            scan_packets_bounded(data, 0, &budget, &mut sink)?;

            if accepted == 0 && !data.is_empty() {
                diagnostic
                    .damaged_files
                    .push((i, "no valid packets found".to_string()));
                diagnostic.skipped_packets += 1;
            }
        }

        let file_set = builder.build()?;
        Ok(Par2ParseResult {
            file_set,
            diagnostic,
        })
    }

    /// Create from an already-parsed list of packets.
    ///
    /// The caller already holds the packets, so this charges only the builder's
    /// own retention against a default budget.
    pub fn from_packets(packets: Vec<Packet>) -> Result<Self> {
        let budget = PacketScanBudget::new(PacketScanLimits::default());
        let mut builder = Par2FileSetBuilder::new();
        for packet in packets {
            builder.add_packet_budgeted(packet, 0, &budget)?;
        }
        builder.build()
    }

    /// Get the file description for a given file ID.
    pub fn file_description(&self, file_id: &FileId) -> Option<&FileDescription> {
        self.files.get(file_id)
    }

    /// Get the slice checksums for a given file ID.
    pub fn file_checksums(&self, file_id: &FileId) -> Option<&[SliceChecksum]> {
        self.slice_checksums.get(file_id).map(|v| v.as_slice())
    }

    /// Return the CRC32 expected for the unpadded bytes of a file.
    ///
    /// PAR2 IFSC records store the CRC32 for each full input slice. A short
    /// final slice is zero-padded before its IFSC checksum is calculated, so
    /// its padding must be removed in GF(2) before the per-slice CRCs can be
    /// combined into the file's actual CRC32. Missing or internally
    /// inconsistent metadata produces no value.
    pub fn expected_file_crc32(&self, file_id: FileId) -> Option<u32> {
        let description = self.files.get(&file_id)?;
        if self.slice_size == 0 {
            return None;
        }

        // Empty files have a well-defined CRC32 without IFSC data. PAR2
        // producers commonly omit the corresponding zero-entry IFSC packet;
        // accept that absence, but reject a contradictory non-empty packet.
        if description.length == 0 {
            return match self.slice_checksums.get(&file_id) {
                Some(checksums) if !checksums.is_empty() => None,
                _ => Some(checksum::crc32(&[])),
            };
        }

        let expected_slice_count = description.length.div_ceil(self.slice_size);
        if expected_slice_count > u32::MAX as u64 {
            return None;
        }
        let expected_slice_count = usize::try_from(expected_slice_count).ok()?;
        let checksums = self.slice_checksums.get(&file_id)?;
        if checksums.len() != expected_slice_count {
            return None;
        }

        let mut file_crc = None;
        for (index, checksum) in checksums.iter().enumerate() {
            let is_last = index + 1 == checksums.len();
            let short_final_slice = is_last && description.length % self.slice_size != 0;
            let slice_len = if short_final_slice {
                description.length % self.slice_size
            } else {
                self.slice_size
            };
            let slice_crc = if short_final_slice {
                let padding_len = self.slice_size.checked_sub(slice_len)?;
                let padding_crc = checksum::crc32_padded(&[], padding_len);
                checksum::crc32_uncombine(checksum.crc32, padding_crc, padding_len)
            } else {
                checksum.crc32
            };

            file_crc = Some(match file_crc {
                Some(prefix_crc) => checksum::crc32_combine(prefix_crc, slice_crc, slice_len),
                None => slice_crc,
            });
        }

        file_crc
    }

    /// Return all file descriptions in the recovery set, in order.
    pub fn recovery_files(&self) -> Vec<&FileDescription> {
        self.recovery_file_ids
            .iter()
            .filter_map(|id| self.files.get(id))
            .collect()
    }

    /// Number of recovery blocks available.
    pub fn recovery_block_count(&self) -> u32 {
        self.recovery_slices.len() as u32
    }

    /// Merge additional packets into this file set.
    ///
    /// Used to add recovery slices from newly-downloaded PAR2 volumes.
    /// Ignores duplicate packets. Returns error if a conflicting recovery
    /// set ID is encountered.
    pub fn merge_packets(&mut self, packets: Vec<Packet>) -> Result<MergeResult> {
        if packets.iter().any(|packet| {
            matches!(
                packet,
                Packet::Main(main) if main.recovery_set_id != self.recovery_set_id
            )
        }) {
            return Err(Par2Error::ConflictingRecoverySet);
        }

        let mut new_recovery_slices = 0u32;
        let mut duplicates_ignored = 0u32;

        for packet in packets {
            match packet {
                Packet::Main(main) => {
                    if main.recovery_set_id != self.recovery_set_id {
                        return Err(Par2Error::ConflictingRecoverySet);
                    }
                    duplicates_ignored += 1;
                }
                Packet::FileDescription(fd) => {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        self.files.entry(fd.file_id)
                    {
                        e.insert(FileDescription {
                            file_id: fd.file_id,
                            hash_full: fd.hash_full,
                            hash_16k: fd.hash_16k,
                            length: fd.file_length,
                            par2_name: fd.par2_name,
                            filename: fd.filename,
                        });
                    } else {
                        duplicates_ignored += 1;
                    }
                }
                Packet::InputFileSliceChecksum(ifsc) => {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        self.slice_checksums.entry(ifsc.file_id)
                    {
                        e.insert(ifsc.checksums);
                    } else {
                        duplicates_ignored += 1;
                    }
                }
                Packet::RecoverySlice(rs) => {
                    if let std::collections::btree_map::Entry::Vacant(e) =
                        self.recovery_slices.entry(rs.exponent)
                    {
                        e.insert(RecoverySlice {
                            exponent: rs.exponent,
                            data: rs.data,
                        });
                        new_recovery_slices += 1;
                    } else {
                        duplicates_ignored += 1;
                    }
                }
                Packet::Creator(c) => {
                    if self.creator.is_none() {
                        self.creator = Some(c.creator_id);
                    } else {
                        duplicates_ignored += 1;
                    }
                }
                Packet::Unknown { .. } => {}
            }
        }

        Ok(MergeResult {
            new_recovery_slices,
            duplicates_ignored,
        })
    }

    /// Compute the number of slices for a file given its length and the slice size.
    ///
    /// Uses checked arithmetic to avoid overflow on malicious inputs.
    /// Returns 0 for zero-length files and caps at `u32::MAX` (the PAR2 spec
    /// uses 32-bit slice indices, so files larger than `slice_size * u32::MAX`
    /// are already outside spec).
    pub fn slice_count_for_file(&self, file_length: u64) -> u32 {
        if file_length == 0 || self.slice_size == 0 {
            return 0;
        }
        let count = file_length.div_ceil(self.slice_size);
        // Saturate to u32::MAX rather than silently truncating.
        u32::try_from(count).unwrap_or(u32::MAX)
    }
}

/// Result of merging packets into an existing [`Par2FileSet`].
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// Number of new recovery slices added.
    pub new_recovery_slices: u32,
    /// Number of duplicate packets ignored.
    pub duplicates_ignored: u32,
}

/// Diagnostic information about PAR2 file parsing issues.
#[derive(Debug, Clone, Default)]
pub struct Par2Diagnostic {
    /// Files that had errors during parsing. (file_index, error description).
    pub damaged_files: Vec<(usize, String)>,
    /// Total number of packets that were skipped due to corruption.
    pub skipped_packets: u32,
}

/// Result of [`Par2FileSet::from_files_with_diagnostics`].
#[derive(Debug)]
pub struct Par2ParseResult {
    pub file_set: Par2FileSet,
    pub diagnostic: Par2Diagnostic,
}

/// Sink that feeds a [`Par2FileSetBuilder`] directly from a scan.
///
/// This is the streaming replacement for scan-into-`Vec` then drain-into-
/// builder: a duplicate or rejected packet is dropped where it is parsed, and
/// its budget charge is handed straight back, so redundant critical packets
/// spread across many volumes never accumulate.
struct BuilderSink<'a> {
    budget: &'a PacketScanBudget,
    builder: Par2FileSetBuilder,
}

impl<'a> BuilderSink<'a> {
    fn new(budget: &'a PacketScanBudget) -> Self {
        Self {
            budget,
            builder: Par2FileSetBuilder::new(),
        }
    }

    fn into_builder(self) -> Par2FileSetBuilder {
        self.builder
    }
}

impl PacketSink for BuilderSink<'_> {
    fn accept(
        &mut self,
        packet: Packet,
        offset: u64,
        _recovery_set_id: RecoverySetId,
    ) -> Result<()> {
        self.builder
            .add_packet_budgeted(packet, offset, self.budget)?;
        Ok(())
    }
}

/// What [`Par2FileSetBuilder::add_packet`] did with a packet.
///
/// The caller needs this to keep its budget honest — a duplicate holds nothing,
/// so its charge must be released — and to count diagnostics without keeping a
/// second set of dedup maps beside the builder's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketAdmission {
    /// The packet's contents are now held by the builder.
    Retained,
    /// A packet of this kind and key was already held; nothing was kept.
    Duplicate,
    /// The packet cannot contribute to a repair and nothing was kept: an
    /// unknown packet type, a recovery exponent outside the usable GF domain,
    /// or a packet that would push a logical bound past its limit.
    Rejected,
}

/// Builder that aggregates packets into a Par2FileSet.
///
/// Packets arrive one at a time and are deduplicated on arrival, so the builder
/// holds the logical inventory and never a copy of the packet stream.
pub(crate) struct Par2FileSetBuilder {
    main_packet: Option<crate::packet::MainPacket>,
    files: HashMap<FileId, FileDescription>,
    slice_checksums: HashMap<FileId, Vec<SliceChecksum>>,
    recovery_slices: BTreeMap<RecoveryExponent, RecoverySlice>,
    creator: Option<String>,
}

impl Par2FileSetBuilder {
    pub(crate) fn new() -> Self {
        Self {
            main_packet: None,
            files: HashMap::new(),
            slice_checksums: HashMap::new(),
            recovery_slices: BTreeMap::new(),
            creator: None,
        }
    }

    /// Whether a packet with this key is already held.
    ///
    /// Lets a caller that must defer a packet decide, before retaining it, that
    /// it is bound to be a duplicate: the builder's keys only ever accumulate.
    pub(crate) fn would_duplicate(&self, packet: &Packet) -> bool {
        match packet {
            Packet::Main(_) => self.main_packet.is_some(),
            Packet::FileDescription(desc) => self.files.contains_key(&desc.file_id),
            Packet::InputFileSliceChecksum(ifsc) => {
                self.slice_checksums.contains_key(&ifsc.file_id)
            }
            Packet::RecoverySlice(slice) => self.recovery_slices.contains_key(&slice.exponent),
            Packet::Creator(_) => self.creator.is_some(),
            Packet::Unknown { .. } => false,
        }
    }

    /// Whether [`Self::add_packet`] would keep this packet's contents.
    ///
    /// Mirrors `add_packet`'s decision exactly so a caller can charge its budget
    /// *before* handing the packet over. Charging first and refunding on a
    /// duplicate would make a duplicate briefly occupy a retained slot, and an
    /// inventory sitting exactly on its limit would then be refused by its own
    /// redundancy.
    pub(crate) fn would_retain(&self, packet: &Packet) -> bool {
        match packet {
            Packet::Main(_) => self.main_packet.is_none(),
            Packet::FileDescription(desc) => {
                !self.files.contains_key(&desc.file_id) && self.files.len() < MAX_FILES_PER_SET
            }
            Packet::InputFileSliceChecksum(ifsc) => {
                !self.slice_checksums.contains_key(&ifsc.file_id)
                    && self.slice_checksums.len() < MAX_FILES_PER_SET
            }
            Packet::RecoverySlice(slice) => {
                slice.exponent <= MAX_RECOVERY_EXPONENT
                    && !self.recovery_slices.contains_key(&slice.exponent)
            }
            Packet::Creator(_) => self.creator.is_none(),
            Packet::Unknown { .. } => false,
        }
    }

    /// [`Self::add_packet`], charging `budget` for exactly what is kept.
    ///
    /// A duplicate, an unknown packet, or a packet past a logical bound costs
    /// the budget nothing: it is never charged in the first place.
    pub(crate) fn add_packet_budgeted(
        &mut self,
        packet: Packet,
        offset: u64,
        budget: &PacketScanBudget,
    ) -> Result<PacketAdmission> {
        if !self.would_retain(&packet) {
            // Still goes through `add_packet`, which is where a Main packet from
            // a foreign recovery set is detected.
            return self.add_packet(packet, offset);
        }
        let bytes = packet_retained_bytes(&packet);
        budget.charge_retained(bytes)?;
        let admission = self.add_packet(packet, offset)?;
        if admission != PacketAdmission::Retained {
            budget.release_retained(bytes);
        }
        Ok(admission)
    }

    pub(crate) fn add_packet(&mut self, packet: Packet, _offset: u64) -> Result<PacketAdmission> {
        Ok(match packet {
            Packet::Main(main) => {
                if let Some(existing) = &self.main_packet {
                    if existing.recovery_set_id != main.recovery_set_id {
                        return Err(Par2Error::ConflictingRecoverySet);
                    }
                    // Duplicate main packet with same RSID: ignore
                    debug!("duplicate main packet (same recovery set ID), ignoring");
                    PacketAdmission::Duplicate
                } else {
                    self.main_packet = Some(main);
                    PacketAdmission::Retained
                }
            }
            Packet::FileDescription(fd) => {
                let file_id = fd.file_id;
                if self.files.contains_key(&file_id) {
                    PacketAdmission::Duplicate
                } else if self.files.len() >= MAX_FILES_PER_SET {
                    // Bound the map before it grows: a Main packet cannot name
                    // more than MAX_FILES_PER_SET files, so descriptions past
                    // that describe files no repair can address.
                    warn!(
                        "discarding file description beyond the {MAX_FILES_PER_SET}-file set limit"
                    );
                    PacketAdmission::Rejected
                } else {
                    self.files.insert(
                        file_id,
                        FileDescription {
                            file_id: fd.file_id,
                            hash_full: fd.hash_full,
                            hash_16k: fd.hash_16k,
                            length: fd.file_length,
                            par2_name: fd.par2_name,
                            filename: fd.filename,
                        },
                    );
                    PacketAdmission::Retained
                }
            }
            Packet::InputFileSliceChecksum(ifsc) => {
                // Use the first IFSC packet for each file ID
                if self.slice_checksums.contains_key(&ifsc.file_id) {
                    PacketAdmission::Duplicate
                } else if self.slice_checksums.len() >= MAX_FILES_PER_SET {
                    warn!("discarding IFSC packet beyond the {MAX_FILES_PER_SET}-file set limit");
                    PacketAdmission::Rejected
                } else {
                    self.slice_checksums.insert(ifsc.file_id, ifsc.checksums);
                    PacketAdmission::Retained
                }
            }
            Packet::RecoverySlice(rs) => {
                if rs.exponent > MAX_RECOVERY_EXPONENT {
                    // Outside the usable GF exponent domain, so this block can
                    // never take part in a solve. Refuse it before it claims a
                    // map slot.
                    warn!(
                        exponent = rs.exponent,
                        "discarding recovery block outside the usable exponent domain"
                    );
                    PacketAdmission::Rejected
                } else {
                    match self.recovery_slices.entry(rs.exponent) {
                        std::collections::btree_map::Entry::Occupied(_) => {
                            PacketAdmission::Duplicate
                        }
                        std::collections::btree_map::Entry::Vacant(slot) => {
                            slot.insert(RecoverySlice {
                                exponent: rs.exponent,
                                data: rs.data,
                            });
                            PacketAdmission::Retained
                        }
                    }
                }
            }
            Packet::Creator(c) => {
                if self.creator.is_none() {
                    self.creator = Some(c.creator_id);
                    PacketAdmission::Retained
                } else {
                    PacketAdmission::Duplicate
                }
            }
            Packet::Unknown { packet_type, .. } => {
                warn!("ignoring unknown packet type: {packet_type:02x?}");
                PacketAdmission::Rejected
            }
        })
    }

    pub(crate) fn build(self) -> Result<Par2FileSet> {
        let main = self.main_packet.ok_or(Par2Error::NoMainPacket)?;

        // Validate recovery block data lengths against slice_size.
        // PAR2 spec requires each recovery block to be exactly slice_size bytes.
        // Wrong-sized recovery blocks are unusable and must not be zero-padded.
        let mut recovery_slices = self.recovery_slices;
        let slice_size = main.slice_size;

        recovery_slices.retain(|exp, rs| {
            let data_len = rs.data.len() as u64;
            if data_len != slice_size {
                warn!(
                    "recovery block exponent {exp}: data length {data_len} does not equal slice_size {slice_size}, discarding"
                );
                return false;
            }
            true
        });

        let mut slice_checksums = self.slice_checksums;
        slice_checksums.retain(|file_id, checksums| {
            let Some(desc) = self.files.get(file_id) else {
                warn!("IFSC packet for unknown file {file_id}, discarding");
                return false;
            };
            let expected = if desc.length == 0 {
                0
            } else {
                desc.length.div_ceil(slice_size) as usize
            };
            if checksums.len() != expected {
                warn!(
                    file = %desc.filename,
                    actual = checksums.len(),
                    expected,
                    "IFSC entry count does not match file block count, discarding"
                );
                return false;
            }
            true
        });

        Ok(Par2FileSet {
            recovery_set_id: main.recovery_set_id,
            slice_size,
            recovery_file_ids: main.recovery_file_ids,
            non_recovery_file_ids: main.non_recovery_file_ids,
            files: self.files,
            slice_checksums,
            recovery_slices,
            creator: self.creator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::packet::header;
    use md5::{Digest, Md5};
    use tempfile::tempdir;

    /// Helper to build a complete valid packet (header + body).
    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (header::HEADER_SIZE + body.len()) as u64;

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);

        let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

        let mut data = Vec::new();
        data.extend_from_slice(header::MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    fn make_main_body(slice_size: u64, file_ids: &[[u8; 16]]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&slice_size.to_le_bytes());
        body.extend_from_slice(&(file_ids.len() as u32).to_le_bytes());
        for id in file_ids {
            body.extend_from_slice(id);
        }
        body
    }

    fn make_file_desc_body(
        file_id: [u8; 16],
        hash_full: [u8; 16],
        hash_16k: [u8; 16],
        file_length: u64,
        filename: &str,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&file_id);
        body.extend_from_slice(&hash_full);
        body.extend_from_slice(&hash_16k);
        body.extend_from_slice(&file_length.to_le_bytes());
        body.extend_from_slice(filename.as_bytes());
        // Pad to multiple of 4
        while body.len() % 4 != 0 {
            body.push(0);
        }
        body
    }

    fn make_ifsc_body(file_id: [u8; 16], checksums: &[(u32, [u8; 16])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&file_id);
        for &(crc, md5) in checksums {
            // PAR2 spec order: MD5 (16 bytes) then CRC32 (4 bytes)
            body.extend_from_slice(&md5);
            body.extend_from_slice(&crc.to_le_bytes());
        }
        body
    }

    /// Compute RSID as MD5 of main body (that's how PAR2 spec works).
    fn compute_rsid(main_body: &[u8]) -> [u8; 16] {
        Md5::digest(main_body).into()
    }

    fn crc_test_set(
        slice_size: u64,
        length: u64,
        checksums: Vec<SliceChecksum>,
    ) -> (Par2FileSet, FileId) {
        let file_id = FileId::from_bytes([0x7A; 16]);
        let description = FileDescription {
            file_id,
            hash_full: [0; 16],
            hash_16k: [0; 16],
            length,
            par2_name: "crc-test.bin".to_string(),
            filename: "crc-test.bin".to_string(),
        };
        let set = Par2FileSet {
            recovery_set_id: RecoverySetId::from_bytes([0; 16]),
            slice_size,
            recovery_file_ids: vec![file_id],
            non_recovery_file_ids: Vec::new(),
            files: std::collections::HashMap::from([(file_id, description)]),
            slice_checksums: std::collections::HashMap::from([(file_id, checksums)]),
            recovery_slices: std::collections::BTreeMap::new(),
            creator: None,
        };
        (set, file_id)
    }

    #[test]
    fn build_par2_set_from_single_file() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(4096, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        let fd_body = make_file_desc_body(file_id_a, [0xAA; 16], [0xAA; 16], 8192, "test.bin");
        let ifsc_body = make_ifsc_body(file_id_a, &[(0x1234, [0xCC; 16]), (0x5678, [0xDD; 16])]);
        let creator_body = b"TestApp\x00";

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_IFSC, &ifsc_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_CREATOR, creator_body, rsid));

        let set = Par2FileSet::from_files(&[&stream]).unwrap();

        assert_eq!(set.slice_size, 4096);
        assert_eq!(set.recovery_file_ids.len(), 1);
        assert_eq!(*set.recovery_file_ids[0].as_bytes(), file_id_a);

        let fd = set
            .file_description(&FileId::from_bytes(file_id_a))
            .unwrap();
        assert_eq!(fd.filename, "test.bin");
        assert_eq!(fd.length, 8192);

        let checksums = set.file_checksums(&FileId::from_bytes(file_id_a)).unwrap();
        assert_eq!(checksums.len(), 2);
        assert_eq!(checksums[0].crc32, 0x1234);

        assert_eq!(set.creator.as_deref(), Some("TestApp"));
        assert_eq!(set.recovery_block_count(), 0);
    }

    #[test]
    fn build_par2_set_from_multiple_files() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(1024, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        // File 1: main + file desc
        let mut file1 = Vec::new();
        file1.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        let fd_body = make_file_desc_body(file_id_a, [0; 16], [0; 16], 2048, "data.bin");
        file1.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));

        // File 2: recovery slice
        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes()); // exponent 0
        recovery_body.extend_from_slice(&[0xAB; 1024]); // recovery data
        let mut file2 = Vec::new();
        file2.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        file2.extend_from_slice(&make_full_packet(
            header::TYPE_RECOVERY,
            &recovery_body,
            rsid,
        ));

        let set = Par2FileSet::from_files(&[&file1[..], &file2[..]]).unwrap();
        assert_eq!(set.files.len(), 1);
        assert_eq!(set.recovery_block_count(), 1);
        assert!(set.recovery_slices.contains_key(&0));
    }

    #[test]
    fn build_par2_set_from_paths_keeps_recovery_file_backed() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(1024, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes());
        recovery_body.extend_from_slice(&[0xAB; 1024]);

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(
            header::TYPE_RECOVERY,
            &recovery_body,
            rsid,
        ));

        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.par2");
        std::fs::write(&path, &stream).unwrap();

        let set = Par2FileSet::from_paths(&[path]).unwrap();
        let recovery = set.recovery_slices.get(&0).unwrap();
        assert!(recovery.data.as_bytes().is_none());

        let mut head = vec![0u8; 16];
        recovery.data.read_range_padded(0, &mut head).unwrap();
        assert_eq!(head, vec![0xAB; 16]);
    }

    #[test]
    fn no_main_packet_error() {
        let rsid = [0; 16];
        let creator_body = b"test";
        let stream = make_full_packet(header::TYPE_CREATOR, creator_body, rsid);

        let err = Par2FileSet::from_files(&[&stream]).unwrap_err();
        assert!(matches!(err, Par2Error::NoMainPacket));
    }

    #[test]
    fn conflicting_recovery_set_error() {
        let main_body_1 = make_main_body(1024, &[]);
        let rsid_1 = compute_rsid(&main_body_1);
        let main_body_2 = make_main_body(2048, &[]);
        let rsid_2 = compute_rsid(&main_body_2);

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body_1, rsid_1));
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body_2, rsid_2));

        let err = Par2FileSet::from_files(&[&stream]).unwrap_err();
        assert!(matches!(err, Par2Error::ConflictingRecoverySet));
    }

    #[test]
    fn slice_count_calculation() {
        let main_body = make_main_body(1000, &[]);
        let rsid = compute_rsid(&main_body);
        let stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        let set = Par2FileSet::from_files(&[&stream]).unwrap();

        assert_eq!(set.slice_count_for_file(0), 0);
        assert_eq!(set.slice_count_for_file(1), 1);
        assert_eq!(set.slice_count_for_file(999), 1);
        assert_eq!(set.slice_count_for_file(1000), 1);
        assert_eq!(set.slice_count_for_file(1001), 2);
        assert_eq!(set.slice_count_for_file(3000), 3);
    }

    #[test]
    fn expected_file_crc32_handles_empty_and_exact_slices() {
        let (empty_set, empty_id) = crc_test_set(4, 0, Vec::new());
        assert_eq!(
            empty_set.expected_file_crc32(empty_id),
            Some(checksum::crc32(&[]))
        );

        let (mut empty_without_ifsc, empty_id) = crc_test_set(4, 0, Vec::new());
        empty_without_ifsc.slice_checksums.clear();
        assert_eq!(
            empty_without_ifsc.expected_file_crc32(empty_id),
            Some(checksum::crc32(&[]))
        );

        let data = b"exactly-four-bytes";
        let (set, file_id) = crc_test_set(
            6,
            data.len() as u64,
            vec![
                SliceChecksum {
                    crc32: checksum::crc32(&data[..6]),
                    md5: [0; 16],
                },
                SliceChecksum {
                    crc32: checksum::crc32(&data[6..12]),
                    md5: [0; 16],
                },
                SliceChecksum {
                    crc32: checksum::crc32(&data[12..]),
                    md5: [0; 16],
                },
            ],
        );
        assert_eq!(
            set.expected_file_crc32(file_id),
            Some(checksum::crc32(data))
        );
    }

    #[test]
    fn expected_file_crc32_unpads_short_final_slice_before_combining() {
        let data = b"abcdefghij";
        let (set, file_id) = crc_test_set(
            4,
            data.len() as u64,
            vec![
                SliceChecksum {
                    crc32: checksum::crc32(&data[..4]),
                    md5: [0; 16],
                },
                SliceChecksum {
                    crc32: checksum::crc32(&data[4..8]),
                    md5: [0; 16],
                },
                SliceChecksum {
                    crc32: checksum::crc32_padded(&data[8..], 4),
                    md5: [0; 16],
                },
            ],
        );

        assert_eq!(
            set.expected_file_crc32(file_id),
            Some(checksum::crc32(data))
        );
    }

    #[test]
    fn expected_file_crc32_matches_randomized_direct_file_crc32() {
        let mut seed = 0xD1CE_BAAD_F00D_CAFEu64;
        for case in 0..128usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let slice_size = 1 + (seed as usize % 257);
            let length = 1 + ((seed >> 16) as usize % 4096) + case;
            let mut data = vec![0u8; length];
            for byte in &mut data {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            let checksums = data
                .chunks(slice_size)
                .map(|slice| {
                    let mut state = checksum::SliceChecksumState::new();
                    state.update(slice);
                    let (crc32, md5) = state.finalize(Some(slice_size as u64));
                    SliceChecksum { crc32, md5 }
                })
                .collect();
            let (set, file_id) = crc_test_set(slice_size as u64, length as u64, checksums);

            assert_eq!(
                set.expected_file_crc32(file_id),
                Some(checksum::crc32(&data)),
                "case={case} slice_size={slice_size} length={length}"
            );
        }
    }

    #[test]
    fn expected_file_crc32_rejects_absent_or_inconsistent_metadata() {
        let data = b"five!";
        let checksums = vec![SliceChecksum {
            crc32: checksum::crc32_padded(data, 4),
            md5: [0; 16],
        }];
        let (mut set, file_id) = crc_test_set(4, data.len() as u64, checksums);
        assert_eq!(set.expected_file_crc32(file_id), None);

        set.slice_checksums.clear();
        assert_eq!(set.expected_file_crc32(file_id), None);

        let (mut no_description, file_id) = crc_test_set(4, 0, Vec::new());
        no_description.files.clear();
        assert_eq!(no_description.expected_file_crc32(file_id), None);

        let (zero_slice_size, file_id) = crc_test_set(0, 0, Vec::new());
        assert_eq!(zero_slice_size.expected_file_crc32(file_id), None);
    }

    #[test]
    fn merge_packets_adds_recovery() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(1024, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        let mut file1 = Vec::new();
        file1.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        let fd_body = make_file_desc_body(file_id_a, [0; 16], [0; 16], 2048, "data.bin");
        file1.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));

        let mut set = Par2FileSet::from_files(&[&file1[..]]).unwrap();
        assert_eq!(set.recovery_block_count(), 0);

        // Build recovery packet
        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes()); // exponent 0
        recovery_body.extend_from_slice(&[0xAB; 1024]);
        let mut file2 = Vec::new();
        file2.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        file2.extend_from_slice(&make_full_packet(
            header::TYPE_RECOVERY,
            &recovery_body,
            rsid,
        ));

        let packets: Vec<_> = crate::packet::scan_packets(&file2, 0)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect();

        let result = set.merge_packets(packets).unwrap();
        assert_eq!(result.new_recovery_slices, 1);
        assert_eq!(result.duplicates_ignored, 1); // duplicate main
        assert_eq!(set.recovery_block_count(), 1);
    }

    #[test]
    fn merge_packets_rejects_conflicting_rsid() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(1024, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        let stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        let mut set = Par2FileSet::from_files(&[&stream[..]]).unwrap();

        // Different main body = different RSID
        let other_main_body = make_main_body(2048, &[file_id_a]);
        let other_rsid = compute_rsid(&other_main_body);
        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes());
        recovery_body.extend_from_slice(&[0xAB; 2048]);
        let mut other_stream = make_full_packet(header::TYPE_RECOVERY, &recovery_body, other_rsid);
        other_stream.extend_from_slice(&make_full_packet(
            header::TYPE_MAIN,
            &other_main_body,
            other_rsid,
        ));

        let packets: Vec<_> = crate::packet::scan_packets(&other_stream, 0)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect();

        let err = set.merge_packets(packets).unwrap_err();
        assert!(matches!(err, Par2Error::ConflictingRecoverySet));
        assert_eq!(set.recovery_block_count(), 0);
    }

    #[test]
    fn merge_packets_deduplicates() {
        let file_id_a = [0x01; 16];
        let main_body = make_main_body(1024, &[file_id_a]);
        let rsid = compute_rsid(&main_body);

        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes());
        recovery_body.extend_from_slice(&[0xAB; 1024]);

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(
            header::TYPE_RECOVERY,
            &recovery_body,
            rsid,
        ));

        let mut set = Par2FileSet::from_files(&[&stream[..]]).unwrap();
        assert_eq!(set.recovery_block_count(), 1);

        // Merge the same recovery block again
        let packets: Vec<_> = crate::packet::scan_packets(&stream, 0)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect();

        let result = set.merge_packets(packets).unwrap();
        assert_eq!(result.new_recovery_slices, 0);
        assert_eq!(result.duplicates_ignored, 2); // main + recovery
        assert_eq!(set.recovery_block_count(), 1);
    }

    #[test]
    fn duplicate_main_same_rsid_accepted() {
        let main_body = make_main_body(4096, &[]);
        let rsid = compute_rsid(&main_body);

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));

        // Should succeed (duplicate with same RSID is ok)
        let set = Par2FileSet::from_files(&[&stream]).unwrap();
        assert_eq!(set.slice_size, 4096);
    }

    fn make_recovery_body(exponent: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&exponent.to_le_bytes());
        body.extend_from_slice(payload);
        body
    }

    /// Exponents outside the usable GF domain describe no recoverable block, so
    /// they must be refused before they claim a slot in the recovery map.
    #[test]
    fn recovery_exponents_outside_the_usable_domain_are_discarded() {
        let main_body = make_main_body(4, &[]);
        let rsid = compute_rsid(&main_body);

        let mut stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        for exponent in [
            0u32,
            MAX_RECOVERY_EXPONENT,
            MAX_RECOVERY_EXPONENT + 1,
            u32::MAX,
        ] {
            stream.extend_from_slice(&make_full_packet(
                header::TYPE_RECOVERY,
                &make_recovery_body(exponent, &[0xAB; 4]),
                rsid,
            ));
        }

        let set = Par2FileSet::from_files(&[&stream]).unwrap();
        assert_eq!(set.recovery_block_count(), 2);
        assert!(set.recovery_slices.contains_key(&0));
        assert!(set.recovery_slices.contains_key(&MAX_RECOVERY_EXPONENT));
        assert!(
            !set.recovery_slices
                .contains_key(&(MAX_RECOVERY_EXPONENT + 1))
        );
    }

    /// Redundant critical packets are what a real multi-volume set is mostly
    /// made of. They have to cost work but not retention, or the retained
    /// budget would be spent on copies of the same few packets.
    #[test]
    fn duplicate_packets_do_not_consume_the_retained_packet_budget() {
        let file_id = [0x31; 16];
        let main_body = make_main_body(4, &[file_id]);
        let rsid = compute_rsid(&main_body);
        let fd = make_full_packet(
            header::TYPE_FILE_DESC,
            &make_file_desc_body(file_id, [0xAA; 16], [0xAA; 16], 4, "dup.bin"),
            rsid,
        );
        let ifsc = make_full_packet(
            header::TYPE_IFSC,
            &make_ifsc_body(file_id, &[(0x1234, [0xCC; 16])]),
            rsid,
        );

        let mut stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        for _ in 0..2_000 {
            stream.extend_from_slice(&fd);
            stream.extend_from_slice(&ifsc);
        }

        // Exactly the logical inventory: Main + one File Description + one IFSC.
        let limits = PacketScanLimits::default().with_max_retained_packets(3);
        let set = Par2FileSet::from_files_with_limits(&[&stream], limits).unwrap();
        assert_eq!(set.files.len(), 1);
        assert_eq!(set.slice_checksums.len(), 1);
    }

    /// One budget spans every input, so redundancy spread across volumes is
    /// counted once for the load rather than once per file.
    #[test]
    fn the_retained_budget_is_shared_across_every_input_file() {
        let main_body = make_main_body(4, &[]);
        let rsid = compute_rsid(&main_body);

        let build = |exponents: std::ops::Range<u32>| {
            let mut stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
            for exponent in exponents {
                stream.extend_from_slice(&make_full_packet(
                    header::TYPE_RECOVERY,
                    &make_recovery_body(exponent, &[0xAB; 4]),
                    rsid,
                ));
            }
            stream
        };
        let first = build(0..5);
        let second = build(5..10);

        // Main plus five recovery blocks fits either file on its own.
        let limits = PacketScanLimits::default().with_max_retained_packets(6);
        assert_eq!(
            Par2FileSet::from_files_with_limits(&[&first], limits)
                .unwrap()
                .recovery_block_count(),
            5
        );
        assert_eq!(
            Par2FileSet::from_files_with_limits(&[&second], limits)
                .unwrap()
                .recovery_block_count(),
            5
        );

        // Together they need eleven, and the shared budget refuses them.
        let error = Par2FileSet::from_files_with_limits(&[&first, &second], limits).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));

        let limits = limits.with_max_retained_packets(11);
        assert_eq!(
            Par2FileSet::from_files_with_limits(&[&first, &second], limits)
                .unwrap()
                .recovery_block_count(),
            10
        );
    }

    /// A set right up against the documented ceilings still loads.
    #[test]
    fn an_inventory_near_the_documented_recovery_ceiling_still_loads() {
        let main_body = make_main_body(4, &[]);
        let rsid = compute_rsid(&main_body);
        let mut stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        // A slice of the domain rather than all 65,536: the full-scale run lives
        // in the repairer's reproduction test, which owns the slow path.
        for exponent in (MAX_RECOVERY_EXPONENT - 999)..=MAX_RECOVERY_EXPONENT {
            stream.extend_from_slice(&make_full_packet(
                header::TYPE_RECOVERY,
                &make_recovery_body(exponent, &[0xAB; 4]),
                rsid,
            ));
        }

        let set = Par2FileSet::from_files(&[&stream]).unwrap();
        assert_eq!(set.recovery_block_count(), 1_000);
        assert!(set.recovery_slices.contains_key(&MAX_RECOVERY_EXPONENT));
    }

    /// A refused load yields an error and nothing else. There is no partially
    /// built set to observe, by construction: the builder is consumed to
    /// produce a `Par2FileSet` and the error path never reaches that point.
    #[test]
    fn a_refused_load_produces_no_file_set_at_all() {
        let main_body = make_main_body(4, &[]);
        let rsid = compute_rsid(&main_body);
        let mut stream = make_full_packet(header::TYPE_MAIN, &main_body, rsid);
        for exponent in 0..32u32 {
            stream.extend_from_slice(&make_full_packet(
                header::TYPE_RECOVERY,
                &make_recovery_body(exponent, &[0xAB; 4]),
                rsid,
            ));
        }

        let limits = PacketScanLimits::default().with_max_retained_packets(4);
        let outcome = Par2FileSet::from_files_with_limits(&[&stream], limits);
        assert!(matches!(
            outcome,
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
        assert!(outcome.is_err(), "no Par2FileSet is reachable from Err");

        let dir = tempdir().unwrap();
        let path = dir.path().join("refused.par2");
        std::fs::write(&path, &stream).unwrap();
        assert!(matches!(
            Par2FileSet::from_paths_with_limits(&[path], limits),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }
}
