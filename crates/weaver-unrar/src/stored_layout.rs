//! Cross-volume stored-layout assembly over per-volume header facts.
//!
//! [`StoredLayoutBuilder`] learns a multi-volume set's layout one volume at a
//! time from [`RarVolumeFacts`], in any order, and answers the question a
//! one-pass router asks: for a physical byte range inside a volume, which
//! member owns each byte and at what offset inside that member.
//!
//! The whole design turns on one property of the format: **no RAR header field
//! carries a part's logical offset within its member**. A split part header
//! states the member's *total* unpacked size only, so part *N* begins at
//! `sum(data_size)` over parts `0..N` — a value that exists only once every
//! earlier part's header has been parsed. [`StoredLayoutBuilder::header_frontier`]
//! reports how far that knowledge reaches for the set as a whole, and
//! [`StoredMemberPart::logical_offset`] is `None` until the part's own chain
//! prefix is complete.
//!
//! This module classifies facts and nothing else. Budgets, tolerances, group
//! merging and the decision to route or demote belong to the caller; the layout
//! only reports what the headers say.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::archive::{RarVolumeFacts, RarVolumeMemberFacts};
use crate::types::{ArchiveFormat, CompressionMethod};

/// Why a member's split chain cannot be trusted.
///
/// A malformed chain never panics and never routes: the member's packed bytes
/// take the envelope path like any other ineligible member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// Two headers in one volume claim the same member name.
    DuplicatePartInVolume { volume: u32 },
    /// Two members' packed ranges overlap inside one volume.
    OverlappingParts { volume: u32 },
    /// The set's first volume carries a continuation part, so the chain claims
    /// a predecessor volume that cannot exist.
    ContinuationInFirstVolume,
    /// A part that is not the member's first claims to start it
    /// (`split_before` clear).
    UnexpectedChainStart { volume: u32 },
    /// A part that is not the member's last claims to end it (`split_after`
    /// clear).
    UnexpectedChainEnd { volume: u32 },
    /// A volume inside the member's span was added but carries no part of it.
    MissingPartInAddedVolume { volume: u32 },
    /// The header declares the unpacked size unknown, so neither the chain sum
    /// nor a destination size can be established.
    MissingUnpackedSize,
    /// A complete stored chain's packed bytes do not sum to the member's
    /// unpacked size. Checked over the whole chain, never per part.
    SizeMismatch {
        packed_total: u64,
        unpacked_size: u64,
    },
}

/// Why a member's bytes cannot be routed straight to a destination.
///
/// The variants carry what a caller needs to apply its own policy — notably
/// the byte counts a compressed member would cost if it were tolerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IneligibilityReason {
    /// At least one part uses a compression method other than `Store`.
    Compressed {
        packed_bytes: u64,
        unpacked_bytes: u64,
    },
    /// At least one part is encrypted.
    Encrypted,
    /// At least one part sets the per-member solid flag. This is the member's
    /// own flag, not the archive-level solid flag.
    Solid,
    /// The member is a directory entry.
    Directory,
    /// The member is a redirection (symlink, hardlink, junction, file copy).
    Redirection,
    /// The member carries a BLAKE2sp digest but no whole-member CRC32. BLAKE2sp
    /// only accepts bytes in order, so out-of-order routing cannot verify it.
    Blake2OnlyNoCrc32,
    /// The member carries no whole-member checksum at all.
    NoChecksum,
    /// The member's split chain is inconsistent.
    MalformedChain(MalformedReason),
}

/// Whether a member's packed bytes can be routed to their final destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberEligibility {
    /// The chain is complete and every direct-store requirement holds,
    /// including a whole-member CRC32.
    DirectEligible,
    /// Nothing observed so far disqualifies the member, but its chain is still
    /// open, so the authoritative whole-member CRC32 — which lives in the final
    /// part's header — has not been seen yet. Resolves to [`Self::DirectEligible`]
    /// or [`Self::Ineligible`] once the chain closes.
    ProvisionallyDirect,
    /// A fact disqualifies the member.
    Ineligible(IneligibilityReason),
}

impl MemberEligibility {
    /// Whether the layout maps this member's packed bytes to the member rather
    /// than to the envelope.
    ///
    /// True for both direct states: a set is routed while its chains are still
    /// open, and a member that later fails to close cleanly is the caller's
    /// demotion decision, not a mapping error.
    pub fn routes_direct(self) -> bool {
        matches!(self, Self::DirectEligible | Self::ProvisionallyDirect)
    }
}

/// One volume's slice of a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMemberPart {
    /// Volume number this part lives in.
    pub volume: u32,
    /// Physical offset of the packed bytes within that volume.
    pub data_offset: u64,
    /// Packed byte count in that volume.
    pub data_size: u64,
    /// Offset of this part inside the member, or `None` while any earlier part
    /// of the chain is still unknown. No header states this value; it is the
    /// prefix sum of the earlier parts' `data_size`.
    pub logical_offset: Option<u64>,
    /// CRC32 of this part's packed bytes, from a non-final split header.
    pub packed_crc32: Option<u32>,
    /// BLAKE2sp of this part's packed bytes, from a non-final split header.
    pub packed_blake2_hash: Option<[u8; 32]>,
    /// The part continues a member started in an earlier volume.
    pub split_before: bool,
    /// The member continues into a later volume.
    pub split_after: bool,
}

/// A member assembled from every volume that carries part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// Name exactly as the headers state it. Not sanitized: destination path
    /// policy belongs to the caller, and the raw name is what links parts
    /// across volumes.
    pub name: String,
    /// Lowest volume number carrying a part of this member.
    pub first_volume: u32,
    /// Total unpacked size the headers declare.
    pub unpacked_size: Option<u64>,
    /// Whole-member CRC32: the final part's header for a split member, the
    /// member's own header when unsplit. `None` until that header arrives.
    pub data_crc32: Option<u32>,
    /// Whole-member BLAKE2sp, from the same header as `data_crc32`.
    pub data_blake2_hash: Option<[u8; 32]>,
    /// Parts in volume order.
    pub parts: Vec<StoredMemberPart>,
    /// Whether the chain runs from a known first part to a known last part with
    /// no unseen volume in between.
    pub chain_complete: bool,
    /// Classification of this member from the facts seen so far.
    pub eligibility: MemberEligibility,
}

/// The member names one volume's headers link to its neighbours.
///
/// Split flags are the only evidence that two archive identities are the same
/// set, so a caller merging candidate sets should merge on these names alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeSplitEvidence {
    /// Names continuing from the previous volume (`split_before`).
    pub continued_from_previous: Vec<String>,
    /// Names continuing into the next volume (`split_after`).
    pub continues_into_next: Vec<String>,
}

/// Where one run of physical volume bytes belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappedSlice {
    /// Bytes of a direct-routed member, at `logical_offset` inside it.
    Member {
        member_index: usize,
        logical_offset: u64,
        len: u64,
    },
    /// Bytes that are not inside a direct-routed member's packed range:
    /// headers, service blocks, recovery records and ineligible members' data.
    Envelope { len: u64 },
    /// Bytes whose destination is not known yet, because the volume has not
    /// been added or because the owning member's logical offset is still
    /// unresolved.
    Unroutable { len: u64 },
}

/// Rejections from [`StoredLayoutBuilder::add_volume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoredLayoutError {
    /// The volume was already added with different header facts.
    #[error("volume {volume} was already added with different header facts")]
    ConflictingVolume { volume: u32 },
    /// The volume belongs to a different archive format than the layout.
    #[error("volume format {found:?} does not match layout format {expected:?}")]
    FormatMismatch {
        expected: ArchiveFormat,
        found: ArchiveFormat,
    },
}

/// The header facts one volume states about one member.
///
/// Only the fields the layout consumes are kept, which is exactly the
/// comparison a re-add must survive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemberSnapshot {
    name: String,
    data_offset: u64,
    data_size: u64,
    unpacked_size: Option<u64>,
    data_crc32: Option<u32>,
    data_blake2_hash: Option<[u8; 32]>,
    packed_crc32: Option<u32>,
    packed_blake2_hash: Option<[u8; 32]>,
    split_before: bool,
    split_after: bool,
    is_directory: bool,
    is_encrypted: bool,
    is_redirection: bool,
    is_store: bool,
    is_solid: bool,
}

impl MemberSnapshot {
    fn from_facts(facts: &RarVolumeMemberFacts) -> Self {
        Self {
            name: facts.name.clone(),
            data_offset: facts.data_offset,
            data_size: facts.data_size,
            unpacked_size: facts.unpacked_size,
            data_crc32: facts.data_crc32,
            data_blake2_hash: facts.data_blake2_hash,
            packed_crc32: facts.packed_crc32,
            packed_blake2_hash: facts.packed_blake2_hash,
            split_before: facts.split_before,
            split_after: facts.split_after,
            is_directory: facts.is_directory,
            is_encrypted: facts.is_encrypted,
            is_redirection: facts.redirection_type.is_some(),
            is_store: facts.compression_method == CompressionMethod::Store.code(),
            is_solid: facts.compression_solid,
        }
    }
}

/// A member's packed range inside one volume, used by the physical mapping.
#[derive(Debug, Clone, Copy)]
struct VolumeExtent {
    member_index: usize,
    data_offset: u64,
    data_size: u64,
}

/// Everything one added volume contributes.
struct VolumeRecord {
    snapshots: Vec<MemberSnapshot>,
    /// Member extents sorted by physical offset.
    extents: Vec<VolumeExtent>,
    evidence: VolumeSplitEvidence,
}

/// Facts about a member that only ever accumulate as volumes arrive.
#[derive(Debug, Clone, Copy, Default)]
struct MemberTraits {
    /// Set by a violation a single volume proves on its own; structural chain
    /// violations are re-derived from the chain instead.
    malformed: Option<MalformedReason>,
    encrypted: bool,
    solid: bool,
    directory: bool,
    redirection: bool,
    compressed: bool,
}

/// Incremental cross-volume stored layout for one archive set.
///
/// Volumes may be added in any order and any number of times; re-adding a
/// volume with the same header facts is a no-op. See the module docs for the
/// logical-offset precondition the whole layout rests on.
pub struct StoredLayoutBuilder {
    format: ArchiveFormat,
    volumes: BTreeMap<u32, VolumeRecord>,
    members: Vec<StoredMember>,
    traits: Vec<MemberTraits>,
    index: HashMap<String, usize>,
    frontier: Option<u32>,
}

impl StoredLayoutBuilder {
    /// Start an empty layout for a set of the given format.
    pub fn new(format: ArchiveFormat) -> Self {
        Self {
            format,
            volumes: BTreeMap::new(),
            members: Vec::new(),
            traits: Vec::new(),
            index: HashMap::new(),
            frontier: None,
        }
    }

    /// The format this layout was opened for.
    pub fn format(&self) -> ArchiveFormat {
        self.format
    }

    /// Learn one volume's headers.
    ///
    /// `volume` is the caller's 0-based index within the set, which is
    /// authoritative: RAR4 volumes do not reliably state their own number.
    ///
    /// Re-adding a volume whose facts are unchanged succeeds and changes
    /// nothing; re-adding it with different facts is rejected rather than
    /// silently rewriting a layout other volumes were already resolved against.
    pub fn add_volume(
        &mut self,
        volume: u32,
        facts: &RarVolumeFacts,
    ) -> Result<(), StoredLayoutError> {
        let found = facts.archive_format();
        if found != self.format {
            return Err(StoredLayoutError::FormatMismatch {
                expected: self.format,
                found,
            });
        }

        let snapshots: Vec<MemberSnapshot> = facts
            .members
            .iter()
            .map(MemberSnapshot::from_facts)
            .collect();
        if let Some(existing) = self.volumes.get(&volume) {
            return if existing.snapshots == snapshots {
                Ok(())
            } else {
                Err(StoredLayoutError::ConflictingVolume { volume })
            };
        }

        let mut extents: Vec<VolumeExtent> = Vec::with_capacity(snapshots.len());
        let mut evidence = VolumeSplitEvidence::default();
        let mut names_here: HashSet<&str> = HashSet::with_capacity(snapshots.len());

        for snapshot in &snapshots {
            if snapshot.split_before {
                evidence.continued_from_previous.push(snapshot.name.clone());
            }
            if snapshot.split_after {
                evidence.continues_into_next.push(snapshot.name.clone());
            }

            let member_index = self.member_index_for(snapshot, volume);
            self.absorb_traits(member_index, snapshot);

            if !names_here.insert(snapshot.name.as_str()) {
                // Keep the first header and record the conflict; either way the
                // member can no longer be trusted.
                self.traits[member_index]
                    .malformed
                    .get_or_insert(MalformedReason::DuplicatePartInVolume { volume });
                continue;
            }

            let member = &mut self.members[member_index];
            member.first_volume = member.first_volume.min(volume);
            if member.unpacked_size.is_none() {
                member.unpacked_size = snapshot.unpacked_size;
            }
            // Only a final part states the whole-member checksums; every
            // earlier part's fields describe that volume's packed bytes.
            if !snapshot.split_after {
                member.data_crc32 = snapshot.data_crc32;
                member.data_blake2_hash = snapshot.data_blake2_hash;
            }

            let part = StoredMemberPart {
                volume,
                data_offset: snapshot.data_offset,
                data_size: snapshot.data_size,
                logical_offset: None,
                packed_crc32: snapshot.packed_crc32,
                packed_blake2_hash: snapshot.packed_blake2_hash,
                split_before: snapshot.split_before,
                split_after: snapshot.split_after,
            };
            let position = member
                .parts
                .partition_point(|existing| existing.volume < volume);
            member.parts.insert(position, part);

            extents.push(VolumeExtent {
                member_index,
                data_offset: snapshot.data_offset,
                data_size: snapshot.data_size,
            });
        }

        extents.sort_by_key(|extent| extent.data_offset);
        for pair in extents.windows(2) {
            let (left, right) = (pair[0], pair[1]);
            if left.data_size > 0
                && right.data_size > 0
                && left.data_offset.saturating_add(left.data_size) > right.data_offset
            {
                for member_index in [left.member_index, right.member_index] {
                    self.traits[member_index]
                        .malformed
                        .get_or_insert(MalformedReason::OverlappingParts { volume });
                }
            }
        }

        self.volumes.insert(
            volume,
            VolumeRecord {
                snapshots,
                extents,
                evidence,
            },
        );
        self.advance_frontier();

        // A volume also changes members it carries no part of: one added inside
        // a member's span proves a hole in that member's chain.
        let affected: Vec<usize> = (0..self.members.len())
            .filter(|index| self.member_spans(*index, volume))
            .collect();
        for index in affected {
            self.resolve_member(index);
        }

        Ok(())
    }

    /// Whether this volume's headers have been learned.
    pub fn has_volume(&self, volume: u32) -> bool {
        self.volumes.contains_key(&volume)
    }

    /// The largest `N` for which volumes `0..=N` have all been added, or `None`
    /// while volume 0 is missing.
    ///
    /// Payload arriving for a volume past the frontier cannot be fully placed:
    /// a part's logical offset needs every earlier part's header, so the
    /// frontier bounds how far ahead of the header chain a router can route.
    pub fn header_frontier(&self) -> Option<u32> {
        self.frontier
    }

    /// Members in the order they were first seen, which is the order
    /// [`MappedSlice::Member`] indexes them by.
    pub fn members(&self) -> &[StoredMember] {
        &self.members
    }

    /// The split flags one volume's headers carry, once that volume is added.
    pub fn split_evidence(&self, volume: u32) -> Option<&VolumeSplitEvidence> {
        self.volumes.get(&volume).map(|record| &record.evidence)
    }

    /// Split `[offset, offset + len)` of one volume into destination runs.
    ///
    /// Slices come back in physical order and cover the requested range
    /// exactly; adjacent runs of the same non-member kind are coalesced. An
    /// empty range maps to no slices.
    pub fn map_physical_range(&self, volume: u32, offset: u64, len: u64) -> Vec<MappedSlice> {
        let mut slices = Vec::new();
        if len == 0 {
            return slices;
        }
        let end = offset.saturating_add(len);

        let Some(record) = self.volumes.get(&volume) else {
            slices.push(MappedSlice::Unroutable { len });
            return slices;
        };

        let mut cursor = offset;
        for extent in &record.extents {
            if cursor >= end {
                break;
            }
            if extent.data_size == 0 {
                continue;
            }
            let extent_end = extent.data_offset.saturating_add(extent.data_size);
            if extent_end <= cursor {
                continue;
            }
            if extent.data_offset >= end {
                break;
            }

            if extent.data_offset > cursor {
                push_slice(
                    &mut slices,
                    MappedSlice::Envelope {
                        len: extent.data_offset - cursor,
                    },
                );
                cursor = extent.data_offset;
            }

            let run_end = extent_end.min(end);
            let run_len = run_end - cursor;
            let member = &self.members[extent.member_index];
            let part = member
                .parts
                .binary_search_by_key(&volume, |part| part.volume)
                .ok()
                .and_then(|position| member.parts[position].logical_offset);
            let slice = match (member.eligibility.routes_direct(), part) {
                (true, Some(logical_offset)) => MappedSlice::Member {
                    member_index: extent.member_index,
                    logical_offset: logical_offset + (cursor - extent.data_offset),
                    len: run_len,
                },
                (true, None) => MappedSlice::Unroutable { len: run_len },
                (false, _) => MappedSlice::Envelope { len: run_len },
            };
            push_slice(&mut slices, slice);
            cursor = run_end;
        }

        if cursor < end {
            push_slice(&mut slices, MappedSlice::Envelope { len: end - cursor });
        }
        slices
    }

    /// Find or create the member a header belongs to, keyed by header name.
    fn member_index_for(&mut self, snapshot: &MemberSnapshot, volume: u32) -> usize {
        if let Some(index) = self.index.get(&snapshot.name) {
            return *index;
        }
        let index = self.members.len();
        self.members.push(StoredMember {
            name: snapshot.name.clone(),
            first_volume: volume,
            unpacked_size: None,
            data_crc32: None,
            data_blake2_hash: None,
            parts: Vec::new(),
            chain_complete: false,
            eligibility: MemberEligibility::ProvisionallyDirect,
        });
        self.traits.push(MemberTraits::default());
        self.index.insert(snapshot.name.clone(), index);
        index
    }

    /// Fold one header's disqualifying facts into the member's running traits.
    fn absorb_traits(&mut self, member_index: usize, snapshot: &MemberSnapshot) {
        let traits = &mut self.traits[member_index];
        traits.encrypted |= snapshot.is_encrypted;
        traits.solid |= snapshot.is_solid;
        traits.directory |= snapshot.is_directory;
        traits.redirection |= snapshot.is_redirection;
        traits.compressed |= !snapshot.is_store;
    }

    fn member_spans(&self, member_index: usize, volume: u32) -> bool {
        let parts = &self.members[member_index].parts;
        match (parts.first(), parts.last()) {
            (Some(first), Some(last)) => first.volume <= volume && volume <= last.volume,
            _ => false,
        }
    }

    fn advance_frontier(&mut self) {
        if !self.volumes.contains_key(&0) {
            return;
        }
        let mut frontier = self.frontier.unwrap_or(0);
        while let Some(next) = frontier.checked_add(1) {
            if !self.volumes.contains_key(&next) {
                break;
            }
            frontier = next;
        }
        self.frontier = Some(frontier);
    }

    /// Re-derive one member's logical offsets, completeness and classification.
    fn resolve_member(&mut self, member_index: usize) {
        let mut parts = std::mem::take(&mut self.members[member_index].parts);

        // A logical offset is the prefix sum of the earlier parts, so it exists
        // only from a known first part and only across an unbroken run.
        let head_known = parts.first().is_some_and(|part| !part.split_before);
        let mut running = head_known.then_some(0u64);
        let mut expected_volume = parts.first().map_or(0, |part| part.volume);
        let mut packed_total = 0u64;
        for part in &mut parts {
            if part.volume != expected_volume {
                running = None;
            }
            part.logical_offset = running;
            running = running.map(|value| value.saturating_add(part.data_size));
            expected_volume = part.volume.saturating_add(1);
            packed_total = packed_total.saturating_add(part.data_size);
        }

        let chain_complete =
            running.is_some() && parts.last().is_some_and(|part| !part.split_after);
        let traits = self.traits[member_index];
        let malformed = traits.malformed.or_else(|| self.chain_malformation(&parts));
        let eligibility = classify(
            traits,
            malformed,
            chain_complete,
            packed_total,
            self.members[member_index].unpacked_size,
            self.members[member_index].data_crc32,
            self.members[member_index].data_blake2_hash,
        );

        let member = &mut self.members[member_index];
        member.eligibility = eligibility;
        member.chain_complete = chain_complete;
        member.parts = parts;
    }

    /// Structural violations a chain proves once enough volumes are present.
    fn chain_malformation(&self, parts: &[StoredMemberPart]) -> Option<MalformedReason> {
        let last_position = parts.len().checked_sub(1)?;
        for (position, part) in parts.iter().enumerate() {
            if !part.split_before && position != 0 {
                return Some(MalformedReason::UnexpectedChainStart {
                    volume: part.volume,
                });
            }
            if !part.split_after && position != last_position {
                return Some(MalformedReason::UnexpectedChainEnd {
                    volume: part.volume,
                });
            }
        }

        let first = parts.first()?;
        if first.split_before && first.volume == 0 {
            return Some(MalformedReason::ContinuationInFirstVolume);
        }

        // A hole is only provably wrong once the volume that should have filled
        // it has been added and turned out to carry nothing for this member.
        let mut expected_volume = first.volume;
        for part in parts {
            while expected_volume < part.volume {
                if self.volumes.contains_key(&expected_volume) {
                    return Some(MalformedReason::MissingPartInAddedVolume {
                        volume: expected_volume,
                    });
                }
                expected_volume += 1;
            }
            expected_volume = part.volume.saturating_add(1);
        }

        None
    }
}

/// Append a slice, merging it into a same-kind run where that is meaningful.
fn push_slice(slices: &mut Vec<MappedSlice>, slice: MappedSlice) {
    match (slices.last_mut(), slice) {
        (Some(MappedSlice::Envelope { len }), MappedSlice::Envelope { len: extra })
        | (Some(MappedSlice::Unroutable { len }), MappedSlice::Unroutable { len: extra }) => {
            *len = len.saturating_add(extra);
        }
        _ => slices.push(slice),
    }
}

/// Classify a member from its accumulated facts.
///
/// The order is deliberate: a fact that rules out any handling is reported
/// ahead of one a caller might tolerate, so an encrypted or solid member never
/// presents itself as merely compressed.
#[allow(clippy::too_many_arguments)]
fn classify(
    traits: MemberTraits,
    malformed: Option<MalformedReason>,
    chain_complete: bool,
    packed_total: u64,
    unpacked_size: Option<u64>,
    data_crc32: Option<u32>,
    data_blake2_hash: Option<[u8; 32]>,
) -> MemberEligibility {
    use IneligibilityReason as Reason;

    if let Some(reason) = malformed {
        return MemberEligibility::Ineligible(Reason::MalformedChain(reason));
    }
    if traits.directory {
        return MemberEligibility::Ineligible(Reason::Directory);
    }
    if traits.redirection {
        return MemberEligibility::Ineligible(Reason::Redirection);
    }
    if traits.encrypted {
        return MemberEligibility::Ineligible(Reason::Encrypted);
    }
    if traits.solid {
        return MemberEligibility::Ineligible(Reason::Solid);
    }
    if traits.compressed {
        return MemberEligibility::Ineligible(Reason::Compressed {
            packed_bytes: packed_total,
            unpacked_bytes: unpacked_size.unwrap_or(0),
        });
    }
    if !chain_complete {
        return MemberEligibility::ProvisionallyDirect;
    }

    let Some(unpacked_size) = unpacked_size else {
        return MemberEligibility::Ineligible(Reason::MalformedChain(
            MalformedReason::MissingUnpackedSize,
        ));
    };
    // Stored bytes are the member's bytes, so the whole chain must sum to the
    // declared size. Never checked per part: only the sum is meaningful.
    if packed_total != unpacked_size {
        return MemberEligibility::Ineligible(Reason::MalformedChain(
            MalformedReason::SizeMismatch {
                packed_total,
                unpacked_size,
            },
        ));
    }

    match (data_crc32, data_blake2_hash) {
        (Some(_), _) => MemberEligibility::DirectEligible,
        (None, Some(_)) => MemberEligibility::Ineligible(Reason::Blake2OnlyNoCrc32),
        (None, None) => MemberEligibility::Ineligible(Reason::NoChecksum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::RarArchive;

    const EPISODE: &str = "Silver.Horizon.S01E01.mkv";
    const EXTRA: &str = "Silver.Horizon.S01E01.nfo";

    /// A stored, unsplit, unencrypted member with no checksum yet.
    fn member(name: &str, data_offset: u64, data_size: u64) -> RarVolumeMemberFacts {
        RarVolumeMemberFacts {
            order: 0,
            name: name.to_string(),
            name_raw: None,
            unpacked_size: Some(data_size),
            data_crc32: None,
            data_blake2_hash: None,
            version: None,
            packed_crc32: None,
            packed_blake2_hash: None,
            packed_hash_uses_mac: false,
            split_before: false,
            split_after: false,
            is_directory: false,
            is_encrypted: false,
            host_os: None,
            attributes: None,
            owner: None,
            mtime_ns: None,
            ctime_ns: None,
            atime_ns: None,
            data_offset,
            data_size,
            compression_method: CompressionMethod::Store.code(),
            compression_version: 5,
            compression_solid: false,
            dict_size: 0,
            use_hash_mac: false,
            redirection_type: None,
            redirection_target: None,
            redirection_target_raw: None,
            redirection_target_is_directory: false,
        }
    }

    /// One part of a member split across volumes. `unpacked_size` is the whole
    /// member's size, exactly as every split header states it.
    fn split_part(
        name: &str,
        data_offset: u64,
        data_size: u64,
        unpacked_size: u64,
        split_before: bool,
        split_after: bool,
    ) -> RarVolumeMemberFacts {
        let mut facts = member(name, data_offset, data_size);
        facts.unpacked_size = Some(unpacked_size);
        facts.split_before = split_before;
        facts.split_after = split_after;
        if split_after {
            facts.packed_crc32 = Some(0xC0DE_0000 + data_size as u32);
        }
        facts
    }

    fn with_crc32(mut facts: RarVolumeMemberFacts, crc32: u32) -> RarVolumeMemberFacts {
        facts.data_crc32 = Some(crc32);
        facts
    }

    fn volume(members: Vec<RarVolumeMemberFacts>) -> RarVolumeFacts {
        RarVolumeFacts {
            format: 5,
            volume_number: 0,
            more_volumes: false,
            is_solid: false,
            is_encrypted: false,
            is_volume: true,
            has_recovery_record: false,
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            members,
            services: Vec::new(),
        }
    }

    fn layout() -> StoredLayoutBuilder {
        StoredLayoutBuilder::new(ArchiveFormat::Rar5)
    }

    fn add(builder: &mut StoredLayoutBuilder, number: u32, facts: &RarVolumeFacts) {
        builder.add_volume(number, facts).expect("volume accepted");
    }

    fn ineligible(builder: &StoredLayoutBuilder, index: usize) -> IneligibilityReason {
        match builder.members()[index].eligibility {
            MemberEligibility::Ineligible(reason) => reason,
            other => panic!("expected an ineligible member, got {other:?}"),
        }
    }

    #[test]
    fn unsplit_store_member_is_direct_eligible_and_maps_around_the_envelope() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![with_crc32(member(EPISODE, 100, 64), 0x1234_5678)]),
        );

        let member = &builder.members()[0];
        assert_eq!(member.name, EPISODE);
        assert_eq!(member.first_volume, 0);
        assert!(member.chain_complete);
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        assert_eq!(member.parts[0].logical_offset, Some(0));
        assert_eq!(member.data_crc32, Some(0x1234_5678));
        assert_eq!(builder.header_frontier(), Some(0));

        assert_eq!(
            builder.map_physical_range(0, 0, 200),
            vec![
                MappedSlice::Envelope { len: 100 },
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 0,
                    len: 64,
                },
                MappedSlice::Envelope { len: 36 },
            ]
        );
        assert!(builder.map_physical_range(0, 0, 0).is_empty());
    }

    #[test]
    fn member_split_across_three_volumes_resolves_prefix_sums() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 44, 20, 60, true, true)]),
        );
        add(
            &mut builder,
            2,
            &volume(vec![with_crc32(
                split_part(EPISODE, 48, 30, 60, true, false),
                0xFEED_BEEF,
            )]),
        );

        let member = &builder.members()[0];
        assert_eq!(member.parts.len(), 3);
        assert_eq!(
            member
                .parts
                .iter()
                .map(|part| part.logical_offset)
                .collect::<Vec<_>>(),
            vec![Some(0), Some(10), Some(30)]
        );
        assert!(member.chain_complete);
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        // Whole-member checksums come from the final part only.
        assert_eq!(member.data_crc32, Some(0xFEED_BEEF));
        assert!(member.parts[0].packed_crc32.is_some());
        assert!(member.parts[1].packed_crc32.is_some());
        assert_eq!(member.parts[2].packed_crc32, None);

        assert_eq!(
            builder.map_physical_range(1, 44, 20),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 10,
                len: 20,
            }]
        );
        // A range starting mid-part keeps the logical offset in step.
        assert_eq!(
            builder.map_physical_range(2, 60, 30),
            vec![
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 42,
                    len: 18,
                },
                MappedSlice::Envelope { len: 12 },
            ]
        );
    }

    #[test]
    fn split_member_stays_provisional_until_its_final_header_arrives() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );

        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::ProvisionallyDirect
        );
        assert!(!builder.members()[0].chain_complete);
        // Provisional members still route: the chain closing is what decides
        // whether they stay direct.
        assert_eq!(
            builder.map_physical_range(0, 40, 10),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 0,
                len: 10,
            }]
        );
    }

    #[test]
    fn long_chain_routes_only_behind_the_header_frontier() {
        const VOLUMES: u32 = 64;
        const PART: u64 = 1024;
        const HEADER: u64 = 96;

        let mut builder = layout();
        for number in 0..VOLUMES {
            let part = split_part(
                EPISODE,
                HEADER,
                PART,
                PART * u64::from(VOLUMES),
                number > 0,
                number + 1 < VOLUMES,
            );
            let facts = volume(vec![if number + 1 == VOLUMES {
                with_crc32(part, 0x0BAD_F00D)
            } else {
                part
            }]);
            // Payload for a volume not yet added is not placeable at all.
            assert_eq!(
                builder.map_physical_range(number, HEADER, PART),
                vec![MappedSlice::Unroutable { len: PART }]
            );

            add(&mut builder, number, &facts);

            assert_eq!(builder.header_frontier(), Some(number));
            assert_eq!(
                builder.map_physical_range(number, HEADER, PART),
                vec![MappedSlice::Member {
                    member_index: 0,
                    logical_offset: PART * u64::from(number),
                    len: PART,
                }]
            );
        }

        let member = &builder.members()[0];
        assert_eq!(member.parts.len(), VOLUMES as usize);
        for (position, part) in member.parts.iter().enumerate() {
            assert_eq!(part.logical_offset, Some(PART * position as u64));
        }
    }

    #[test]
    fn long_chain_added_out_of_order_resolves_when_the_gap_closes() {
        const VOLUMES: u32 = 52;
        const PART: u64 = 512;
        const HEADER: u64 = 64;

        let total = PART * u64::from(VOLUMES);
        let facts_for = |number: u32| {
            let part = split_part(
                EPISODE,
                HEADER,
                PART,
                total,
                number > 0,
                number + 1 < VOLUMES,
            );
            let part = if number + 1 == VOLUMES {
                with_crc32(part, 0x0BAD_F00D)
            } else {
                part
            };
            volume(vec![part])
        };

        // Everything except volume 1, newest first.
        let mut builder = layout();
        for number in (0..VOLUMES).rev() {
            if number == 1 {
                continue;
            }
            add(&mut builder, number, &facts_for(number));
        }

        assert_eq!(builder.header_frontier(), Some(0));
        assert_eq!(builder.members()[0].parts[0].logical_offset, Some(0));
        assert!(
            builder.members()[0].parts[1..]
                .iter()
                .all(|part| part.logical_offset.is_none()),
            "no part past the hole can know where it starts"
        );
        assert_eq!(
            builder.map_physical_range(2, HEADER, PART),
            vec![MappedSlice::Unroutable { len: PART }]
        );

        add(&mut builder, 1, &facts_for(1));

        assert_eq!(builder.header_frontier(), Some(VOLUMES - 1));
        let member = &builder.members()[0];
        for (position, part) in member.parts.iter().enumerate() {
            assert_eq!(part.logical_offset, Some(PART * position as u64));
        }
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        assert_eq!(
            builder.map_physical_range(2, HEADER, PART),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: PART * 2,
                len: PART,
            }]
        );
    }

    #[test]
    fn multiple_members_in_one_volume_map_across_their_boundaries() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 50, 100), 0x1111_1111),
                with_crc32(member(EXTRA, 170, 30), 0x2222_2222),
            ]),
        );

        // A span straddling the first member's tail, the header gap and the
        // second member's head.
        assert_eq!(
            builder.map_physical_range(0, 120, 70),
            vec![
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 70,
                    len: 30,
                },
                MappedSlice::Envelope { len: 20 },
                MappedSlice::Member {
                    member_index: 1,
                    logical_offset: 0,
                    len: 20,
                },
            ]
        );
        // A whole-volume span covers both members and every envelope run.
        assert_eq!(
            builder.map_physical_range(0, 0, 220),
            vec![
                MappedSlice::Envelope { len: 50 },
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 0,
                    len: 100,
                },
                MappedSlice::Envelope { len: 20 },
                MappedSlice::Member {
                    member_index: 1,
                    logical_offset: 0,
                    len: 30,
                },
                MappedSlice::Envelope { len: 20 },
            ]
        );
        // A span wholly inside one member stays one slice.
        assert_eq!(
            builder.map_physical_range(0, 60, 10),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 10,
                len: 10,
            }]
        );
    }

    #[test]
    fn an_ineligible_member_routes_its_packed_bytes_into_the_envelope() {
        let mut compressed = member(EXTRA, 170, 30);
        compressed.compression_method = CompressionMethod::Normal.code();
        compressed.unpacked_size = Some(90);

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 50, 100), 0x1111_1111),
                with_crc32(compressed, 0x2222_2222),
            ]),
        );

        assert_eq!(
            ineligible(&builder, 1),
            IneligibilityReason::Compressed {
                packed_bytes: 30,
                unpacked_bytes: 90,
            }
        );
        // The gap, the compressed member's packed bytes and the trailing gap
        // are one envelope run.
        assert_eq!(
            builder.map_physical_range(0, 150, 60),
            vec![MappedSlice::Envelope { len: 60 }]
        );
    }

    #[test]
    fn missing_middle_volume_is_malformed_once_that_volume_arrives() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            2,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 30, 60, true, false),
                0xFEED_BEEF,
            )]),
        );
        // A hole is not yet a fault: volume 1 simply has not been seen.
        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::ProvisionallyDirect
        );

        add(&mut builder, 1, &volume(vec![member(EXTRA, 40, 20)]));

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::MissingPartInAddedVolume {
                volume: 1,
            })
        );
        // Malformed members take the envelope path rather than panicking.
        assert_eq!(
            builder.map_physical_range(0, 40, 10),
            vec![MappedSlice::Envelope { len: 10 }]
        );
    }

    #[test]
    fn continuation_in_the_first_volume_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, true, true)]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ContinuationInFirstVolume)
        );
    }

    #[test]
    fn a_second_chain_start_inside_a_member_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 40, 50, 60, false, false)]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::UnexpectedChainStart {
                volume: 1,
            })
        );
    }

    #[test]
    fn a_completed_chain_whose_parts_do_not_sum_to_the_member_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 20, 60, true, false),
                0xFEED_BEEF,
            )]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::SizeMismatch {
                packed_total: 30,
                unpacked_size: 60,
            })
        );
    }

    #[test]
    fn duplicate_member_name_in_one_volume_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 40, 10), 0x1111_1111),
                with_crc32(member(EPISODE, 60, 10), 0x2222_2222),
            ]),
        );

        assert_eq!(builder.members().len(), 1);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::DuplicatePartInVolume {
                volume: 0,
            })
        );
    }

    #[test]
    fn re_adding_a_volume_is_idempotent_but_conflicting_facts_are_rejected() {
        let facts = volume(vec![with_crc32(member(EPISODE, 100, 64), 0x1234_5678)]);
        let mut builder = layout();
        add(&mut builder, 0, &facts);
        add(&mut builder, 0, &facts);

        assert_eq!(builder.members().len(), 1);
        assert_eq!(builder.members()[0].parts.len(), 1);

        let conflicting = volume(vec![with_crc32(member(EPISODE, 100, 65), 0x1234_5678)]);
        assert_eq!(
            builder.add_volume(0, &conflicting),
            Err(StoredLayoutError::ConflictingVolume { volume: 0 })
        );
        assert_eq!(builder.members()[0].parts[0].data_size, 64);
    }

    #[test]
    fn a_volume_from_another_format_is_rejected() {
        let mut facts = volume(vec![member(EPISODE, 100, 64)]);
        facts.format = 4;

        let mut builder = layout();
        assert_eq!(
            builder.add_volume(0, &facts),
            Err(StoredLayoutError::FormatMismatch {
                expected: ArchiveFormat::Rar5,
                found: ArchiveFormat::Rar4,
            })
        );
        assert!(!builder.has_volume(0));
    }

    #[test]
    fn a_split_part_keeps_both_packed_checksums() {
        let mut head = split_part(EPISODE, 40, 10, 30, false, true);
        head.packed_crc32 = Some(0xAAAA_BBBB);
        head.packed_blake2_hash = Some([0x5A; 32]);

        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![head]));

        let part = &builder.members()[0].parts[0];
        assert_eq!(part.packed_crc32, Some(0xAAAA_BBBB));
        assert_eq!(part.packed_blake2_hash, Some([0x5A; 32]));
    }

    #[test]
    fn a_blake2_only_stored_member_is_not_direct_eligible() {
        let mut blake2_only = member(EPISODE, 40, 10);
        blake2_only.data_blake2_hash = Some([0x11; 32]);

        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![blake2_only]));

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::Blake2OnlyNoCrc32
        );
    }

    #[test]
    fn a_stored_member_with_no_checksum_is_not_direct_eligible() {
        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![member(EPISODE, 40, 10)]));

        assert_eq!(ineligible(&builder, 0), IneligibilityReason::NoChecksum);
    }

    #[test]
    fn per_member_solid_rejects_while_an_archive_solid_store_set_passes() {
        let mut solid_member = with_crc32(member(EPISODE, 40, 10), 0x1111_1111);
        solid_member.compression_solid = true;
        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![solid_member]));
        assert_eq!(ineligible(&builder, 0), IneligibilityReason::Solid);

        // The archive-level solid flag does not disqualify store members.
        let mut archive_solid = volume(vec![with_crc32(member(EPISODE, 40, 10), 0x1111_1111)]);
        archive_solid.is_solid = true;
        let mut builder = layout();
        add(&mut builder, 0, &archive_solid);
        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::DirectEligible
        );
    }

    #[test]
    fn directory_redirection_and_encrypted_members_are_rejected() {
        let mut directory = with_crc32(member("Silver.Horizon.S01", 40, 0), 0);
        directory.is_directory = true;

        let mut redirection = with_crc32(member("Silver.Horizon.S01E01.link", 40, 12), 0x3333);
        redirection.redirection_type = Some(1);
        redirection.redirection_target = Some(EPISODE.to_string());

        let mut encrypted = with_crc32(member(EPISODE, 60, 10), 0x4444);
        encrypted.is_encrypted = true;

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![directory, redirection, encrypted]),
        );

        assert_eq!(ineligible(&builder, 0), IneligibilityReason::Directory);
        assert_eq!(ineligible(&builder, 1), IneligibilityReason::Redirection);
        assert_eq!(ineligible(&builder, 2), IneligibilityReason::Encrypted);
    }

    #[test]
    fn split_evidence_lists_only_the_names_that_link_volumes() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EXTRA, 40, 10), 0x1111_1111),
                split_part(EPISODE, 60, 10, 30, false, true),
            ]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 20, 30, true, false),
                0x2222_2222,
            )]),
        );

        let first = builder.split_evidence(0).expect("volume 0 evidence");
        assert!(first.continued_from_previous.is_empty());
        assert_eq!(first.continues_into_next, vec![EPISODE.to_string()]);

        let second = builder.split_evidence(1).expect("volume 1 evidence");
        assert_eq!(second.continued_from_previous, vec![EPISODE.to_string()]);
        assert!(second.continues_into_next.is_empty());

        assert!(builder.split_evidence(2).is_none());
    }

    #[test]
    fn rar5_multi_volume_store_fixture_builds_a_direct_layout() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5");
        let volumes: Vec<std::path::PathBuf> = (1..=5)
            .map(|part| fixtures.join(format!("rar5_mv_store.part{part}.rar")))
            .collect();
        if volumes.iter().any(|path| !path.exists()) {
            eprintln!("skipping test: rar5_mv_store fixtures not present");
            return;
        }

        let mut builder = layout();
        for (number, path) in volumes.iter().enumerate() {
            let facts = RarArchive::parse_volume_facts(std::fs::File::open(path).unwrap(), None)
                .expect("fixture volume facts");
            builder
                .add_volume(number as u32, &facts)
                .expect("fixture volume accepted");
        }

        assert_eq!(builder.header_frontier(), Some(4));
        let direct: Vec<&StoredMember> = builder
            .members()
            .iter()
            .filter(|member| member.eligibility == MemberEligibility::DirectEligible)
            .collect();
        assert!(
            !direct.is_empty(),
            "a plain multi-volume store set should yield direct members"
        );
        assert!(
            direct.iter().any(|member| member.parts.len() > 1),
            "the fixture set should exercise a member split across volumes"
        );

        for member in direct {
            assert!(member.chain_complete);
            assert_eq!(member.parts[0].logical_offset, Some(0));
            let mut running = 0u64;
            for part in &member.parts {
                assert_eq!(part.logical_offset, Some(running));
                running += part.data_size;
            }
            assert_eq!(Some(running), member.unpacked_size);
            assert!(member.data_crc32.is_some());

            // Every part's packed range maps back to that part's logical span.
            for (position, part) in member.parts.iter().enumerate() {
                if part.data_size == 0 {
                    continue;
                }
                let index = builder
                    .members()
                    .iter()
                    .position(|candidate| candidate.name == member.name)
                    .unwrap();
                assert_eq!(
                    builder.map_physical_range(part.volume, part.data_offset, part.data_size),
                    vec![MappedSlice::Member {
                        member_index: index,
                        logical_offset: part.logical_offset.unwrap(),
                        len: part.data_size,
                    }],
                    "part {position} of {}",
                    member.name
                );
            }
        }
    }
}
