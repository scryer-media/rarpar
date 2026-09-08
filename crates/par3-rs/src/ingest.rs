//! Incremental, authenticated packet ingestion without retaining payload bytes.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::packet::{HEADER_SIZE, PacketHeader, PacketType, ParseContext};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};
use crate::{
    Fingerprint, FingerprintHasher, InputSetId, Packet, Par3Error, Par3Set, ScanLimits, SetLimits,
};

/// Meaning of a lazy packet's data bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// Original input block stored inside a PAR3 carrier.
    Data {
        /// Logical input block index.
        index: u64,
    },
    /// Recovery equation bound to a root and matrix.
    Recovery {
        /// Root packet fingerprint.
        root: Fingerprint,
        /// Matrix packet fingerprint.
        matrix: Fingerprint,
        /// Recovery block index, global across cohorts.
        index: u64,
    },
}

/// An authenticated packet payload that remains in a source owned by the caller.
///
/// Construction is private: an unchecked header cannot create a usable payload.
/// Reads check the original generation, and `validate` rechecks packet contents.
#[derive(Clone)]
pub struct PayloadRef {
    access: Arc<dyn SourceAccess>,
    source: SourceId,
    snapshot: SourceSnapshot,
    packet_offset: u64,
    header: PacketHeader,
    data_offset: u64,
    kind: PayloadKind,
    reservation: Arc<Reservation>,
}

impl std::fmt::Debug for PayloadRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadRef")
            .field("source", &self.source)
            .field("packet_offset", &self.packet_offset)
            .field("kind", &self.kind)
            .finish()
    }
}

impl PayloadRef {
    /// Semantic identity of the payload.
    #[must_use]
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }

    /// Input set named by the authenticated header.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        self.header.input_set_id
    }

    /// Packet fingerprint, suitable for detecting replay.
    #[must_use]
    pub fn packet_hash(&self) -> Fingerprint {
        self.header.hash
    }

    /// Number of stored payload bytes, excluding the header and identity fields.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.packet_offset + self.header.length - self.data_offset
    }

    /// Whether the packet represents only implicit zero padding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a payload range without allocation. Trailing trimmed bytes are not
    /// padded here: only the codec knows the logical block size.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> EngineResult<usize> {
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        let take = self.len().saturating_sub(offset).min(out.len() as u64) as usize;
        if take != 0 {
            read_exact_at(
                self.access.as_ref(),
                self.source,
                self.data_offset + offset,
                &mut out[..take],
            )?;
        }
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        Ok(take)
    }

    /// Reauthenticate the entire packet immediately before consuming it for a
    /// repair. A stat fingerprint alone is not cryptographic evidence.
    pub fn validate(&self, options: &ExecutionOptions) -> EngineResult<()> {
        options.validate()?;
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        let size = options.stripe_bytes.min(64 << 10);
        let _buffer_reservation = options.memory.reserve(size)?;
        let mut buffer = vec![0; size];
        let mut hash = FingerprintHasher::new();
        let mut offset = 24;
        while offset < self.header.length {
            options.cancel.check()?;
            let take = (self.header.length - offset).min(size as u64) as usize;
            read_exact_at(
                self.access.as_ref(),
                self.source,
                self.packet_offset + offset,
                &mut buffer[..take],
            )?;
            hash.update(&buffer[..take]);
            offset += take as u64;
        }
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        if hash.finalize() != self.header.hash {
            return Err(Par3Error::PacketHashMismatch {
                offset: self.packet_offset,
            }
            .into());
        }
        Ok(())
    }
}

/// A fully authenticated metadata packet or a lazy payload.
#[derive(Clone, Debug)]
pub struct IngestedPacket {
    contents: IngestedContents,
    origin: PacketOrigin,
}

/// Original carrier coordinates retained alongside an authenticated packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketOrigin {
    /// Caller-supplied source identity.
    pub source: SourceId,
    /// Immutable source generation and length.
    pub snapshot: SourceSnapshot,
    /// Start of this packet, in carrier coordinates.
    pub offset: u64,
    /// Complete authenticated packet length.
    pub length: u64,
    provider: ProviderIdentity,
}

impl PacketOrigin {
    /// Whether coordinates refer to the same provider, source and generation.
    /// Equal caller-supplied numeric identities in different providers do not
    /// establish that two packets came from the same carrier.
    pub fn same_carrier(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self.source == other.source
            && self.snapshot == other.snapshot
    }
}

#[derive(Clone)]
struct ProviderIdentity(Arc<dyn SourceAccess>);
impl PartialEq for ProviderIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ProviderIdentity {}
impl std::fmt::Debug for ProviderIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SourceProvider")
    }
}

#[derive(Clone, Debug)]
enum IngestedContents {
    Metadata(Arc<Packet>, Arc<Reservation>),
    Payload(Arc<PayloadRef>),
}

impl IngestedPacket {
    /// Authenticated packet's original carrier coordinates.
    #[must_use]
    pub fn origin(&self) -> PacketOrigin {
        self.origin.clone()
    }

    /// Borrow metadata, if this packet is not a payload.
    #[must_use]
    pub fn metadata(&self) -> Option<&Packet> {
        match &self.contents {
            IngestedContents::Metadata(packet, _) => Some(packet),
            _ => None,
        }
    }

    /// Borrow a lazy payload.
    #[must_use]
    pub fn payload(&self) -> Option<&PayloadRef> {
        match &self.contents {
            IngestedContents::Payload(payload) => Some(payload),
            _ => None,
        }
    }

    /// Input set identifier.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        match &self.contents {
            IngestedContents::Metadata(packet, _) => packet.input_set_id(),
            IngestedContents::Payload(payload) => payload.input_set_id(),
        }
    }

    /// Authenticated packet fingerprint.
    #[must_use]
    pub fn hash(&self) -> Fingerprint {
        match &self.contents {
            IngestedContents::Metadata(packet, _) => packet.hash(),
            IngestedContents::Payload(payload) => payload.packet_hash(),
        }
    }

    pub(crate) fn rehome(&mut self, options: &ExecutionOptions) -> EngineResult<()> {
        if let IngestedContents::Payload(payload) = &self.contents
            && payload.reservation.belongs_to(&options.memory)
        {
            return Ok(());
        }
        let reservation = match &mut self.contents {
            IngestedContents::Metadata(_, reservation) => reservation,
            IngestedContents::Payload(payload) => &mut Arc::make_mut(payload).reservation,
        };
        if !reservation.belongs_to(&options.memory) {
            *reservation = Arc::new(options.memory.reserve(reservation.bytes())?);
        }
        Ok(())
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        match &self.contents {
            IngestedContents::Metadata(packet, reservation) => {
                let _ = reservation;
                (packet.len() as usize)
                    .saturating_mul(4)
                    .saturating_add(512)
            }
            IngestedContents::Payload(payload) => {
                let _ = &payload.reservation;
                512
            }
        }
    }
}

/// Result of one scanner poll. Only `Packet` is usable evidence.
#[derive(Debug)]
pub enum ScanEvent {
    /// Next authenticated packet.
    Packet(IngestedPacket),
    /// A range must arrive before this candidate can be authenticated.
    NeedData {
        /// First unavailable byte.
        offset: u64,
    },
    /// The scanner reached the source's logical end.
    End,
}

struct Candidate {
    header: PacketHeader,
    offset: u64,
    consumed: u64,
    hash: FingerprintHasher,
    retained: Vec<u8>,
    prefix: [u8; 40],
    prefix_len: usize,
    reservation: Reservation,
}

/// A resumable scanner for one carrier and immutable content generation.
///
/// Repeated `poll` calls preserve the packet hash frontier across partial
/// arrivals. A hole returns `NeedData`; use `seek` to scan a later available
/// range and a separate scanner to revisit the hole later. Neither operation
/// assumes that holes contain zero bytes.
pub struct PacketScanner {
    access: Arc<dyn SourceAccess>,
    source: SourceId,
    snapshot: SourceSnapshot,
    offset: u64,
    candidate: Option<Candidate>,
    at_packet_boundary: bool,
    options: ExecutionOptions,
    limits: ScanLimits,
    failed_hash_bytes: u64,
    packets: usize,
    buffer: Vec<u8>,
    _buffer_reservation: Reservation,
}

impl PacketScanner {
    /// Open a source without reading its payload. Allocation is budgeted first.
    pub fn new(
        access: Arc<dyn SourceAccess>,
        source: SourceId,
        options: ExecutionOptions,
        limits: ScanLimits,
    ) -> EngineResult<Self> {
        options.validate()?;
        let snapshot = access.snapshot(source)?.ok_or(EngineError::Unavailable {
            source_id: source,
            offset: 0,
        })?;
        let size = options.stripe_bytes.clamp(HEADER_SIZE, 64 << 10);
        let reservation = options.memory.reserve(size)?;
        Ok(Self {
            access,
            source,
            snapshot,
            offset: 0,
            candidate: None,
            at_packet_boundary: false,
            options,
            limits,
            failed_hash_bytes: 0,
            packets: 0,
            buffer: vec![0; size],
            _buffer_reservation: reservation,
        })
    }

    /// Resume searching at an explicit byte offset, discarding a pending hash.
    /// Hash-work and packet-count budgets remain cumulative.
    pub fn seek(&mut self, offset: u64) -> EngineResult<()> {
        if offset > self.snapshot.len {
            return Err(EngineError::InvalidState("scan seek beyond source"));
        }
        self.offset = offset;
        self.candidate = None;
        self.at_packet_boundary = false;
        Ok(())
    }

    /// Position after the last packet, or at the current candidate header.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.offset
    }

    /// Return one packet, a missing-byte boundary, or the logical end.
    pub fn poll(&mut self) -> EngineResult<ScanEvent> {
        loop {
            self.options.cancel.check()?;
            ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
            if self.candidate.is_none() {
                if self.offset >= self.snapshot.len {
                    return Ok(ScanEvent::End);
                }
                let search_size = if self.at_packet_boundary {
                    HEADER_SIZE
                } else {
                    self.buffer.len()
                };
                self.at_packet_boundary = false;
                let take = (self.snapshot.len - self.offset).min(search_size as u64) as usize;
                if take < 8 {
                    self.offset = self.snapshot.len;
                    return Ok(ScanEvent::End);
                }
                let mut read = 0;
                while read < 8 {
                    self.options.scan_work.charge(take - read)?;
                    let count = self.access.read_at(
                        self.source,
                        self.offset + read as u64,
                        &mut self.buffer[read..take],
                    )?;
                    if count > take - read {
                        return Err(EngineError::InvalidState("invalid source read length"));
                    }
                    if count == 0 {
                        return Ok(ScanEvent::NeedData {
                            offset: self.offset + read as u64,
                        });
                    }
                    read += count;
                }
                let Some(found) = self.buffer[..read]
                    .windows(8)
                    .position(|bytes| bytes == crate::MAGIC)
                else {
                    self.offset += (read - 7) as u64;
                    continue;
                };
                self.offset += found as u64;
                if self.snapshot.len - self.offset < HEADER_SIZE as u64 {
                    self.offset = self.snapshot.len;
                    return Ok(ScanEvent::End);
                }
                let mut header_bytes = [0; HEADER_SIZE];
                let mut header_read = (read - found).min(HEADER_SIZE);
                header_bytes[..header_read]
                    .copy_from_slice(&self.buffer[found..found + header_read]);
                while header_read < HEADER_SIZE {
                    self.options.cancel.check()?;
                    self.options.scan_work.charge(HEADER_SIZE - header_read)?;
                    let count = self.access.read_at(
                        self.source,
                        self.offset + header_read as u64,
                        &mut header_bytes[header_read..],
                    )?;
                    if count > HEADER_SIZE - header_read {
                        return Err(EngineError::InvalidState("invalid source read length"));
                    }
                    if count == 0 {
                        return Ok(ScanEvent::NeedData {
                            offset: self.offset + header_read as u64,
                        });
                    }
                    header_read += count;
                }
                let header = match PacketHeader::parse(&header_bytes, self.offset) {
                    Ok(header)
                        if header.length <= self.limits.max_packet_len
                            && header.length <= self.snapshot.len - self.offset =>
                    {
                        header
                    }
                    _ => {
                        self.offset += 8;
                        continue;
                    }
                };
                let prefix_len = match header.packet_type {
                    PacketType::Data => 8,
                    PacketType::RecoveryData => 40,
                    _ => 0,
                };
                if header.length < (HEADER_SIZE + prefix_len) as u64 {
                    self.offset += 8;
                    continue;
                }
                let retained_len = if prefix_len == 0 {
                    usize::try_from(header.length)
                        .map_err(|_| EngineError::ResourceLimit("metadata packet size"))?
                } else {
                    0
                };
                let cost = retained_len
                    .checked_mul(4)
                    .and_then(|size| size.checked_add(512))
                    .ok_or(EngineError::ResourceLimit("metadata packet size"))?;
                if cost > self.options.retained_bytes
                    || cost as u64 > self.limits.max_retained_bytes
                {
                    return Err(EngineError::ResourceLimit("metadata packet retention"));
                }
                let reservation = self.options.memory.reserve(cost)?;
                let mut retained = Vec::with_capacity(retained_len);
                if prefix_len == 0 {
                    retained.extend_from_slice(&header_bytes);
                }
                let mut hash = FingerprintHasher::new();
                hash.update(&header_bytes[24..]);
                self.candidate = Some(Candidate {
                    header,
                    offset: self.offset,
                    consumed: HEADER_SIZE as u64,
                    hash,
                    retained,
                    prefix: [0; 40],
                    prefix_len,
                    reservation,
                });
            }

            let candidate = self.candidate.as_mut().expect("candidate initialized");
            while candidate.consumed < candidate.header.length {
                self.options.cancel.check()?;
                let take = (candidate.header.length - candidate.consumed)
                    .min(self.buffer.len() as u64) as usize;
                self.options.scan_work.charge(take)?;
                let read = self.access.read_at(
                    self.source,
                    candidate.offset + candidate.consumed,
                    &mut self.buffer[..take],
                )?;
                if read == 0 {
                    return Ok(ScanEvent::NeedData {
                        offset: candidate.offset + candidate.consumed,
                    });
                }
                if read > take {
                    return Err(EngineError::InvalidState("invalid source read length"));
                }
                candidate.hash.update(&self.buffer[..read]);
                if candidate.prefix_len == 0 {
                    candidate.retained.extend_from_slice(&self.buffer[..read]);
                } else {
                    let prefix_start = (candidate.consumed - HEADER_SIZE as u64)
                        .min(candidate.prefix_len as u64)
                        as usize;
                    let prefix_take = read.min(candidate.prefix_len - prefix_start);
                    candidate.prefix[prefix_start..prefix_start + prefix_take]
                        .copy_from_slice(&self.buffer[..prefix_take]);
                }
                candidate.consumed += read as u64;
            }
            ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
            let candidate = self.candidate.take().expect("candidate present");
            if candidate.hash.finalize() != candidate.header.hash {
                self.failed_hash_bytes = self
                    .failed_hash_bytes
                    .saturating_add(candidate.header.length);
                if self.failed_hash_bytes
                    > self
                        .snapshot
                        .len
                        .saturating_mul(self.limits.max_failed_hash_passes)
                {
                    return Err(EngineError::ResourceLimit("failed packet hashing work"));
                }
                self.offset = candidate.offset + 8;
                continue;
            }
            if self.packets >= self.limits.max_packets {
                return Err(EngineError::ResourceLimit("packet count"));
            }
            self.packets += 1;
            self.offset = candidate.offset + candidate.header.length;
            self.at_packet_boundary = true;
            let contents = if candidate.prefix_len == 0 {
                let packet =
                    Packet::parse(&candidate.retained, candidate.offset, &ParseContext::new())?;
                IngestedContents::Metadata(Arc::new(packet), Arc::new(candidate.reservation))
            } else {
                let kind = if candidate.prefix_len == 8 {
                    PayloadKind::Data {
                        index: u64::from_le_bytes(
                            candidate.prefix[..8].try_into().expect("eight bytes"),
                        ),
                    }
                } else {
                    PayloadKind::Recovery {
                        root: candidate.prefix[..16].try_into().expect("fingerprint"),
                        matrix: candidate.prefix[16..32].try_into().expect("fingerprint"),
                        index: u64::from_le_bytes(
                            candidate.prefix[32..40].try_into().expect("eight bytes"),
                        ),
                    }
                };
                IngestedContents::Payload(Arc::new(PayloadRef {
                    access: Arc::clone(&self.access),
                    source: self.source,
                    snapshot: self.snapshot,
                    packet_offset: candidate.offset,
                    data_offset: candidate.offset
                        + HEADER_SIZE as u64
                        + candidate.prefix_len as u64,
                    header: candidate.header,
                    kind,
                    reservation: Arc::new(candidate.reservation),
                }))
            };
            return Ok(ScanEvent::Packet(IngestedPacket {
                contents,
                origin: PacketOrigin {
                    provider: ProviderIdentity(self.access.clone()),
                    source: self.source,
                    snapshot: self.snapshot,
                    offset: candidate.offset,
                    length: self.offset - candidate.offset,
                },
            }));
        }
    }
}

/// Effect of admitting an authenticated packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeEffect {
    /// Already present; retained analysis remains valid.
    Replay,
    /// Only data/recovery availability changed.
    Payload,
    /// Metadata changed; a retained layout must be rebuilt.
    Metadata,
}

/// Incremental input-set assembly with payloads kept outside the metadata tree.
pub struct IncrementalSet {
    id: InputSetId,
    packets: BTreeMap<Fingerprint, IngestedPacket>,
    retained: usize,
    options: ExecutionOptions,
}

impl IncrementalSet {
    /// Start collecting a named input set.
    pub fn new(id: InputSetId, options: ExecutionOptions) -> EngineResult<Self> {
        options.validate()?;
        Ok(Self {
            id,
            packets: BTreeMap::new(),
            retained: 0,
            options,
        })
    }

    /// Admit one authenticated packet, deduplicating by fingerprint.
    pub fn merge(&mut self, mut packet: IngestedPacket) -> EngineResult<MergeEffect> {
        self.options.cancel.check()?;
        if packet.input_set_id() != self.id {
            return Err(EngineError::InvalidState(
                "packet belongs to another input set",
            ));
        }
        if let Some(previous) = self.packets.get(&packet.hash()) {
            if let Some(payload) = previous.payload()
                && payload.access.snapshot(payload.source)? != Some(payload.snapshot)
            {
                packet.rehome(&self.options)?;
                self.packets.insert(packet.hash(), packet);
                return Ok(MergeEffect::Payload);
            }
            return Ok(MergeEffect::Replay);
        }
        let retained = self
            .retained
            .checked_add(packet.retained_bytes())
            .ok_or(EngineError::ResourceLimit("retained metadata"))?;
        if retained > self.options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained metadata"));
        }
        packet.rehome(&self.options)?;
        let effect = if packet.payload().is_some() {
            MergeEffect::Payload
        } else {
            MergeEffect::Metadata
        };
        self.packets.insert(packet.hash(), packet);
        self.retained = retained;
        Ok(effect)
    }

    pub(crate) fn contains(&self, hash: &Fingerprint) -> bool {
        self.packets.contains_key(hash)
    }

    /// Forget lazy payloads whose published source generation disappeared or
    /// changed. Authenticated metadata is self-contained and remains usable.
    /// This checks source snapshots without reading carrier or protected bytes.
    pub fn discard_changed_payloads(&mut self) -> EngineResult<usize> {
        self.options.cancel.check()?;
        let mut removed = 0;
        let mut failure = None;
        self.packets.retain(|_, packet| {
            let Some(payload) = packet.payload() else {
                return true;
            };
            match payload.access.snapshot(payload.source) {
                Ok(snapshot) if snapshot != Some(payload.snapshot) => {
                    self.retained -= packet.retained_bytes();
                    removed += 1;
                    false
                }
                Err(error) => {
                    failure = Some(error);
                    true
                }
                _ => true,
            }
        });
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(removed)
    }

    /// Resolve metadata when Start, Root and all referenced children are present.
    /// `None` means more metadata is needed, rather than a malformed set.
    pub fn metadata(&self) -> EngineResult<Option<Par3Set>> {
        self.options.cancel.check()?;
        // Admission reserved four times each packet's wire size for the parsed
        // packet, its clone during resolution, and the resolved metadata tree.
        let packets = self
            .packets
            .values()
            .filter_map(IngestedPacket::metadata)
            .cloned()
            .collect();
        let limits = SetLimits {
            max_entries: (self.options.retained_bytes / 1024).min(SetLimits::DEFAULT_MAX_ENTRIES),
            max_path_bytes: (self.options.retained_bytes / 8) as u64,
            ..SetLimits::default()
        };
        match Par3Set::from_packets_for_with_limits(packets, self.id, &limits) {
            Ok(set) => Ok(Some(set)),
            Err(
                Par3Error::MissingStartPacket { .. }
                | Par3Error::MissingRootPacket { .. }
                | Par3Error::MissingChildPacket { .. }
                | Par3Error::UnknownInputSet { .. },
            ) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Lazy payloads, including arrivals whose root or matrix has not arrived.
    pub fn payloads(&self) -> impl Iterator<Item = &PayloadRef> {
        self.packets.values().filter_map(IngestedPacket::payload)
    }

    /// All authenticated packets, for carrier reconstruction or inspection.
    pub fn packets(&self) -> impl Iterator<Item = &IngestedPacket> {
        self.packets.values()
    }

    /// Conservatively accounted retained bytes.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
}
