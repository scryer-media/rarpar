//! Incremental, authenticated packet ingestion without retaining payload bytes.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::packet::{HEADER_SIZE, PacketHeader, PacketType, ParseContext, btree_entry_bytes};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};
use crate::set::{ExpansionCharge, RESOLUTION_BASE_BYTES, resolution_cost};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};
use crate::{
    Fingerprint, FingerprintHasher, InputSetId, Packet, Par3Error, Par3Set, ScanLimits, SetLimits,
};

/// Bytes charged for one retained packet beyond the bytes it holds: its own
/// value, the map entry that indexes it, and its carrier origin.
const PACKET_OVERHEAD_BYTES: usize = 512;

/// Granule the directory walk's charges are batched into, so that resolving a
/// tree of many small entries does not take one atomic round trip per entry.
const EXPANSION_GRANULE_BYTES: usize = 64 * 1024;

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
    diagnostics: crate::runtime::ExecutionDiagnostics,
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
    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.access, &other.access)
            && self.source == other.source
            && self.snapshot == other.snapshot
            && self.packet_offset == other.packet_offset
            && self.header.hash == other.header.hash
    }
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
                &self.diagnostics,
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
        let _buffer_reservation = options
            .memory
            .reserve_as(MemoryCategory::CarrierPackets, size)?;
        let mut buffer = vec![0; size];
        let mut hash = FingerprintHasher::new();
        let mut offset = 24;
        while offset < self.header.length {
            options.cancel.check()?;
            let take = (self.header.length - offset).min(size as u64) as usize;
            read_exact_at(
                &options.diagnostics,
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
            *reservation = Arc::new(
                options
                    .memory
                    .reserve_as(reservation.category(), reservation.bytes())?,
            );
        }
        Ok(())
    }

    /// Bytes this packet keeps alive, measured from the structures that exist:
    /// the parsed body's own container capacities plus the fixed cost of the
    /// map entry and carrier origin that index it.
    pub(crate) fn retained_bytes(&self) -> usize {
        let indexed = size_of::<Self>()
            .saturating_add(btree_entry_bytes::<Fingerprint, Self>())
            .saturating_add(PACKET_OVERHEAD_BYTES);
        match &self.contents {
            IngestedContents::Metadata(packet, _) => packet.owned_bytes().saturating_add(indexed),
            IngestedContents::Payload(_) => size_of::<PayloadRef>().saturating_add(indexed),
        }
    }
}

/// Charges the directory walk's allocations to a live reservation.
///
/// The walk is the only part of resolution whose size is not a function of its
/// input, so it is the only part that pays as it goes. Charges are batched into
/// granules so a tree of many small entries does not cost one atomic round trip
/// per entry, and a refusal is stashed so the caller can report the measured
/// ceiling rather than the walk's own structural limit message.
struct BudgetCharge<'a> {
    reservation: &'a mut Reservation,
    /// Expansion room this walk would have if nothing else held the budget.
    /// This is the ceiling a refusal is classified against: a walk that does
    /// not fit here does not fit alone either, so waiting cannot admit it.
    ceiling: usize,
    /// Expansion room actually left when the walk started, after peers and this
    /// session's own earlier reservations. Reported as what was available, and
    /// never used to decide whether the walk can ever fit.
    headroom: usize,
    taken: usize,
    pending: usize,
    failure: Option<EngineError>,
}

impl BudgetCharge<'_> {
    fn flush(&mut self) -> Result<(), Par3Error> {
        let bytes = std::mem::take(&mut self.pending);
        if bytes == 0 {
            return Ok(());
        }
        let next = self.taken.saturating_add(bytes);
        let refuse = |this: &mut Self, error: EngineError| {
            this.failure = Some(error);
            Par3Error::ScanLimitExceeded {
                reason: "resolving this input set needs more memory than the budget allows"
                    .to_owned(),
            }
        };
        // Only the uncontended ceiling decides whether this walk can ever fit.
        // Measuring against the contended headroom would report a walk that
        // fits alone as terminal the moment a peer happens to hold memory.
        if next > self.ceiling {
            let error = EngineError::budget_limit(
                "metadata expansion",
                next,
                self.ceiling,
                self.headroom.saturating_sub(self.taken),
            );
            return Err(refuse(self, error));
        }
        // Inside the ceiling, the budget itself is the authority on whether the
        // bytes are there right now, and its refusal already carries the shape.
        if let Err(error) = self.reservation.grow_by(bytes) {
            return Err(refuse(self, error));
        }
        self.taken = next;
        Ok(())
    }
}

impl ExpansionCharge for BudgetCharge<'_> {
    fn charge(&mut self, bytes: usize) -> Result<(), Par3Error> {
        self.pending = self.pending.saturating_add(bytes);
        if self.pending < EXPANSION_GRANULE_BYTES {
            return Ok(());
        }
        self.flush()
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

struct ScanReadAhead {
    bytes: Vec<u8>,
    offset: u64,
    len: usize,
}

impl ScanReadAhead {
    fn read_at(
        &mut self,
        access: &dyn SourceAccess,
        source: SourceId,
        source_len: u64,
        offset: u64,
        out: &mut [u8],
        options: &ExecutionOptions,
    ) -> EngineResult<usize> {
        if offset < self.offset || offset - self.offset >= self.len as u64 {
            self.len = 0;
            let take = source_len
                .saturating_sub(offset)
                .min(self.bytes.len() as u64) as usize;
            options.scan_work.charge(take)?;
            let read =
                options
                    .diagnostics
                    .read_at(access, source, offset, &mut self.bytes[..take])?;
            if read > take {
                return Err(EngineError::InvalidState("invalid source read length"));
            }
            self.offset = offset;
            self.len = read;
        }
        let start = (offset - self.offset) as usize;
        let take = out.len().min(self.len - start);
        out[..take].copy_from_slice(&self.bytes[start..start + take]);
        Ok(take)
    }
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
/// A budgeted read-ahead stripe reuses bytes across packet boundaries. Seeking
/// discards it; every poll still checks the source generation. The scanner
/// reserves two stripes of at most 64 KiB each. A provider may also pin a
/// budgeted handle for the scanner and its authenticated packets' lifetime.
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
    read_ahead: ScanReadAhead,
    _buffer_reservation: Reservation,
}

impl PacketScanner {
    /// Open a source, using a provider's immutable view when available. Pinning
    /// may read the source once; the provider must charge that work to options.
    pub fn new(
        access: Arc<dyn SourceAccess>,
        source: SourceId,
        options: ExecutionOptions,
        limits: ScanLimits,
    ) -> EngineResult<Self> {
        options.validate()?;
        let access = access.pin(source, &options)?.unwrap_or(access);
        let snapshot = access.snapshot(source)?.ok_or(EngineError::Unavailable {
            source_id: source,
            offset: 0,
        })?;
        let size = options.stripe_bytes.clamp(HEADER_SIZE, 64 << 10);
        let reservation = options
            .memory
            .reserve_as(MemoryCategory::CarrierPackets, size * 2)?;
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
            read_ahead: ScanReadAhead {
                bytes: vec![0; size],
                offset: 0,
                len: 0,
            },
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
        self.read_ahead.len = 0;
        Ok(())
    }

    /// Position after the last packet, or at the current candidate header.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.offset
    }

    /// Return one packet, a missing-byte boundary, or the logical end.
    pub fn poll(&mut self) -> EngineResult<ScanEvent> {
        let mut progress = self.options.stage(crate::runtime::Stage::Scan)?;
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
                    let count = self.read_ahead.read_at(
                        self.access.as_ref(),
                        self.source,
                        self.snapshot.len,
                        self.offset + read as u64,
                        &mut self.buffer[read..take],
                        &self.options,
                    )?;
                    progress.advance(count as u64);
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
                    let count = self.read_ahead.read_at(
                        self.access.as_ref(),
                        self.source,
                        self.snapshot.len,
                        self.offset + header_read as u64,
                        &mut header_bytes[header_read..],
                        &self.options,
                    )?;
                    progress.advance(count as u64);
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
                        .map_err(|_| EngineError::resource_limit("metadata packet size"))?
                } else {
                    0
                };
                // Charge the bytes actually about to be allocated: the carrier
                // copy this scanner buffers, plus the fixed per-packet
                // bookkeeping. The parsed body is measured and the charge
                // resized once the packet authenticates.
                let cost = retained_len
                    .checked_add(PACKET_OVERHEAD_BYTES)
                    .ok_or(EngineError::resource_limit("metadata packet size"))?;
                let retention_ceiling = self
                    .options
                    .retained_bytes
                    .min(usize::try_from(self.limits.max_retained_bytes).unwrap_or(usize::MAX));
                if cost > retention_ceiling {
                    return Err(EngineError::budget_limit(
                        "metadata packet retention",
                        cost,
                        retention_ceiling,
                        retention_ceiling,
                    ));
                }
                let reservation = self
                    .options
                    .memory
                    .reserve_as(MemoryCategory::CarrierPackets, cost)?;
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
                let read = self.read_ahead.read_at(
                    self.access.as_ref(),
                    self.source,
                    self.snapshot.len,
                    candidate.offset + candidate.consumed,
                    &mut self.buffer[..take],
                    &self.options,
                )?;
                progress.advance(read as u64);
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
                    return Err(EngineError::resource_limit("failed packet hashing work"));
                }
                self.offset = candidate.offset + 8;
                continue;
            }
            if self.packets >= self.limits.max_packets {
                return Err(EngineError::resource_limit("packet count"));
            }
            self.packets += 1;
            self.offset = candidate.offset + candidate.header.length;
            self.at_packet_boundary = true;
            let mut reservation = candidate.reservation;
            let retained = candidate.retained;
            let contents = if candidate.prefix_len == 0 {
                let packet = Packet::parse(&retained, candidate.offset, &ParseContext::new())?;
                // The carrier copy and the parsed body overlap until the copy is
                // dropped, so cover both before releasing down to what survives.
                let owned = packet
                    .owned_bytes()
                    .saturating_add(PACKET_OVERHEAD_BYTES)
                    .min(isize::MAX as usize);
                if let Some(growth) = owned.checked_sub(reservation.bytes()) {
                    reservation.grow_by(growth)?;
                }
                drop(retained);
                reservation.shrink_to(owned);
                IngestedContents::Metadata(Arc::new(packet), Arc::new(reservation))
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
                    diagnostics: self.options.diagnostics.clone(),
                    access: Arc::clone(&self.access),
                    source: self.source,
                    snapshot: self.snapshot,
                    packet_offset: candidate.offset,
                    data_offset: candidate.offset
                        + HEADER_SIZE as u64
                        + candidate.prefix_len as u64,
                    header: candidate.header,
                    kind,
                    reservation: Arc::new(reservation),
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
                && !payload
                    .access
                    .snapshot(payload.source)
                    .is_ok_and(|current| current == Some(payload.snapshot))
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
            .ok_or(EngineError::resource_limit("retained metadata"))?;
        if retained > self.options.retained_bytes {
            // `retained_bytes` is this session's own ceiling: nobody else draws
            // on it and it only grows, so waiting never admits the packet. The
            // demand reported is the session total under that ceiling, not this
            // packet's increment, or the refusal would read as contention.
            return Err(EngineError::budget_limit(
                "retained metadata",
                retained,
                self.options.retained_bytes,
                self.options.retained_bytes.saturating_sub(self.retained),
            ));
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

    pub(crate) fn packet(&self, hash: &Fingerprint) -> Option<&IngestedPacket> {
        self.packets.get(hash)
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
    /// Construction is budgeted; the returned convenience value is caller-owned.
    /// Retained sessions keep the separate resolved-tree reservation internally.
    pub fn metadata(&self) -> EngineResult<Option<Par3Set>> {
        self.metadata_accounted(self.options.retained_bytes.saturating_sub(self.retained))
            .map(|value| value.map(|(set, _reservation)| set))
    }

    pub(crate) fn metadata_accounted(
        &self,
        retained_limit: usize,
    ) -> EngineResult<Option<(Par3Set, Reservation)>> {
        let _progress = self.options.stage(crate::runtime::Stage::Metadata)?;
        use crate::packet::PacketBody;
        let mut has_start = false;
        let mut has_root = false;
        // What resolution allocates before the tree is walked: one clone of each
        // retained body plus the maps that index them, measured from the
        // packets that exist rather than from a multiple of their wire length.
        let mut working = RESOLUTION_BASE_BYTES;
        let mut entry_cost = 1024usize;
        for packet in self.packets.values().filter_map(IngestedPacket::metadata) {
            self.options.cancel.check()?;
            has_start |= matches!(packet.body(), PacketBody::Start(_));
            has_root |= matches!(packet.body(), PacketBody::Root(_));
            let cost = resolution_cost(packet);
            working = working
                .checked_add(cost)
                .ok_or(EngineError::resource_limit("resolved metadata"))?;
            if matches!(
                packet.body(),
                PacketBody::File(_) | PacketBody::Directory(_)
            ) {
                entry_cost = entry_cost.max(cost);
            }
        }
        if !has_start || !has_root {
            return Ok(None);
        }

        // Only the working set is reserved up front. Everything the directory
        // walk materialises is charged as it is materialised, so a set that
        // resolves small is never asked to fit the whole retained ceiling.
        let available = self.options.memory.available();
        let ceiling = retained_limit.min(available);
        // The same ceiling computed as if this session were alone on the budget.
        // Every refusal below is classified against this figure rather than the
        // contended one: a set that resolves alone must never be reported as
        // terminal merely because a peer holds memory at this instant.
        let uncontended = retained_limit.min(self.options.memory.limit());
        let Some(extra) = ceiling.checked_sub(working) else {
            return Err(EngineError::budget_limit(
                "resolved metadata",
                working,
                uncontended,
                available,
            ));
        };
        let mut reservation = self
            .options
            .memory
            .reserve_as(MemoryCategory::ResolvedMetadata, working)?;

        // Split the expansion headroom between owned entry descriptions and the
        // path text they carry, exactly as the pre-reserved ceiling did.
        let limits = SetLimits {
            max_entries: (extra / 2 / entry_cost).min(SetLimits::DEFAULT_MAX_ENTRIES),
            max_path_bytes: (extra / 8) as u64,
            ..SetLimits::default()
        };
        let packets = self
            .packets
            .values()
            .filter_map(IngestedPacket::metadata)
            .cloned()
            .collect();

        let mut charge = BudgetCharge {
            reservation: &mut reservation,
            ceiling: uncontended.saturating_sub(working),
            headroom: extra,
            taken: 0,
            pending: 0,
            failure: None,
        };
        let mut resolved =
            Par3Set::from_packets_for_charged(packets, self.id, &limits, &mut charge);
        if resolved.is_ok()
            && let Err(error) = charge.flush()
        {
            resolved = Err(error);
        }
        let refusal = charge.failure.take();
        drop(charge);

        match resolved {
            Ok(set) => {
                // What survives resolution is the set itself: the working copies
                // and index maps are already gone. Charge its real capacity.
                let actual = set
                    .retained_capacity_bytes()
                    .checked_add(RESOLUTION_BASE_BYTES)
                    .ok_or(EngineError::resource_limit("resolved metadata accounting"))?;
                if actual > retained_limit {
                    return Err(EngineError::budget_limit(
                        "resolved metadata",
                        actual,
                        uncontended,
                        available,
                    ));
                }
                if let Some(growth) = actual.checked_sub(reservation.bytes()) {
                    reservation.grow_by(growth)?;
                } else {
                    reservation.shrink_to(actual);
                }
                Ok(Some((set, reservation)))
            }
            Err(
                Par3Error::MissingStartPacket { .. }
                | Par3Error::MissingRootPacket { .. }
                | Par3Error::MissingChildPacket { .. }
                | Par3Error::UnknownInputSet { .. },
            ) => Ok(None),
            Err(Par3Error::ScanLimitExceeded { .. }) => Err(refusal.unwrap_or_else(|| {
                // The walk stopped on a structural bound derived from `extra`,
                // which means it needs strictly more room than it was given but
                // stops before it can say how much more. Report it as a total
                // demand against the uncontended resolution ceiling: when the
                // walk already had that whole ceiling nothing can release to
                // grow it, so name one byte past it and the refusal reads as
                // terminal; otherwise the difference is held by someone else
                // and releasing it admits this same walk.
                let need = if ceiling < uncontended {
                    ceiling
                } else {
                    uncontended.saturating_add(1)
                };
                EngineError::budget_limit("metadata expansion", need, uncontended, ceiling)
            })),
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

#[cfg(test)]
mod charge_classification_tests {
    //! The directory walk is charged against two different ceilings, and which
    //! one a refusal names decides whether a host retries or fails the job.
    //! `BudgetCharge` is private, so these drive it directly rather than trying
    //! to steer a whole resolution onto the branch under test.
    use super::{BudgetCharge, EXPANSION_GRANULE_BYTES, ExpansionCharge};
    use crate::runtime::{EngineError, LimitCause, MemoryBudget, MemoryCategory};

    #[test]
    fn a_walk_that_fits_alone_is_retryable_when_something_else_holds_the_budget() {
        let budget = MemoryBudget::new(1 << 20);
        let mut reservation = budget
            .reserve_as(MemoryCategory::ResolvedMetadata, 4096)
            .unwrap();
        // Everything but a sliver is spoken for, so the walk cannot take the
        // bytes now even though the ceiling it is measured against has room.
        let peer = budget
            .reserve_as(MemoryCategory::Caches, budget.available() - 4096)
            .unwrap();
        let mut charge = BudgetCharge {
            reservation: &mut reservation,
            ceiling: 512 << 10,
            headroom: 8192,
            taken: 0,
            pending: 0,
            failure: None,
        };
        charge
            .charge(EXPANSION_GRANULE_BYTES)
            .expect_err("the budget has no room for a granule");
        let failure = charge.failure.take().expect("a refusal is recorded");
        let EngineError::ResourceLimit(limit) = failure else {
            panic!("expected a measured resource limit: {failure:?}");
        };
        assert_eq!(
            limit.cause(),
            LimitCause::PeerContention,
            "this walk fits the uncontended ceiling, so waiting admits it: {limit}"
        );
        drop(peer);
    }

    #[test]
    fn a_walk_that_outgrows_the_uncontended_ceiling_is_terminal() {
        let budget = MemoryBudget::new(1 << 20);
        let mut reservation = budget
            .reserve_as(MemoryCategory::ResolvedMetadata, 4096)
            .unwrap();
        let mut charge = BudgetCharge {
            reservation: &mut reservation,
            ceiling: EXPANSION_GRANULE_BYTES / 2,
            headroom: EXPANSION_GRANULE_BYTES / 2,
            taken: 0,
            pending: 0,
            failure: None,
        };
        charge
            .charge(EXPANSION_GRANULE_BYTES)
            .expect_err("the walk wants more than it could ever have");
        let failure = charge.failure.take().expect("a refusal is recorded");
        let EngineError::ResourceLimit(limit) = failure else {
            panic!("expected a measured resource limit: {failure:?}");
        };
        assert_eq!(limit.what, "metadata expansion");
        assert_eq!(
            limit.cause(),
            LimitCause::ExceedsLimit,
            "no release can grow the uncontended ceiling: {limit}"
        );
    }
}
