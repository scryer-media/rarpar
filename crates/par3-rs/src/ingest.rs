//! Incremental, authenticated packet ingestion without retaining payload bytes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Whether this payload is read from `source` of `access`.
    pub(crate) fn reads_from(&self, access: &Arc<dyn SourceAccess>, source: SourceId) -> bool {
        Arc::ptr_eq(&self.access, access) && self.source == source
    }

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

    /// Complete on-carrier packet length, header included.
    ///
    /// This is the work a reauthentication costs, and what a failed one is
    /// charged against [`IncrementalSet::failed_hash_bytes`].
    #[must_use]
    pub fn packet_length(&self) -> u64 {
        self.header.length
    }

    /// Whether the packet represents only implicit zero padding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a payload range without allocation. Trailing trimmed bytes are not
    /// padded here: only the codec knows the logical block size.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> EngineResult<usize> {
        let take = self.len().saturating_sub(offset).min(out.len() as u64) as usize;
        // Only the check after the read makes the bytes trustworthy. A read
        // that fails is checked too, so a changed carrier still reports the
        // change rather than whatever the read ran into.
        if take != 0
            && let Err(error) = read_exact_at(
                &self.diagnostics,
                self.access.as_ref(),
                self.source,
                self.data_offset + offset,
                &mut out[..take],
            )
        {
            ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
            return Err(error);
        }
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        Ok(take)
    }

    /// Reauthenticate the entire packet immediately before consuming it for a
    /// repair. A stat fingerprint alone is not cryptographic evidence.
    pub fn validate(&self, options: &ExecutionOptions) -> EngineResult<()> {
        self.reauthenticate(options).map_err(|(error, _)| error)
    }

    /// [`Self::validate`], saying also whether a whole hashing pass was spent
    /// before the failure.
    ///
    /// The two are not the same cost. A generation that has already changed
    /// when the check starts costs one `snapshot` call; a carrier rewritten
    /// *under* the read costs the whole packet, read and hashed and thrown
    /// away, which is exactly the work [`IncrementalSet::failed_hash_bytes`]
    /// exists to report. Only the caller holds that counter, so the
    /// distinction is carried out to it rather than decided here.
    pub(crate) fn reauthenticate(
        &self,
        options: &ExecutionOptions,
    ) -> Result<(), (EngineError, bool)> {
        options.validate().map_err(|error| (error, false))?;
        let size = options.stripe_bytes.min(64 << 10);
        let _buffer_reservation = options
            .memory
            .reserve_as(MemoryCategory::CarrierPackets, size)
            .map_err(|error| (error, false))?;
        self.reauthenticate_in(options, &mut vec![0; size])
    }

    /// [`Self::reauthenticate`] through a buffer the caller already holds, so
    /// a codec whose stripes took the budget can still authenticate a payload
    /// before it uses it. The packet is read in `buffer`-sized pieces, and
    /// `buffer` holds nothing useful afterwards.
    pub(crate) fn reauthenticate_in(
        &self,
        options: &ExecutionOptions,
        buffer: &mut [u8],
    ) -> Result<(), (EngineError, bool)> {
        let spent = |error: EngineError| (error, false);
        options.validate().map_err(spent)?;
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot).map_err(spent)?;
        if buffer.is_empty() {
            return Err(spent(EngineError::InvalidState(
                "empty reauthentication buffer",
            )));
        }
        let size = buffer.len();
        let mut hash = FingerprintHasher::new();
        let mut offset = 24;
        while offset < self.header.length {
            options.cancel.check().map_err(spent)?;
            let take = (self.header.length - offset).min(size as u64) as usize;
            read_exact_at(
                &options.diagnostics,
                self.access.as_ref(),
                self.source,
                self.packet_offset + offset,
                &mut buffer[..take],
            )
            .map_err(spent)?;
            hash.update(&buffer[..take]);
            offset += take as u64;
        }
        // Everything from here on has cost a full pass over the packet.
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)
            .map_err(|error| (error, true))?;
        if hash.finalize() != self.header.hash {
            return Err((
                Par3Error::PacketHashMismatch {
                    offset: self.packet_offset,
                }
                .into(),
                true,
            ));
        }
        Ok(())
    }

    /// Read the whole payload into the front of `out`, zero the rest, and
    /// authenticate the packet over the bytes just read: one read in place of
    /// [`Self::reauthenticate`] followed by [`Self::read_at`].
    ///
    /// The packet's header and the identity fields ahead of its payload were
    /// authenticated when it was admitted and are held here; only the payload
    /// is read again, and the hash over the two is the packet's own. The bytes
    /// in `out` are the ones the hash vouched for, so a caller that consumes
    /// them only after this returns `Ok` never uses an unverified byte. `out`
    /// must be at least [`Self::len`] bytes; what it holds after an error is
    /// unspecified. The error carries whether a whole pass was spent, as
    /// [`Self::reauthenticate`]'s does.
    pub(crate) fn read_authenticated(
        &self,
        options: &ExecutionOptions,
        out: &mut [u8],
    ) -> Result<(), (EngineError, bool)> {
        let spent = |error: EngineError| (error, false);
        options.validate().map_err(spent)?;
        let len = usize::try_from(self.len())
            .ok()
            .filter(|len| *len <= out.len())
            .ok_or_else(|| spent(EngineError::InvalidState("payload wider than its buffer")))?;
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot).map_err(spent)?;
        out[len..].fill(0);
        if len != 0 {
            read_exact_at(
                &options.diagnostics,
                self.access.as_ref(),
                self.source,
                self.data_offset,
                &mut out[..len],
            )
            .map_err(spent)?;
        }
        // From here on the payload has been read, as a reauthentication would
        // have read it.
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)
            .map_err(|error| (error, true))?;
        let mut hash = FingerprintHasher::new();
        hash.update(&self.header.length.to_le_bytes());
        hash.update(self.header.input_set_id.as_bytes());
        hash.update(&self.header.packet_type.signature());
        match self.kind {
            PayloadKind::Data { index } => hash.update(&index.to_le_bytes()),
            PayloadKind::Recovery {
                root,
                matrix,
                index,
            } => {
                hash.update(&root);
                hash.update(&matrix);
                hash.update(&index.to_le_bytes());
            }
        }
        hash.update(&out[..len]);
        if hash.finalize() != self.header.hash {
            return Err((
                Par3Error::PacketHashMismatch {
                    offset: self.packet_offset,
                }
                .into(),
                true,
            ));
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
///
/// The batching runs *ahead* of the walk, never behind it. The walk allocates
/// an entry the moment it is charged for it, so a reservation that lagged by up
/// to a granule would let the heap sit a granule over the ceiling the budget
/// believes it is holding the line at. Growth is therefore taken a granule at a
/// time before the charge is acknowledged, and [`Self::flush`] hands back
/// whatever the walk did not use.
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
    /// Bytes the walk has been charged for and that are settled into `taken`.
    taken: usize,
    /// Bytes this charge has grown the reservation by. Never less than
    /// `taken + pending`: that is the whole point of reserving ahead.
    reserved: usize,
    /// Charged bytes not yet settled into `taken`, so the counter moves once a
    /// granule rather than once an entry.
    pending: usize,
    failure: Option<EngineError>,
}

impl BudgetCharge<'_> {
    /// Stash the engine's own refusal and hand the walk its structural one.
    fn refuse(&mut self, error: EngineError) -> Par3Error {
        self.failure = Some(error);
        Par3Error::ScanLimitExceeded {
            reason: "resolving this input set needs more memory than the budget allows".to_owned(),
        }
    }

    /// Grow the reservation until it covers every byte charged so far.
    ///
    /// This runs before a charge is acknowledged, so the walk never allocates
    /// against bytes the budget has not granted. One granule is taken at a
    /// time, which keeps the atomic traffic of a tree of small entries at one
    /// round trip per 64 KiB rather than one per entry.
    fn reserve_ahead(&mut self) -> Result<(), Par3Error> {
        let need = self.taken.saturating_add(self.pending);
        if need <= self.reserved {
            return Ok(());
        }
        // Only the uncontended ceiling decides whether this walk can ever fit.
        // Measuring against the contended headroom would report a walk that
        // fits alone as terminal the moment a peer happens to hold memory.
        if need > self.ceiling {
            let error = EngineError::budget_limit(
                "metadata expansion",
                need,
                self.ceiling,
                self.headroom.saturating_sub(self.taken),
            );
            return Err(self.refuse(error));
        }
        // A granule beyond what is needed, but never beyond the ceiling the
        // refusal above just cleared: reserving ahead must not itself become
        // the thing that refuses a walk that fits.
        let ahead = need
            .saturating_add(EXPANSION_GRANULE_BYTES)
            .min(self.ceiling)
            .max(need);
        let growth = ahead - self.reserved;
        // Inside the ceiling, the budget itself is the authority on whether the
        // bytes are there right now, and its refusal already carries the shape.
        if let Err(error) = self.reservation.grow_by(growth) {
            return Err(self.refuse(error));
        }
        self.reserved = ahead;
        Ok(())
    }

    /// Settle the pending charges and give back what was reserved ahead.
    fn flush(&mut self) -> Result<(), Par3Error> {
        self.reserve_ahead()?;
        self.taken = self.taken.saturating_add(std::mem::take(&mut self.pending));
        if self.reserved > self.taken {
            let slack = self.reserved - self.taken;
            let target = self.reservation.bytes().saturating_sub(slack);
            self.reservation.shrink_to(target);
            self.reserved = self.taken;
        }
        Ok(())
    }
}

impl ExpansionCharge for BudgetCharge<'_> {
    fn charge(&mut self, bytes: usize) -> Result<(), Par3Error> {
        self.pending = self.pending.saturating_add(bytes);
        self.reserve_ahead()?;
        if self.pending >= EXPANSION_GRANULE_BYTES {
            self.taken = self.taken.saturating_add(std::mem::take(&mut self.pending));
        }
        Ok(())
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
    /// The scanner's stripe: the least scanning work one fill is charged,
    /// and the most a fill asks for once the work budget cannot cover more.
    unit: usize,
    offset: u64,
    len: usize,
    /// Bytes have been read from the source since its generation was last
    /// confirmed.
    unchecked: bool,
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
            self.unchecked = true;
            let mut take = source_len
                .saturating_sub(offset)
                .min(self.bytes.len() as u64) as usize;
            // A fill is charged what it asks for, and handed back what a
            // short read did not return beyond one stripe: a whole scan
            // costs its bytes and an empty poll a stripe, whatever the
            // read-ahead's size. A budget too low for a full fill still
            // admits a stripe, as a stripe-sized read-ahead would.
            if take <= self.unit || options.scan_work.charge(take).is_err() {
                take = take.min(self.unit);
                options.scan_work.charge(take)?;
            }
            let read =
                options
                    .diagnostics
                    .read_at(access, source, offset, &mut self.bytes[..take])?;
            if read > take {
                return Err(EngineError::InvalidState("invalid source read length"));
            }
            options
                .scan_work
                .refund(take - read.max(self.unit).min(take));
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

/// A packet whose bytes are read and whose hash has been checked, waiting to
/// be admitted to a budget.
///
/// Authentication and admission are two steps, and only the second can be
/// refused by something that may relent: a budget a peer is holding answers
/// `PeerContention`, which the host is expected to park on and retry. The
/// hasher is gone by then — the bytes are proven — so what is kept here is
/// everything the admission still needs, and the scanner's position is not
/// moved until it succeeds.
struct Authenticated {
    header: PacketHeader,
    offset: u64,
    retained: Vec<u8>,
    prefix: [u8; 40],
    prefix_len: usize,
    reservation: Reservation,
}

/// Why an authenticated packet was not admitted.
enum Admission {
    /// A budget refused it. Nothing about the packet has changed, so it is
    /// handed back to be offered again when the budget relents.
    Refused(EngineError, Box<Authenticated>),
    /// The packet is authenticated but cannot be made into one — a body the
    /// parser rejects. Offering it again would fail the same way, so the scan
    /// counts it and moves past it, as it did before it could retry anything.
    Unusable(EngineError),
}

/// A carrier's packets authenticated from the bytes handed to its file, in the
/// order they are handed to it.
///
/// This makes the checks a [`PacketScanner`] reading the finished file back
/// would make, without the read: every byte belongs to a packet that starts
/// where the previous one ended, whose header parses within the scan limits,
/// names `id` and is long enough for its prefix, whose hash covers its body,
/// and, for metadata, whose body parses. Packet count and metadata retention
/// are held to the same limits and charged to the same budget as a scan. Only
/// bytes the inner writer accepted are authenticated, so what is proven is what
/// was written; whether storage then keeps them is the synchronization
/// barrier's contract and a later verification's question.
///
/// A carrier repeats its metadata. The caller may name the packets it will
/// repeat ([`Self::with_known`]): once a copy of one has been authenticated
/// in full here and found byte-identical to that entry, every later copy is
/// compared against the entry byte for byte instead of being hashed and
/// parsed again. Equal bytes carry the same proof, so the guarantee is
/// unchanged; the bytes still reach the inner writer through the same writes.
pub(crate) struct AuthenticatingWriter<'k, W> {
    inner: W,
    id: InputSetId,
    options: ExecutionOptions,
    limits: ScanLimits,
    written: u64,
    packets: usize,
    /// Offset of the packet after the last authenticated one.
    next_packet: u64,
    header: [u8; HEADER_SIZE],
    header_len: usize,
    packet: Option<WrittenPacket>,
    known: &'k [Vec<u8>],
    /// The known packets by the hash their header claims, each with whether a
    /// copy has been authenticated in full and matched it.
    claimed: BTreeMap<Fingerprint, (usize, bool)>,
    /// Packets proven by comparison rather than by their hash.
    #[cfg(test)]
    compared: usize,
}

struct WrittenPacket {
    header: PacketHeader,
    offset: u64,
    consumed: u64,
    hash: FingerprintHasher,
    /// The whole wire packet, for metadata only; payloads are never retained.
    retained: Option<(Vec<u8>, Reservation)>,
    /// The proven known packet this one is compared against, instead of
    /// being hashed.
    copy_of: Option<usize>,
}

impl<'k, W: std::io::Write> AuthenticatingWriter<'k, W> {
    pub(crate) fn new(inner: W, id: InputSetId, options: ExecutionOptions) -> Self {
        Self {
            inner,
            id,
            options,
            limits: ScanLimits::default(),
            written: 0,
            packets: 0,
            next_packet: 0,
            header: [0; HEADER_SIZE],
            header_len: 0,
            packet: None,
            known: &[],
            claimed: BTreeMap::new(),
            #[cfg(test)]
            compared: 0,
        }
    }

    /// Name the metadata packets the caller will write more than once; see
    /// the type's documentation.
    pub(crate) fn with_known(mut self, known: &'k [Vec<u8>]) -> Self {
        for (index, packet) in known.iter().enumerate() {
            if let Some(hash) = packet.get(8..24) {
                self.claimed
                    .entry(hash.try_into().expect("16 bytes"))
                    .or_insert((index, false));
            }
        }
        self.known = known;
        self
    }

    pub(crate) fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Require exactly `expected` bytes written, every one inside an
    /// authenticated packet.
    pub(crate) fn finish(&self, expected: u64) -> EngineResult<()> {
        if self.written != expected {
            return Err(EngineError::InvalidState("creation size differs from plan"));
        }
        if self.packet.is_some() || self.header_len != 0 {
            return Err(EngineError::InvalidState(
                "staged carrier authentication is incomplete",
            ));
        }
        Ok(())
    }

    fn authenticate(&mut self, mut bytes: &[u8]) -> EngineResult<()> {
        while !bytes.is_empty() {
            let Some(packet) = self.packet.as_mut() else {
                let take = (HEADER_SIZE - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_len += take;
                bytes = &bytes[take..];
                if self.header_len == HEADER_SIZE {
                    self.header_len = 0;
                    self.open_packet()?;
                }
                continue;
            };
            let take = (packet.header.length - packet.consumed).min(bytes.len() as u64) as usize;
            if let Some(index) = packet.copy_of {
                let at = packet.consumed as usize;
                if bytes[..take] != self.known[index][at..at + take] {
                    return Err(EngineError::InvalidState(
                        "staged carrier has unauthenticated bytes",
                    ));
                }
            } else {
                packet.hash.update(&bytes[..take]);
                if let Some((retained, _)) = &mut packet.retained {
                    retained.extend_from_slice(&bytes[..take]);
                }
            }
            packet.consumed += take as u64;
            bytes = &bytes[take..];
            if packet.consumed == packet.header.length {
                self.close_packet()?;
            }
        }
        Ok(())
    }

    fn open_packet(&mut self) -> EngineResult<()> {
        let offset = self.next_packet;
        let unauthenticated = EngineError::InvalidState("staged carrier has unauthenticated bytes");
        let header = match PacketHeader::parse(&self.header, offset) {
            Ok(header)
                if header.length <= self.limits.max_packet_len
                    && header.input_set_id == self.id =>
            {
                header
            }
            _ => return Err(unauthenticated),
        };
        let prefix_len = match header.packet_type {
            PacketType::Data => 8,
            PacketType::RecoveryData => 40,
            _ => 0,
        };
        if header.length < (HEADER_SIZE + prefix_len) as u64 {
            return Err(unauthenticated);
        }
        let empty = header.length == HEADER_SIZE as u64;
        if prefix_len == 0
            && let Some(&(index, true)) = self.claimed.get(&header.hash)
        {
            let known = &self.known[index];
            if known.len() as u64 != header.length || known[..HEADER_SIZE] != self.header {
                return Err(unauthenticated);
            }
            self.packet = Some(WrittenPacket {
                header,
                offset,
                consumed: HEADER_SIZE as u64,
                hash: FingerprintHasher::new(),
                retained: None,
                copy_of: Some(index),
            });
            #[cfg(test)]
            {
                self.compared += 1;
            }
            if empty {
                self.close_packet()?;
            }
            return Ok(());
        }
        let retained = if prefix_len == 0 {
            // The scanner's charge for the wire copy, doubled for the parsed
            // body it builds while the copy is still held.
            let retained_len = usize::try_from(header.length)
                .map_err(|_| EngineError::resource_limit("metadata packet size"))?;
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
            let reservation = self.options.memory.reserve_as(
                MemoryCategory::CarrierPackets,
                cost.checked_mul(2)
                    .ok_or(EngineError::resource_limit("metadata packet size"))?,
            )?;
            let mut retained = Vec::with_capacity(retained_len);
            retained.extend_from_slice(&self.header);
            Some((retained, reservation))
        } else {
            None
        };
        let mut hash = FingerprintHasher::new();
        hash.update(&self.header[24..]);
        self.packet = Some(WrittenPacket {
            header,
            offset,
            consumed: HEADER_SIZE as u64,
            hash,
            retained,
            copy_of: None,
        });
        if empty {
            self.close_packet()?;
        }
        Ok(())
    }

    fn close_packet(&mut self) -> EngineResult<()> {
        let packet = self.packet.take().expect("open packet");
        if packet.copy_of.is_none() && packet.hash.finalize() != packet.header.hash {
            return Err(EngineError::InvalidState(
                "staged carrier has unauthenticated bytes",
            ));
        }
        if self.packets >= self.limits.max_packets {
            return Err(EngineError::resource_limit("packet count"));
        }
        if let Some((retained, _reservation)) = packet.retained {
            Packet::parse(&retained, packet.offset, &ParseContext::new())?;
            if let Some((index, proven)) = self.claimed.get_mut(&packet.header.hash)
                && !*proven
                && self.known[*index] == retained
            {
                *proven = true;
            }
        }
        self.packets += 1;
        self.next_packet = packet.offset + packet.header.length;
        Ok(())
    }
}

impl<W: std::io::Write> std::io::Write for AuthenticatingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.authenticate(&bytes[..written])
            .map_err(EngineError::into_io)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A resumable scanner for one carrier and immutable content generation.
///
/// Repeated `poll` calls preserve the packet hash frontier across partial
/// arrivals. A hole returns `NeedData`; use `seek` to scan a later available
/// range and a separate scanner to revisit the hole later. Neither operation
/// assumes that holes contain zero bytes.
/// A budgeted read-ahead reuses bytes across packet boundaries. Seeking
/// discards it. The source generation is checked before any packet, end or
/// missing-byte boundary is returned, unless no byte has been read since the
/// last check, so packets parsed from bytes already confirmed cost no further
/// check. The scanner reserves a stripe of at most 64 KiB and a read-ahead of
/// at most a mebibyte, no larger than the source; a budget without room for
/// that read-ahead gets a stripe-sized one. A provider may also pin a
/// budgeted handle for the scanner and its authenticated packets' lifetime.
pub struct PacketScanner {
    access: Arc<dyn SourceAccess>,
    source: SourceId,
    snapshot: SourceSnapshot,
    offset: u64,
    candidate: Option<Candidate>,
    /// A packet already proven and waiting on a budget. It holds its wire
    /// bytes and its reservation, so a retry costs nothing but the admission.
    authenticated: Option<Authenticated>,
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
        // The read-ahead is the scan's read size, sized for the source
        // rather than the stripe, so that a carrier on a network mount is
        // not fetched in small requests. A budget without room for it scans
        // with a stripe-sized one instead.
        let ahead = crate::source::sequential_read_bytes(&options, snapshot.len).max(size);
        let wide = match options
            .memory
            .reserve_as(MemoryCategory::CarrierPackets, size + ahead)
        {
            Ok(reservation) if ahead == size || options.memory.available() >= 128 << 10 => {
                Some(reservation)
            }
            Ok(_) | Err(EngineError::ResourceLimit(_)) => None,
            Err(error) => return Err(error),
        };
        let (reservation, ahead) = match wide {
            Some(reservation) => (reservation, ahead),
            None => (
                options
                    .memory
                    .reserve_as(MemoryCategory::CarrierPackets, size * 2)?,
                size,
            ),
        };
        Ok(Self {
            access,
            source,
            snapshot,
            offset: 0,
            candidate: None,
            authenticated: None,
            at_packet_boundary: false,
            options,
            limits,
            failed_hash_bytes: 0,
            packets: 0,
            buffer: vec![0; size],
            read_ahead: ScanReadAhead {
                bytes: vec![0; ahead],
                unit: size,
                offset: 0,
                len: 0,
                unchecked: false,
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
        self.authenticated = None;
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
            // A packet refused by a budget on the last poll is offered again
            // before anything new is read. Its bytes are already proven, so
            // this costs only the admission that failed.
            if self.authenticated.is_some() {
                self.confirm_generation()?;
                let authenticated = self.authenticated.take().expect("pending packet");
                return self.admit(authenticated);
            }
            if self.candidate.is_none() {
                if self.offset >= self.snapshot.len {
                    self.confirm_generation()?;
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
                    self.confirm_generation()?;
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
                        self.confirm_generation()?;
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
                    self.confirm_generation()?;
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
                        self.confirm_generation()?;
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
                    ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
                    self.read_ahead.unchecked = false;
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
            if self.read_ahead.unchecked {
                self.confirm_generation()?;
            }
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
            return self.admit(Authenticated {
                header: candidate.header,
                offset: candidate.offset,
                retained: candidate.retained,
                prefix: candidate.prefix,
                prefix_len: candidate.prefix_len,
                reservation: candidate.reservation,
            });
        }
    }

    /// Fail if the source left the scanned generation. Every byte read before
    /// a successful check is confirmed by it.
    fn confirm_generation(&mut self) -> EngineResult<()> {
        ensure_snapshot(self.access.as_ref(), self.source, self.snapshot)?;
        self.read_ahead.unchecked = false;
        Ok(())
    }

    /// Offer one authenticated packet to the budget, and move the scan past it
    /// only if the budget takes it.
    ///
    /// The count and the offset used to be advanced first, which is fine for
    /// the errors that end a scan but wrong for the one that does not: a
    /// budget a peer is holding answers `PeerContention`, the host parks and
    /// polls again, and the packet the scanner had already stepped over was
    /// never yielded — a set quietly short one packet. Nothing here is
    /// committed until the packet exists.
    fn admit(&mut self, authenticated: Authenticated) -> EngineResult<ScanEvent> {
        if self.packets >= self.limits.max_packets {
            return Err(EngineError::resource_limit("packet count"));
        }
        let offset = authenticated.offset;
        let length = authenticated.header.length;
        let contents = match self.contents_of(authenticated) {
            Ok(contents) => contents,
            Err(Admission::Refused(error, authenticated)) => {
                self.authenticated = Some(*authenticated);
                return Err(error);
            }
            Err(Admission::Unusable(error)) => {
                self.packets += 1;
                self.offset = offset + length;
                self.at_packet_boundary = true;
                return Err(error);
            }
        };
        self.packets += 1;
        self.offset = offset + length;
        self.at_packet_boundary = true;
        Ok(ScanEvent::Packet(IngestedPacket {
            contents,
            origin: PacketOrigin {
                provider: ProviderIdentity(self.access.clone()),
                source: self.source,
                snapshot: self.snapshot,
                offset,
                length,
            },
        }))
    }

    /// Turn an authenticated packet into what the set will hold, reserving what
    /// that costs.
    ///
    /// Every failure hands the packet back intact unless the packet itself is
    /// the problem, so the caller can decide between retrying and stepping
    /// over it.
    fn contents_of(&mut self, authenticated: Authenticated) -> Result<IngestedContents, Admission> {
        let Authenticated {
            header,
            offset,
            retained,
            prefix,
            prefix_len,
            mut reservation,
        } = authenticated;
        if prefix_len == 0 {
            // The carrier copy and the parsed body are live at the same
            // time: `parse` builds the body's owned containers while
            // `retained` still holds the bytes they are read from. Cover
            // both *before* parsing, so a budget that cannot hold the pair
            // refuses at admission rather than after the allocation has
            // already happened.
            //
            // The wire length is a sound bound for the parsed body of every
            // metadata type: each owned field is a copy of a wire range or
            // a fixed-size value taken from one, so no body owns more bytes
            // than the packet it came from. `reservation` already covers
            // the wire copy plus one packet's overhead, so growing it by
            // itself covers the pair. A tighter bound would have to be per
            // type and computed from the same wire bytes, which is what
            // parsing does; there is nothing cheaper to read first.
            if let Err(error) = reservation.grow_by(reservation.bytes()) {
                return Err(Admission::Refused(
                    error,
                    Box::new(Authenticated {
                        header,
                        offset,
                        retained,
                        prefix,
                        prefix_len,
                        reservation,
                    }),
                ));
            }
            let packet = match Packet::parse(&retained, offset, &ParseContext::new()) {
                Ok(packet) => packet,
                Err(error) => return Err(Admission::Unusable(error.into())),
            };
            let owned = packet
                .owned_bytes()
                .saturating_add(PACKET_OVERHEAD_BYTES)
                .min(isize::MAX as usize);
            if let Some(growth) = owned.checked_sub(reservation.bytes()) {
                // The doubled reservation is a bound on this, so it is not
                // expected to be reached; the wire bytes are still held and
                // still charged while it is asked for, so a refusal here can
                // be retried like any other.
                if let Err(error) = reservation.grow_by(growth) {
                    return Err(Admission::Refused(
                        error,
                        Box::new(Authenticated {
                            header,
                            offset,
                            retained,
                            prefix,
                            prefix_len,
                            reservation,
                        }),
                    ));
                }
                drop(retained);
            } else {
                drop(retained);
                reservation.shrink_to(owned);
            }
            Ok(IngestedContents::Metadata(
                Arc::new(packet),
                Arc::new(reservation),
            ))
        } else {
            let kind = if prefix_len == 8 {
                PayloadKind::Data {
                    index: u64::from_le_bytes(prefix[..8].try_into().expect("eight bytes")),
                }
            } else {
                PayloadKind::Recovery {
                    root: prefix[..16].try_into().expect("fingerprint"),
                    matrix: prefix[16..32].try_into().expect("fingerprint"),
                    index: u64::from_le_bytes(prefix[32..40].try_into().expect("eight bytes")),
                }
            };
            Ok(IngestedContents::Payload(Arc::new(PayloadRef {
                diagnostics: self.options.diagnostics.clone(),
                access: Arc::clone(&self.access),
                source: self.source,
                snapshot: self.snapshot,
                packet_offset: offset,
                data_offset: offset + HEADER_SIZE as u64 + prefix_len as u64,
                header,
                kind,
                reservation: Arc::new(reservation),
            })))
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
    /// Monotonic tallies of the work this set threw away. Atomic because a
    /// failed reauthentication is discovered while the set is only borrowed.
    failed_hash_bytes: AtomicU64,
    rejected_packets: AtomicU64,
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
            failed_hash_bytes: AtomicU64::new(0),
            rejected_packets: AtomicU64::new(0),
        })
    }

    /// Admit one authenticated packet, deduplicating by fingerprint.
    ///
    /// Every refusal is counted once on [`Self::rejected_packets`], whatever
    /// its cause, so a host does not have to keep that tally itself.
    pub fn merge(&mut self, packet: IngestedPacket) -> EngineResult<MergeEffect> {
        let outcome = self.merge_admitted(packet);
        if outcome.is_err() {
            self.rejected_packets.fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    fn merge_admitted(&mut self, mut packet: IngestedPacket) -> EngineResult<MergeEffect> {
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

    /// Packet bytes this set hashed and then threw away, because the content
    /// under an authenticated header did not match its fingerprint.
    ///
    /// Monotonic and per set: it counts every reauthentication the engine
    /// performed on this set's payloads and lost, including the same packet
    /// failing again on a later pass, and it is never reset. A non-zero value
    /// means carrier bytes changed or were never what the header claimed; it
    /// is the cost of trusting a carrier, expressed in bytes, and a host can
    /// use it to decide that a source is not worth re-reading.
    ///
    /// Candidates a [`PacketScanner`] rejected before a packet ever reached
    /// this set are not counted here: they never belonged to a set.
    #[must_use]
    pub fn failed_hash_bytes(&self) -> u64 {
        self.failed_hash_bytes.load(Ordering::Relaxed)
    }

    /// Packets this set refused, by any cause: a packet naming another input
    /// set, a retained-metadata ceiling, a memory refusal, a cancellation, or
    /// a failed reauthentication. Monotonic and per set, never reset.
    ///
    /// A replay is not a refusal: admitting the same packet twice succeeds.
    #[must_use]
    pub fn rejected_packets(&self) -> u64 {
        self.rejected_packets.load(Ordering::Relaxed)
    }

    /// Count a packet the session refused before it reached [`Self::merge`],
    /// so one refusal is one rejection however early it happened.
    pub(crate) fn note_rejected(&self) {
        self.rejected_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Reauthenticate a payload drawn from this set, charging a failure to the
    /// set's own tallies. The error itself is returned unchanged.
    ///
    /// Every reauthentication inside the engine goes through here, so the two
    /// counters describe the whole set rather than one call site.
    pub(crate) fn validate_payload(
        &self,
        payload: &PayloadRef,
        options: &ExecutionOptions,
    ) -> EngineResult<()> {
        self.charge(payload, payload.reauthenticate(options))
    }

    /// [`Self::validate_payload`] through a buffer the caller already holds:
    /// see [`PayloadRef::reauthenticate_in`].
    pub(crate) fn validate_payload_in(
        &self,
        payload: &PayloadRef,
        options: &ExecutionOptions,
        buffer: &mut [u8],
    ) -> EngineResult<()> {
        self.charge(payload, payload.reauthenticate_in(options, buffer))
    }

    /// [`Self::validate_payload`] fused with the read that consumes the
    /// payload: see [`PayloadRef::read_authenticated`]. A failure is charged
    /// exactly as a failed reauthentication is.
    pub(crate) fn read_payload(
        &self,
        payload: &PayloadRef,
        options: &ExecutionOptions,
        out: &mut [u8],
    ) -> EngineResult<()> {
        self.charge(payload, payload.read_authenticated(options, out))
    }

    fn charge(
        &self,
        payload: &PayloadRef,
        checked: Result<(), (EngineError, bool)>,
    ) -> EngineResult<()> {
        match checked {
            Ok(()) => Ok(()),
            Err((error, spent)) => {
                // A pass was spent whenever the packet was read and hashed
                // before the refusal, whether the hash disagreed or the carrier
                // was rewritten under the reader. Both are bytes this set paid
                // for and threw away, which is what the counter reports; only
                // a hash that disagreed is a packet this set refused.
                if spent {
                    self.failed_hash_bytes
                        .fetch_add(payload.packet_length(), Ordering::Relaxed);
                }
                if matches!(
                    error,
                    EngineError::Format(crate::Par3Error::PacketHashMismatch { .. })
                ) {
                    self.rejected_packets.fetch_add(1, Ordering::Relaxed);
                }
                Err(error)
            }
        }
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
        // What resolution allocates before the tree is walked: the one copy of
        // each retained body it is handed, which `build` moves into whatever
        // keeps it rather than cloning, plus the maps that index them, measured
        // from the packets that exist rather than from a multiple of their wire
        // length.
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
        //
        // "Alone" means without *peers*, not without this set's own packets:
        // those are already admitted, they are not going to be released by
        // anyone waiting, and a standalone session whose own retained packets
        // fill the ceiling used to be told `PeerContention` — retryable — for a
        // refusal no amount of waiting could ever lift. Its own held bytes come
        // off the ceiling it is measured against, so that refusal now reads as
        // terminal while a peer's bytes still read as contention.
        let uncontended = retained_limit.min(
            self.options
                .memory
                .limit()
                .saturating_sub(self.retained_bytes()),
        );
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
            reserved: 0,
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
            reserved: 0,
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

    /// PR #73 round 3, finding 2. The granule batching used to run *behind* the
    /// walk: `TreeWalk` allocates an entry the moment it is charged for it, and
    /// the reservation only caught up once a granule of charges had piled up,
    /// so the heap sat up to 64 KiB past what the budget believed it was
    /// holding. The reservation now leads the walk, and the final flush gives
    /// back whatever it led by.
    #[test]
    fn the_reservation_is_never_behind_what_the_walk_has_already_allocated() {
        let budget = MemoryBudget::new(1 << 20);
        let mut reservation = budget
            .reserve_as(MemoryCategory::ResolvedMetadata, 0)
            .unwrap();
        assert_eq!(budget.used(), 0, "the walk starts owing nothing");
        let ceiling = 256 << 10;
        let mut charge = BudgetCharge {
            reservation: &mut reservation,
            ceiling,
            headroom: ceiling,
            taken: 0,
            reserved: 0,
            pending: 0,
            failure: None,
        };
        // Entry-sized charges, well under a granule, so the old code would
        // acknowledge thousands of them before growing anything.
        let entry = 96usize;
        let entries = ceiling / entry;
        let mut charged = 0usize;
        for step in 0..entries {
            charge.charge(entry).expect("this walk fits its ceiling");
            charged += entry;
            assert!(
                budget.used() >= charged,
                "entry {step}: the walk has allocated {charged} bytes against {} reserved",
                budget.used()
            );
            assert!(
                budget.used() <= ceiling,
                "entry {step}: reserving ahead overshot the ceiling"
            );
        }
        charge.flush().expect("settles");
        drop(charge);
        assert_eq!(
            reservation.bytes(),
            charged,
            "the slack reserved ahead was not handed back"
        );
        assert_eq!(budget.used(), charged);
    }

    /// The other half: a ceiling one byte under what the walk needs refuses at
    /// the charge that crosses it, and nothing was allocated past the ceiling
    /// on the way there.
    #[test]
    fn a_ceiling_one_byte_short_refuses_before_the_allocation_it_would_cover() {
        let entry = 96usize;
        let entries = 1024usize;
        let budget = MemoryBudget::new(1 << 20);
        let mut reservation = budget
            .reserve_as(MemoryCategory::ResolvedMetadata, 0)
            .unwrap();
        let ceiling = entry * entries - 1;
        let mut charge = BudgetCharge {
            reservation: &mut reservation,
            ceiling,
            headroom: ceiling,
            taken: 0,
            reserved: 0,
            pending: 0,
            failure: None,
        };
        let mut charged = 0usize;
        let mut refused_at = None;
        for step in 0..entries {
            if charge.charge(entry).is_err() {
                refused_at = Some(step);
                break;
            }
            charged += entry;
            assert!(budget.used() >= charged, "entry {step} outran its charge");
            assert!(
                budget.used() <= ceiling,
                "entry {step} overshot the ceiling"
            );
        }
        assert_eq!(
            refused_at,
            Some(entries - 1),
            "the refusal did not land on the charge that crossed the ceiling"
        );
        let failure = charge.failure.take().expect("a refusal is recorded");
        let EngineError::ResourceLimit(limit) = failure else {
            panic!("expected a measured resource limit: {failure:?}");
        };
        assert_eq!(limit.what, "metadata expansion");
        assert_eq!(limit.need, entry * entries);
        assert_eq!(limit.limit, ceiling);
        assert_eq!(limit.cause(), LimitCause::ExceedsLimit);
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
            reserved: 0,
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

#[cfg(test)]
mod admission_tests {
    //! Reading a packet and being allowed to keep it are two different things,
    //! and only the second can fail in a way the host is told to retry. These
    //! drive a scanner across an official archive with a peer holding the
    //! budget, which is the only way to reach that path.
    use super::{IngestedContents, PacketScanner, ScanEvent};
    use crate::ScanLimits;
    use crate::runtime::{EngineError, ExecutionOptions, MemoryBudget, MemoryCategory};
    use crate::source::{MemorySourceAccess, SourceId};
    use std::sync::Arc;

    /// Where each packet of `archive` sits, and whether it is metadata.
    fn scanned(archive: &[u8], options: &ExecutionOptions) -> Vec<(u64, u64, bool)> {
        let mut scanner = scanner_over(archive, options);
        let mut seen = Vec::new();
        loop {
            match scanner.poll().expect("an ample budget scans the archive") {
                ScanEvent::Packet(packet) => seen.push((
                    packet.origin.offset,
                    packet.origin.length,
                    matches!(packet.contents, IngestedContents::Metadata(..)),
                )),
                ScanEvent::End => break,
                other => panic!("the whole archive is present: {other:?}"),
            }
        }
        seen
    }

    fn scanner_over(archive: &[u8], options: &ExecutionOptions) -> PacketScanner {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, archive.to_vec().into());
        PacketScanner::new(
            Arc::new(access),
            SourceId(1),
            options.clone(),
            ScanLimits::default(),
        )
        .expect("a scanner over the archive")
    }

    /// A provider that reports the generation it was given until it is armed,
    /// and a different one from its second answer after that.
    ///
    /// A carrier rewritten between a payload's opening generation check and
    /// its closing one cannot be staged from a fixed byte string, and it is
    /// the only way to reach the path where a whole hash pass is spent and
    /// then discarded. The bytes it serves are the official archive's.
    struct RewrittenUnderTheReader {
        inner: MemorySourceAccess,
        armed: std::sync::atomic::AtomicBool,
        answers: std::sync::atomic::AtomicU64,
    }

    impl crate::source::SourceAccess for RewrittenUnderTheReader {
        fn snapshot(
            &self,
            source: SourceId,
        ) -> std::io::Result<Option<crate::source::SourceSnapshot>> {
            let snapshot = self.inner.snapshot(source)?;
            if !self.armed.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(snapshot);
            }
            if self
                .answers
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                return Ok(snapshot);
            }
            Ok(snapshot.map(|snapshot| crate::source::SourceSnapshot {
                generation: snapshot.generation + 1,
                ..snapshot
            }))
        }

        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read_at(source, offset, out)
        }

        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<std::ops::Range<u64>>> {
            self.inner.next_available(source, offset)
        }
    }

    /// PR #73 round 5, finding E. `failed_hash_bytes` is what a host reads to
    /// decide a carrier is not worth re-reading, and its own documentation says
    /// it counts carrier bytes that changed under the reader. Only a hash
    /// mismatch was counted, so a packet read and hashed in full and then
    /// thrown away because the carrier had been rewritten was free, and the
    /// most expensive way to lose a packet was the one that showed nothing.
    #[test]
    fn a_carrier_rewritten_under_a_reauthentication_charges_the_pass_it_wasted() {
        let archive = crate::test_reference::set_vol0_par3();
        let options = ExecutionOptions::default();
        let mut inner = MemorySourceAccess::default();
        inner.insert(SourceId(1), 1, archive.clone().into());
        let access = Arc::new(RewrittenUnderTheReader {
            inner,
            armed: std::sync::atomic::AtomicBool::new(false),
            answers: std::sync::atomic::AtomicU64::new(0),
        });
        let mut scanner = PacketScanner::new(
            Arc::clone(&access) as Arc<dyn crate::source::SourceAccess>,
            SourceId(1),
            options.clone(),
            ScanLimits::default(),
        )
        .expect("a scanner over the archive");

        let mut set = super::IncrementalSet::new(crate::test_reference::SET_ID, options.clone())
            .expect("a set");
        let mut payload = None;
        loop {
            match scanner.poll().expect("the archive scans") {
                ScanEvent::Packet(packet) => {
                    if let IngestedContents::Payload(reference) = &packet.contents {
                        payload.get_or_insert_with(|| Arc::clone(reference));
                    }
                    set.merge(packet).expect("every packet is admitted");
                }
                ScanEvent::End => break,
                other => panic!("the whole archive is present: {other:?}"),
            }
        }
        let payload = payload.expect("the reference carrier holds recovery payloads");
        assert_eq!(
            set.failed_hash_bytes(),
            0,
            "nothing has been lost while the carrier stood still"
        );

        // From here the carrier answers its own generation once — which is the
        // check that opens the reauthentication — and a different one after.
        access
            .armed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let error = set
            .validate_payload(&payload, &options)
            .expect_err("the carrier changed under the reader");
        assert!(
            matches!(error, EngineError::SourceChanged(SourceId(1))),
            "the reauthentication failed for the wrong reason: {error:?}"
        );
        assert_eq!(
            set.failed_hash_bytes(),
            payload.packet_length(),
            "the whole packet was read and hashed and thrown away, uncounted"
        );
        assert_eq!(
            set.rejected_packets(),
            0,
            "a carrier that moved is not a packet this set refused"
        );
    }

    /// PR #73 round 5, finding A. A budget a peer is holding answers
    /// `PeerContention`, which the contract calls retryable: the host parks and
    /// polls again. The scanner used to count the packet and step its offset
    /// past it *before* asking for the memory its parsed body needs, so the
    /// retry resumed after a packet that was never yielded and the set came out
    /// quietly short. Nothing may move until the packet exists.
    #[test]
    fn a_packet_a_peer_squeezed_out_is_offered_again_rather_than_skipped() {
        let archive = crate::test_reference::set16_vol0_par3();
        let ample = ExecutionOptions::default();
        let expected = scanned(&archive, &ample);

        // Contend on the widest metadata packet: the refusal has to land on the
        // growth that covers the parsed body, not on the wire copy that is
        // taken before the packet is authenticated, and the margin below only
        // separates the two when the packet is larger than it is.
        let (index, offset, length) = expected
            .iter()
            .enumerate()
            .filter(|(_, (_, _, metadata))| *metadata)
            .map(|(index, (offset, length, _))| (index, *offset, *length))
            .max_by_key(|(_, _, length)| *length)
            .expect("the official archive carries metadata packets");
        const MARGIN: usize = 2048;
        assert!(
            length as usize > MARGIN,
            "the widest metadata packet is {length} bytes, too small to separate the two charges"
        );

        let options = ExecutionOptions {
            memory: MemoryBudget::new(8 << 20),
            ..ExecutionOptions::default()
        };
        let mut scanner = scanner_over(&archive, &options);
        for (position, expect) in expected.iter().take(index).enumerate() {
            let ScanEvent::Packet(packet) = scanner.poll().expect("an uncontended packet") else {
                panic!("the archive is shorter than the reference scan");
            };
            assert_eq!(
                (packet.origin.offset, packet.origin.length),
                (expect.0, expect.1),
                "packet {position} moved"
            );
        }

        // Leave the scanner room for the wire copy of the next packet and no
        // room to double it, which is what admitting the parsed body costs.
        let peer = options
            .memory
            .reserve_as(
                MemoryCategory::CarrierPackets,
                options.memory.available() - (length as usize + MARGIN),
            )
            .expect("a peer takes the headroom");

        let refusal = scanner
            .poll()
            .expect_err("the parsed body does not fit beside the peer");
        let EngineError::ResourceLimit(limit) = refusal else {
            panic!("a contended admission must be refused cleanly: {refusal:?}");
        };
        assert!(
            limit.contended(),
            "the peer is holding the memory, so this is retryable: {limit}"
        );
        assert_eq!(
            scanner.position(),
            offset,
            "the scan stepped over a packet it never yielded"
        );

        drop(peer);
        let ScanEvent::Packet(packet) = scanner.poll().expect("the peer is gone") else {
            panic!("the refused packet was never offered again");
        };
        assert_eq!(
            (packet.origin.offset, packet.origin.length),
            (offset, length),
            "the retry yielded a different packet"
        );

        // And the rest of the archive follows, once each.
        let mut seen = vec![(packet.origin.offset, packet.origin.length)];
        loop {
            match scanner.poll().expect("the budget is free again") {
                ScanEvent::Packet(packet) => {
                    seen.push((packet.origin.offset, packet.origin.length))
                }
                ScanEvent::End => break,
                other => panic!("the whole archive is present: {other:?}"),
            }
        }
        let remaining: Vec<(u64, u64)> = expected[index..]
            .iter()
            .map(|(offset, length, _)| (*offset, *length))
            .collect();
        assert_eq!(
            seen, remaining,
            "the contended scan lost or repeated a packet"
        );
    }
}

#[cfg(test)]
mod authenticating_writer_tests {
    //! Creation authenticates each carrier as it hands the bytes to the file
    //! instead of scanning the file again. These feed the writer official
    //! reference carriers, and damage made by flipping bytes of them in memory.
    use super::AuthenticatingWriter;
    use crate::InputSetId;
    use crate::runtime::{EngineError, EngineResult, ExecutionOptions};
    use crate::test_reference::{
        SET_ID, SET16_ID, set_par3, set_vol0_par3, set_vol1_par3, set16_par3, set16_vol0_par3,
        set16_vol1_par3,
    };
    use std::io::Write;

    fn written(bytes: &[u8], id: InputSetId, piece: usize, expected: u64) -> EngineResult<()> {
        let mut writer = AuthenticatingWriter::new(Vec::new(), id, ExecutionOptions::default());
        for chunk in bytes.chunks(piece) {
            writer.write_all(chunk).map_err(EngineError::from)?;
        }
        assert_eq!(
            writer.get_ref().as_slice(),
            bytes,
            "the inner writer got every byte"
        );
        writer.finish(expected)
    }

    fn carriers() -> [(Vec<u8>, InputSetId); 6] {
        [
            (set_par3(), SET_ID),
            (set_vol0_par3(), SET_ID),
            (set_vol1_par3(), SET_ID),
            (set16_par3(), SET16_ID),
            (set16_vol0_par3(), SET16_ID),
            (set16_vol1_par3(), SET16_ID),
        ]
    }

    /// The packets of a carrier, split at their header lengths.
    fn split_packets(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let length = u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap()) as usize;
            out.push(bytes[at..at + length].to_vec());
            at += length;
        }
        out
    }

    #[test]
    fn repeated_known_packets_are_proven_by_comparison_and_still_refuse_damage() {
        let index = set_par3();
        let known = split_packets(&index);
        // The index, then every packet again in reverse, the way a volume
        // repeats its metadata after the first copy.
        let mut carrier = index.clone();
        for packet in known.iter().rev() {
            carrier.extend_from_slice(packet);
        }
        let write = |bytes: &[u8], known: &[Vec<u8>], piece: usize| -> EngineResult<usize> {
            let mut writer =
                AuthenticatingWriter::new(Vec::new(), SET_ID, ExecutionOptions::default())
                    .with_known(known);
            for chunk in bytes.chunks(piece) {
                writer.write_all(chunk).map_err(EngineError::from)?;
            }
            assert_eq!(writer.get_ref().as_slice(), bytes);
            writer.finish(carrier.len() as u64)?;
            Ok(writer.compared)
        };
        // The first copy of each packet is hashed; every repeat is compared.
        for piece in [1, 7, 48, 49, 4096, carrier.len()] {
            assert_eq!(write(&carrier, &known, piece).unwrap(), known.len());
        }
        // Every byte of every repeated copy is still covered: by the header
        // parse, or by the comparison with the copy proven first.
        for at in index.len()..carrier.len() {
            let mut damaged = carrier.clone();
            damaged[at] ^= 0x01;
            assert!(
                write(&damaged, &known, 4096).is_err(),
                "a flip at byte {at} of a repeat was accepted"
            );
        }
        // A known entry that differs from what was written is never proven,
        // so the copies are hashed as before and still authenticate.
        let mut wrong = known.clone();
        let last = wrong[0].len() - 1;
        wrong[0][last] ^= 0x01;
        assert_eq!(write(&carrier, &wrong, 4096).unwrap(), known.len() - 1);
    }

    #[test]
    fn reference_carriers_authenticate_however_their_writes_are_split() {
        for (bytes, id) in carriers() {
            // Pieces that split headers, prefixes and bodies, and one write.
            for piece in [1, 7, 48, 49, 4096, bytes.len()] {
                written(&bytes, id, piece, bytes.len() as u64)
                    .unwrap_or_else(|error| panic!("{piece}-byte writes: {error:?}"));
            }
        }
    }

    #[test]
    fn a_flipped_byte_anywhere_in_a_carrier_is_refused() {
        // Magic, hash, length, set identity, type, prefix and body: the header
        // parse or the packet hash covers every byte.
        for (bytes, id) in carriers().into_iter().take(2) {
            for at in 0..bytes.len() {
                let mut damaged = bytes.clone();
                damaged[at] ^= 0x01;
                assert!(
                    written(&damaged, id, 4096, bytes.len() as u64).is_err(),
                    "a flip at byte {at} was accepted"
                );
            }
        }
    }

    #[test]
    fn another_set_a_short_carrier_or_stray_bytes_are_refused() {
        let bytes = set_vol0_par3();
        let len = bytes.len() as u64;
        assert!(written(&bytes, SET16_ID, 4096, len).is_err(), "another set");
        assert!(
            written(&bytes, SET_ID, 4096, len + 1).is_err(),
            "planned size"
        );
        assert!(
            written(&bytes[..bytes.len() - 1], SET_ID, 4096, len - 1).is_err(),
            "a packet cut short"
        );
        // The first packet's length, header included.
        let first = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
        assert!(
            written(&bytes[..first + 20], SET_ID, 4096, first as u64 + 20).is_err(),
            "a header cut short"
        );
        let mut stray = bytes[..first].to_vec();
        stray.push(0);
        stray.extend_from_slice(&bytes[first..]);
        assert!(
            written(&stray, SET_ID, 4096, len + 1).is_err(),
            "a byte between packets"
        );
    }
}
