//! Resource bounds for one packet-inventory load.
//!
//! A PAR2 set is a bag of packets spread over an arbitrary number of files, and
//! nothing in the container format bounds how many packets a file may hold. The
//! *logical* inventory a set can describe is bounded by the format; the
//! *physical* packet stream is not. Without an explicit budget a small input can
//! therefore inflate into a large amount of retained bookkeeping: 4.5 MiB of
//! minimal recovery packets used to produce tens of megabytes of live parsed
//! metadata, held simultaneously in several temporary collections.
//!
//! [`PacketScanBudget`] is that explicit budget. One budget is shared across
//! every input file of a single load, so redundancy spread over many volumes is
//! accounted once rather than per file. It tracks three quantities:
//!
//! 1. **Packets examined** — every packet that parsed and passed its MD5,
//!    including duplicates and packets belonging to a foreign recovery set.
//!    This is the *work* meter, and it bounds scan cost.
//! 2. **Retained packets** — packets whose contents the caller actually keeps.
//!    Duplicates and rejected packets do not count here, so this is the
//!    *logical inventory* meter.
//! 3. **Retained metadata bytes** — the heap the retained packets hold: file
//!    names, IFSC entry arrays, Main file-ID lists, creator strings, and the
//!    per-packet container slot each one occupies.
//!
//! Every charge uses checked arithmetic and also polls the cancellation token,
//! so a cancelled load stops between packets instead of running to completion.
//!
//! Exceeding any limit is [`Par2Error::ResourceLimitExceeded`]. It is never a
//! truncation: a load that trips a limit yields an error, never a partial set.
//!
//! # What the byte meter does not cover
//!
//! Recovery *payloads* are excluded. The disk scanner keeps them file-backed
//! (nothing is copied), and the in-memory scanner's copies are bounded by the
//! caller's own buffer, so payload bytes are governed by `slice_size` times the
//! recovery-block count rather than by this budget. The byte meter is about the
//! metadata that a scan can multiply.

use std::cell::Cell;
use std::path::Path;

use crate::error::{Par2Error, Result};
use crate::types::{CancellationToken, MAX_FILES_PER_SET};

use super::Packet;

/// Highest recovery-slice exponent that can contribute to a repair.
///
/// PAR2 codes over GF(2^16), and this crate's creator refuses a plan whose
/// `first_exponent + count` reaches 65536 (see `create::plan`). Exponents above
/// this describe no usable recovery block, so retaining them only grows the
/// inventory.
pub const MAX_RECOVERY_EXPONENT: u32 = 65_535;

/// Number of distinct usable recovery exponents: `0..=MAX_RECOVERY_EXPONENT`.
pub const RECOVERY_EXPONENT_DOMAIN: usize = MAX_RECOVERY_EXPONENT as usize + 1;

/// Default ceiling on unique retained logical packets.
///
/// Derived from what the format can actually describe, not from a round number:
///
/// | Packet kind          | Maximum | Why |
/// |----------------------|--------:|-----|
/// | Main                 |       1 | one recovery set per inventory |
/// | Creator              |       1 | one creator string is kept |
/// | File Description     |  32,768 | [`MAX_FILES_PER_SET`], the Main packet's file-ID cap |
/// | Input File Slice Checksum | 32,768 | at most one IFSC packet per described file |
/// | Recovery Slice       |  65,536 | [`RECOVERY_EXPONENT_DOMAIN`] |
///
/// `1 + 1 + 32,768 + 32,768 + 65,536 = 131,074`.
pub const DEFAULT_MAX_RETAINED_PACKETS: usize =
    2 + 2 * MAX_FILES_PER_SET + RECOVERY_EXPONENT_DOMAIN;

/// How many times the whole logical inventory may appear in the packet stream
/// before the examined-packet meter refuses it.
///
/// PAR2 producers replicate the critical packets (Main, File Description, IFSC,
/// Creator) into every recovery volume so that any surviving volume can
/// describe the set. par2cmdline sizes that redundancy at roughly
/// `log2(recovery block count)` volumes, which is at most 17 copies for a
/// 65,536-block set, plus the index file. 32 leaves close to a 2x margin over
/// that while still refusing a stream that repeats the inventory thousands of
/// times.
pub const DEFAULT_INVENTORY_REDUNDANCY: u64 = 32;

/// Default ceiling on total packets examined across one load, redundancy
/// included: [`DEFAULT_MAX_RETAINED_PACKETS`] x [`DEFAULT_INVENTORY_REDUNDANCY`]
/// = 4,194,368.
pub const DEFAULT_MAX_EXAMINED_PACKETS: u64 =
    DEFAULT_MAX_RETAINED_PACKETS as u64 * DEFAULT_INVENTORY_REDUNDANCY;

/// Default ceiling on retained packet metadata, in bytes.
///
/// The dominant legitimate term is file names: a set may describe 32,768 files,
/// and each File Description keeps both the PAR2 name and its translated local
/// name. Ordinary sets use names well under 512 bytes, which puts a full
/// 32,768-file inventory near 40 MiB; 128 MiB leaves headroom for sets whose
/// names are long relative paths. The pathological term this refuses is the
/// packet parser's own per-packet ceilings multiplied out: 32,768 File
/// Descriptions at the 100,000-byte name limit would be 6.5 GiB, and 32,768
/// IFSC packets at 32,768 entries each would be 21 GiB.
pub const DEFAULT_MAX_RETAINED_METADATA_BYTES: usize = 128 * 1024 * 1024;

/// Bytes charged for the container slot a retained packet occupies.
///
/// A retained packet lives in a hash map or ordered map keyed by file ID or
/// exponent. This covers the key, the entry header, and the load-factor slack
/// those maps carry, so the byte meter reflects the map growth the finding
/// called out rather than only the packet payloads.
const RETAINED_SLOT_OVERHEAD_BYTES: usize = 64;

/// Limits applied to one packet-inventory load.
///
/// [`Default`] is the format-derived set documented on the `DEFAULT_*`
/// constants in this module. Callers that know their own bound — the creator's
/// staged-volume validation knows exactly how many packets it wrote — should
/// narrow these rather than rely on the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketScanLimits {
    /// Unique retained logical packets. Duplicates do not count.
    pub max_retained_packets: usize,
    /// Valid packets examined, duplicates and foreign-set packets included.
    pub max_examined_packets: u64,
    /// Heap held by retained packet metadata, recovery payloads excluded.
    pub max_retained_metadata_bytes: usize,
}

impl Default for PacketScanLimits {
    fn default() -> Self {
        Self {
            max_retained_packets: DEFAULT_MAX_RETAINED_PACKETS,
            max_examined_packets: DEFAULT_MAX_EXAMINED_PACKETS,
            max_retained_metadata_bytes: DEFAULT_MAX_RETAINED_METADATA_BYTES,
        }
    }
}

impl PacketScanLimits {
    pub fn with_max_retained_packets(mut self, packets: usize) -> Self {
        self.max_retained_packets = packets;
        self
    }

    pub fn with_max_examined_packets(mut self, packets: u64) -> Self {
        self.max_examined_packets = packets;
        self
    }

    pub fn with_max_retained_metadata_bytes(mut self, bytes: usize) -> Self {
        self.max_retained_metadata_bytes = bytes;
        self
    }
}

/// The live meters behind one [`PacketScanLimits`].
///
/// Shared by reference across every input file of a load and across the scanner
/// and its sink, so the counters live in [`Cell`]s rather than behind `&mut`.
/// Packet scanning is single-threaded; nothing here is `Sync`, deliberately.
pub struct PacketScanBudget {
    limits: PacketScanLimits,
    cancel: Option<CancellationToken>,
    examined: Cell<u64>,
    retained_packets: Cell<usize>,
    retained_bytes: Cell<usize>,
}

impl std::fmt::Debug for PacketScanBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketScanBudget")
            .field("limits", &self.limits)
            .field("cancellable", &self.cancel.is_some())
            .field("examined", &self.examined.get())
            .field("retained_packets", &self.retained_packets.get())
            .field("retained_bytes", &self.retained_bytes.get())
            .finish()
    }
}

impl PacketScanBudget {
    pub fn new(limits: PacketScanLimits) -> Self {
        Self {
            limits,
            cancel: None,
            examined: Cell::new(0),
            retained_packets: Cell::new(0),
            retained_bytes: Cell::new(0),
        }
    }

    /// A budget that also aborts when `cancel` fires. Cancellation is polled at
    /// every charge point, which is at least once per packet.
    pub fn with_cancellation(limits: PacketScanLimits, cancel: Option<CancellationToken>) -> Self {
        Self {
            cancel,
            ..Self::new(limits)
        }
    }

    pub fn limits(&self) -> PacketScanLimits {
        self.limits
    }

    pub fn examined(&self) -> u64 {
        self.examined.get()
    }

    pub fn retained_packets(&self) -> usize {
        self.retained_packets.get()
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes.get()
    }

    pub fn check_cancelled(&self) -> Result<()> {
        if self
            .cancel
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(Par2Error::Cancelled);
        }
        Ok(())
    }

    /// Charge one examined packet. Called for every packet that parsed and
    /// passed its MD5, whatever the caller then does with it.
    pub fn charge_examined(&self) -> Result<()> {
        self.check_cancelled()?;
        let examined = self
            .examined
            .get()
            .checked_add(1)
            .ok_or_else(|| self.limit_error("examined packet count overflows"))?;
        if examined > self.limits.max_examined_packets {
            return Err(self.limit_error(&format!(
                "examined {examined} PAR2 packets across the inventory, limit is {}",
                self.limits.max_examined_packets
            )));
        }
        self.examined.set(examined);
        Ok(())
    }

    /// Charge `bytes` of retained metadata without claiming a retained-packet
    /// slot. Used for storage that is shared across packets, such as the
    /// interned path behind a volume's file-backed recovery slices, and for
    /// packets held only until an admission decision can be made.
    pub fn charge_bytes(&self, bytes: usize) -> Result<()> {
        self.check_cancelled()?;
        let retained = self
            .retained_bytes
            .get()
            .checked_add(bytes)
            .ok_or_else(|| self.limit_error("retained metadata byte count overflows"))?;
        if retained > self.limits.max_retained_metadata_bytes {
            return Err(self.limit_error(&format!(
                "retained {retained} bytes of PAR2 packet metadata, limit is {}",
                self.limits.max_retained_metadata_bytes
            )));
        }
        self.retained_bytes.set(retained);
        Ok(())
    }

    /// Charge one retained logical packet holding `bytes` of metadata.
    ///
    /// Both meters move together, and neither moves if either would be
    /// exceeded, so a refused charge leaves the budget exactly as it was.
    pub fn charge_retained(&self, bytes: usize) -> Result<()> {
        let packets = self
            .retained_packets
            .get()
            .checked_add(1)
            .ok_or_else(|| self.limit_error("retained packet count overflows"))?;
        if packets > self.limits.max_retained_packets {
            return Err(self.limit_error(&format!(
                "retained {packets} PAR2 packets, limit is {}",
                self.limits.max_retained_packets
            )));
        }
        self.charge_bytes(bytes)?;
        self.retained_packets.set(packets);
        Ok(())
    }

    /// Give back `bytes` charged by [`Self::charge_bytes`].
    pub fn release_bytes(&self, bytes: usize) {
        self.retained_bytes
            .set(self.retained_bytes.get().saturating_sub(bytes));
    }

    /// Give back a slot charged by [`Self::charge_retained`], for a packet that
    /// turned out to be a duplicate or was otherwise not kept.
    pub fn release_retained(&self, bytes: usize) {
        self.retained_packets
            .set(self.retained_packets.get().saturating_sub(1));
        self.release_bytes(bytes);
    }

    fn limit_error(&self, reason: &str) -> Par2Error {
        Par2Error::ResourceLimitExceeded {
            reason: reason.to_string(),
        }
    }
}

/// Reserve room for `additional` more elements, reporting an allocator refusal
/// instead of aborting the process.
///
/// The budget bounds what a scan *intends* to hold; this bounds what the
/// allocator is actually willing to give. A packet-inventory load is a hostile
/// input surface, so a refused allocation has to come back as an error the
/// caller can act on rather than as an abort.
pub(crate) fn reserve_fallible<T>(vec: &mut Vec<T>, additional: usize) -> Result<()> {
    vec.try_reserve(additional)
        .map_err(|error| Par2Error::ResourceLimitExceeded {
            reason: format!("could not allocate room for {additional} more PAR2 packets: {error}"),
        })
}

/// Bytes an interned recovery-volume path costs the budget.
///
/// The streaming scanner interns one `Arc<Path>` per volume file and shares it
/// across every recovery packet in that file, so this is charged once per file
/// rather than once per packet.
pub(crate) fn interned_path_bytes(path: &Path) -> usize {
    path.as_os_str().len() + 2 * size_of::<usize>()
}

/// Heap a retained packet holds, including its container slot.
///
/// Recovery payloads are excluded; see the module docs.
pub(crate) fn packet_retained_bytes(packet: &Packet) -> usize {
    let contents = match packet {
        Packet::Main(main) => size_of::<super::MainPacket>().saturating_add(
            main.recovery_file_ids
                .len()
                .saturating_add(main.non_recovery_file_ids.len())
                .saturating_mul(size_of::<crate::types::FileId>()),
        ),
        Packet::FileDescription(desc) => size_of::<super::FileDescriptionPacket>()
            .saturating_add(desc.filename.len())
            .saturating_add(desc.par2_name.len()),
        Packet::InputFileSliceChecksum(ifsc) => size_of::<super::IfscPacket>().saturating_add(
            ifsc.checksums
                .len()
                .saturating_mul(size_of::<crate::types::SliceChecksum>()),
        ),
        Packet::RecoverySlice(_) => size_of::<super::RecoverySlicePacket>(),
        Packet::Creator(creator) => {
            size_of::<super::CreatorPacket>().saturating_add(creator.creator_id.len())
        }
        Packet::Unknown { body, .. } => size_of::<Packet>().saturating_add(body.len()),
    };
    contents.saturating_add(RETAINED_SLOT_OVERHEAD_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_their_documented_derivation() {
        let limits = PacketScanLimits::default();
        assert_eq!(limits.max_retained_packets, 131_074);
        assert_eq!(limits.max_examined_packets, 4_194_368);
        assert_eq!(limits.max_retained_metadata_bytes, 128 * 1024 * 1024);
    }

    #[test]
    fn examined_meter_refuses_the_packet_past_the_limit() {
        let budget =
            PacketScanBudget::new(PacketScanLimits::default().with_max_examined_packets(2));
        budget.charge_examined().unwrap();
        budget.charge_examined().unwrap();
        let error = budget.charge_examined().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
        assert_eq!(budget.examined(), 2);
    }

    #[test]
    fn retained_charge_is_all_or_nothing_across_both_meters() {
        let budget = PacketScanBudget::new(
            PacketScanLimits::default()
                .with_max_retained_packets(4)
                .with_max_retained_metadata_bytes(100),
        );
        budget.charge_retained(60).unwrap();
        // The packet slot fits but the bytes do not; neither meter may move.
        let error = budget.charge_retained(60).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
        assert_eq!(budget.retained_packets(), 1);
        assert_eq!(budget.retained_bytes(), 60);
    }

    #[test]
    fn released_charges_return_to_both_meters() {
        let budget = PacketScanBudget::new(PacketScanLimits::default());
        budget.charge_retained(128).unwrap();
        budget.release_retained(128);
        assert_eq!(budget.retained_packets(), 0);
        assert_eq!(budget.retained_bytes(), 0);
        // Saturating, so an over-release cannot wrap the meters.
        budget.release_retained(128);
        assert_eq!(budget.retained_packets(), 0);
        assert_eq!(budget.retained_bytes(), 0);
    }

    #[test]
    fn byte_meter_rejects_overflow_rather_than_wrapping() {
        let budget = PacketScanBudget::new(
            PacketScanLimits::default().with_max_retained_metadata_bytes(usize::MAX),
        );
        budget.charge_bytes(usize::MAX).unwrap();
        let error = budget.charge_bytes(1).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
        assert_eq!(budget.retained_bytes(), usize::MAX);
    }

    #[test]
    fn examined_meter_rejects_overflow_rather_than_wrapping() {
        let budget =
            PacketScanBudget::new(PacketScanLimits::default().with_max_examined_packets(u64::MAX));
        budget.examined.set(u64::MAX);
        let error = budget.charge_examined().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn a_refused_allocation_is_an_error_not_an_abort() {
        // Capacity overflow and out-of-memory both arrive through `try_reserve`;
        // the helper must turn either into a `Par2Error` the caller can act on.
        let mut packets = Vec::<Packet>::new();
        let error = reserve_fallible(&mut packets, usize::MAX).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
        assert!(packets.is_empty());

        let mut wide = Vec::<[u8; 4096]>::new();
        let error = reserve_fallible(&mut wide, usize::MAX / 4096).unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));

        reserve_fallible(&mut packets, 4).unwrap();
        assert!(packets.capacity() >= 4);
    }

    #[test]
    fn every_charge_point_observes_cancellation() {
        let cancel = CancellationToken::new();
        let budget =
            PacketScanBudget::with_cancellation(PacketScanLimits::default(), Some(cancel.clone()));
        budget.charge_examined().unwrap();
        cancel.cancel();
        assert!(matches!(
            budget.charge_examined(),
            Err(Par2Error::Cancelled)
        ));
        assert!(matches!(budget.charge_bytes(1), Err(Par2Error::Cancelled)));
        assert!(matches!(
            budget.charge_retained(1),
            Err(Par2Error::Cancelled)
        ));
        assert!(matches!(
            budget.check_cancelled(),
            Err(Par2Error::Cancelled)
        ));
    }
}
