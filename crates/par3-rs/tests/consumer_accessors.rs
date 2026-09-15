//! Accessors a host needs from a live session, so it does not reconstruct them.
//!
//! A consumer that merges packets into a [`Par3RepairSession`] wants three
//! things the engine already knows: what the resolved set says about the files
//! it protects, how much carrier work was hashed and thrown away, and how many
//! packets were refused. Before these accessors existed a host had to keep its
//! own tallies beside the engine's, and read the set only by cloning it.
mod common;

use std::io;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use par3_rs::Par3RepairSession;
use par3_rs::ingest::{IngestedPacket, PacketScanner, PayloadKind, ScanEvent};
use par3_rs::runtime::{EngineError, ExecutionOptions};
use par3_rs::session::RepairStatus;
use par3_rs::source::{MemorySourceAccess, SourceAccess, SourceId, SourceSnapshot};

/// A carrier whose bytes can change under a reader without its published
/// generation moving — a source that lies about being immutable, which is what
/// a reauthentication exists to catch. Regenerated official bytes with one bit
/// flipped in memory; no packet is assembled here.
struct RottingCarrier {
    bytes: Mutex<Vec<u8>>,
    len: u64,
    reads: AtomicUsize,
}

impl RottingCarrier {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            bytes: Mutex::new(bytes),
            reads: AtomicUsize::new(0),
        }
    }

    fn rot(&self, offset: usize) {
        self.bytes.lock().unwrap()[offset] ^= 0x01;
    }
}

impl SourceAccess for RottingCarrier {
    fn snapshot(&self, _: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok(Some(SourceSnapshot {
            len: self.len,
            generation: 1,
        }))
    }

    fn read_at(&self, _: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let bytes = self.bytes.lock().unwrap();
        let start = (offset as usize).min(bytes.len());
        let take = out.len().min(bytes.len() - start);
        out[..take].copy_from_slice(&bytes[start..start + take]);
        Ok(take)
    }

    fn next_available(&self, _: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok((offset < self.len).then_some(offset..self.len))
    }
}

fn scan(access: Arc<dyn SourceAccess>, options: &ExecutionOptions) -> Vec<IngestedPacket> {
    let mut scanner = PacketScanner::new(
        access,
        SourceId(9),
        options.clone(),
        par3_rs::ScanLimits::default(),
    )
    .unwrap();
    let mut collected = Vec::new();
    while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
        collected.push(packet);
    }
    collected
}

fn damaged_protected_files() -> MemorySourceAccess {
    let mut protected = MemorySourceAccess::default();
    let mut damaged = common::a_bin();
    damaged[2300] ^= 1;
    protected.insert(SourceId(1), 1, damaged.into());
    protected.insert(SourceId(2), 1, common::b_txt().into());
    protected.insert(SourceId(3), 1, common::c_bin().into());
    protected
}

#[test]
fn a_session_lends_its_resolved_set_instead_of_making_the_host_rebuild_it() {
    let options = ExecutionOptions::default();
    let mut session = Par3RepairSession::new(
        common::SET_ID,
        Arc::new(damaged_protected_files()),
        options.clone(),
    )
    .unwrap();

    // Before Start and Root arrive there is no set, and that is not a failure.
    assert!(session.set().is_none());

    let mut carrier = MemorySourceAccess::default();
    carrier.insert(SourceId(9), 1, common::set_par3().into());
    for packet in scan(Arc::new(carrier), &options) {
        session.merge(packet).unwrap();
    }

    // Resolution is lazy: the session resolves the set when something needs it.
    assert!(session.set().is_none());
    session
        .layout()
        .unwrap()
        .expect("the index carrier resolves");
    let set = session.set().expect("the index carrier resolves the set");
    assert_eq!(set.input_set_id(), common::SET_ID);
    assert_eq!(
        set.files()
            .iter()
            .map(|file| (file.path(), file.size()))
            .collect::<Vec<_>>(),
        vec![
            ("a.bin", common::a_bin().len() as u64),
            ("b.txt", common::b_txt().len() as u64),
            ("sub/c.bin", common::c_bin().len() as u64),
        ]
    );
    assert_eq!(set.block_size(), 2000);
    // The option-packet tally is readable without walking the packets.
    assert_eq!(set.option_packet_count(), 0);
    assert_eq!(set.unknown_packet_count(), 0);

    // The borrow is the session's own tree, not a copy: reading it neither
    // allocates nor moves the retained figure.
    let retained = session.retained_bytes();
    let again = session.set().expect("still resolved");
    assert!(std::ptr::eq(set, again));
    assert_eq!(session.retained_bytes(), retained);
}

#[test]
fn a_carrier_that_rots_under_the_reader_is_charged_to_the_set_that_trusted_it() {
    let options = ExecutionOptions::default();
    let carrier = Arc::new(RottingCarrier::new(common::set_vol0_par3()));
    let packets = scan(carrier.clone(), &options);
    let (origin, recovery) = packets
        .iter()
        .find_map(|packet| {
            packet
                .payload()
                .filter(|payload| matches!(payload.kind(), PayloadKind::Recovery { .. }))
                .map(|payload| (packet.origin(), payload))
        })
        .expect("the volume carries a recovery payload");
    let packet_length = recovery.packet_length();
    assert!(packet_length > recovery.len());

    let mut session = Par3RepairSession::new(
        common::SET_ID,
        Arc::new(damaged_protected_files()),
        options.clone(),
    )
    .unwrap();
    for (name, id) in [("a.bin", 1), ("b.txt", 2), ("sub/c.bin", 3)] {
        session.bind_file(name, SourceId(id)).unwrap();
    }
    for packet in packets {
        session.merge(packet).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(session.failed_hash_bytes(), 0);
    assert_eq!(session.rejected_packets(), 0);

    // The carrier changes after its packets authenticated, without admitting
    // to it. Repair reauthenticates before consuming, so the lie is caught.
    carrier.rot((origin.offset + packet_length - 1) as usize);
    let output = common::TempTree::new("rotted-carrier");
    let refused = session
        .repair(output.path(), false)
        .map(|_| ())
        .expect_err("a rotted recovery payload must not be consumed");
    assert!(
        matches!(
            refused,
            EngineError::Format(par3_rs::Par3Error::PacketHashMismatch { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(session.failed_hash_bytes(), packet_length);
    assert_eq!(session.rejected_packets(), 1);

    // Monotonic: a second attempt adds its own failure rather than resetting.
    assert!(session.repair(output.path(), false).is_err());
    assert_eq!(session.failed_hash_bytes(), packet_length * 2);
    assert_eq!(session.rejected_packets(), 2);
}

#[test]
fn every_refused_packet_is_counted_once_whatever_refused_it() {
    let options = ExecutionOptions::default();
    let mut carrier = MemorySourceAccess::default();
    carrier.insert(SourceId(9), 1, common::set_par3().into());
    let ours = scan(Arc::new(carrier), &options);

    let mut carrier = MemorySourceAccess::default();
    carrier.insert(SourceId(9), 1, common::set16_par3().into());
    let foreign = scan(Arc::new(carrier), &options);

    let mut session = Par3RepairSession::new(
        common::SET_ID,
        Arc::new(damaged_protected_files()),
        options.clone(),
    )
    .unwrap();
    for packet in &ours {
        session.merge(packet.clone()).unwrap();
    }
    assert_eq!(session.rejected_packets(), 0);

    // A packet naming another input set is one rejection.
    assert!(session.merge(foreign[0].clone()).is_err());
    assert_eq!(session.rejected_packets(), 1);

    // A replay is not a rejection: admitting the same packet twice succeeds.
    session.merge(ours[0].clone()).unwrap();
    assert_eq!(session.rejected_packets(), 1);

    // A retained ceiling too small for the next packet is one rejection too,
    // and it is counted even though it is refused before the set sees it.
    let mut tight = ExecutionOptions::default();
    tight.retained_bytes = 1;
    let mut tight =
        Par3RepairSession::new(common::SET_ID, Arc::new(damaged_protected_files()), tight).unwrap();
    assert!(tight.merge(ours[0].clone()).is_err());
    assert_eq!(tight.rejected_packets(), 1);
    assert_eq!(tight.failed_hash_bytes(), 0);
}
