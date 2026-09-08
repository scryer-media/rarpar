//! Official Data packets with retained validation and no protected source files.
mod common;

use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use par3_rs::ingest::{IngestedPacket, PacketScanner, PayloadKind, ScanEvent};
use par3_rs::runtime::ExecutionOptions;
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{MemorySourceAccess, SourceAccess, SourceId, SourceSnapshot};

struct Carriers {
    generation: AtomicU64,
    reads: AtomicUsize,
}

fn carriers() -> &'static [Vec<u8>; 5] {
    static CARRIERS: std::sync::OnceLock<[Vec<u8>; 5]> = std::sync::OnceLock::new();
    CARRIERS.get_or_init(|| {
        [
            "data-dedup.par3",
            "data-dedup.part0+1.par3",
            "data-dedup.part1+2.par3",
            "data-dedup.part3+1.par3",
            "data-dedup.vol0+1.par3",
        ]
        .map(common::advanced_fixture)
    })
}

impl SourceAccess for Carriers {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok(carriers()
            .get(source.0 as usize)
            .map(|bytes| SourceSnapshot {
                len: bytes.len() as u64,
                generation: self.generation.load(Ordering::Relaxed),
            }))
    }
    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let bytes = &carriers()[source.0 as usize];
        let offset = (offset as usize).min(bytes.len());
        let take = out.len().min(bytes.len() - offset);
        out[..take].copy_from_slice(&bytes[offset..offset + take]);
        Ok(take)
    }
    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        let end = carriers()[source.0 as usize].len() as u64;
        Ok((offset < end).then_some(offset..end))
    }
}

fn scan(access: Arc<Carriers>, options: &ExecutionOptions) -> Vec<IngestedPacket> {
    let mut packets = Vec::new();
    for index in 0..carriers().len() {
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(index as u64),
            options.clone(),
            par3_rs::ScanLimits::default(),
        )
        .unwrap();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            packets.push(packet);
        }
    }
    packets
}

#[test]
#[ignore = "requires the next published advanced PAR3 corpus; enable in the corpus follow-up PR"]
fn official_xor_recovers_each_omitted_data_block_and_all_its_file_aliases() {
    for missing in 0..4 {
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = 127;
        let access = Arc::new(Carriers {
            generation: AtomicU64::new(1),
            reads: AtomicUsize::new(0),
        });
        let packets = scan(access, &options);
        let mut session = Par3RepairSession::new(
            packets[0].input_set_id(),
            Arc::new(MemorySourceAccess::default()),
            options,
        )
        .unwrap();
        for packet in packets {
            if packet.payload().is_some_and(
                |payload| matches!(payload.kind(), PayloadKind::Data { index } if index == missing),
            ) {
                continue;
            }
            session.merge(packet).unwrap();
        }
        let assessment = session.assess().unwrap();
        assert_eq!(assessment.status, RepairStatus::Ready);
        assert_eq!(assessment.lost_blocks, vec![missing]);
        let output = common::TempTree::new("official-data-xor");
        let report = session.repair(output.path(), false).unwrap();
        assert_eq!(report.reconstructed_blocks, 1);
        assert_eq!(report.installed.len(), 2);
        let expected: Vec<u8> = (0..3300).map(|i| ((i * 29 + i / 31) % 256) as u8).collect();
        for name in ["copy.bin", "input.bin"] {
            assert_eq!(std::fs::read(output.path().join(name)).unwrap(), expected);
        }
    }
}

#[test]
#[ignore = "requires the next published advanced PAR3 corpus; enable in the corpus follow-up PR"]
fn official_data_only_recovery_retains_proofs_across_replays_and_recovery_arrivals() {
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.stripe_bytes = 128;
    let access = Arc::new(Carriers {
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
    });
    let packets = scan(access.clone(), &options);
    let mut session = Par3RepairSession::new(
        packets[0].input_set_id(),
        Arc::new(MemorySourceAccess::default()),
        options.clone(),
    )
    .unwrap();
    // Data arrives before any File, Root, or checksum metadata.
    for packet in &packets {
        if packet
            .payload()
            .is_some_and(|payload| matches!(payload.kind(), PayloadKind::Data { .. }))
        {
            session.merge(packet.clone()).unwrap();
        }
    }
    assert_eq!(
        session.assess().unwrap().status,
        RepairStatus::IncompleteMetadata
    );
    for packet in packets.iter().filter(|packet| packet.metadata().is_some()) {
        session.merge(packet.clone()).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert!(session.assess().unwrap().lost_blocks.is_empty());
    assert_eq!(session.diagnostics().data_validations, 4);
    let output = common::TempTree::new("official-data-only");
    let report = session.repair(output.path(), false).unwrap();
    assert_eq!(report.installed.len(), 2);
    assert_eq!(report.reconstructed_blocks, 0);
    let expected: Vec<u8> = (0..3300).map(|i| ((i * 29 + i / 31) % 256) as u8).collect();
    for name in ["copy.bin", "input.bin"] {
        assert_eq!(std::fs::read(output.path().join(name)).unwrap(), expected);
    }
    access.reads.store(0, Ordering::Relaxed);
    // Includes identical Data replays and a genuinely new Recovery packet.
    for packet in &packets {
        session.merge(packet.clone()).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(session.diagnostics().data_validations, 4);
    assert_eq!(access.reads.load(Ordering::Relaxed), 0);
    access.generation.store(2, Ordering::Relaxed);
    assert_eq!(session.assess().unwrap().lost_blocks, vec![0, 1, 2, 3]);
    assert_eq!(access.reads.load(Ordering::Relaxed), 0);
    for packet in scan(access.clone(), &options) {
        session.merge(packet).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(session.diagnostics().data_validations, 8);
}
