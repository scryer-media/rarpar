//! A blocking consumer lifecycle using only public engine APIs and official packets.
mod common;

use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use par3_rs::evidence::StreamingVerifier;
use par3_rs::ingest::{IngestedPacket, MergeEffect, PacketScanner, PayloadKind, ScanEvent};
use par3_rs::runtime::{
    CancellationToken, EngineError, ExecutionOptions, HandleBudget, MemoryBudget,
};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{MemorySourceAccess, SourceAccess, SourceId, SourceSnapshot};

const PATHS: [&str; 3] = ["a.bin", "b.txt", "sub/c.bin"];

struct VirtualJob {
    bytes: [Vec<u8>; 3],
    holes: [Range<u64>; 3],
    generations: [AtomicU64; 3],
    reads: AtomicUsize,
    read_bytes: AtomicUsize,
}

impl VirtualJob {
    fn new() -> Self {
        Self {
            bytes: [common::a_bin(), common::b_txt(), common::c_bin()],
            holes: [2000..4000, 0..0, 0..2000],
            generations: std::array::from_fn(|_| AtomicU64::new(1)),
            reads: AtomicUsize::new(0),
            read_bytes: AtomicUsize::new(0),
        }
    }

    fn index(source: SourceId) -> usize {
        usize::try_from(source.0 - 1).unwrap()
    }
}

impl SourceAccess for VirtualJob {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        let index = Self::index(source);
        Ok(Some(SourceSnapshot {
            len: self.bytes[index].len() as u64,
            generation: self.generations[index].load(Ordering::Relaxed),
        }))
    }

    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let index = Self::index(source);
        let Some(range) = self.next_available(source, offset)? else {
            return Ok(0);
        };
        if range.start != offset {
            return Ok(0);
        }
        let count = out.len().min((range.end - offset) as usize);
        out[..count].copy_from_slice(&self.bytes[index][offset as usize..offset as usize + count]);
        self.read_bytes.fetch_add(count, Ordering::Relaxed);
        Ok(count)
    }

    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        let index = Self::index(source);
        let len = self.bytes[index].len() as u64;
        let hole = &self.holes[index];
        let start = if hole.contains(&offset) {
            hole.end
        } else {
            offset
        };
        let end = if start < hole.start { hole.start } else { len };
        Ok((start < end).then_some(start..end))
    }
}

fn packets(bytes: Vec<u8>, options: &ExecutionOptions) -> Vec<IngestedPacket> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(99), 1, bytes.into());
    let mut scanner = PacketScanner::new(
        Arc::new(access),
        SourceId(99),
        options.clone(),
        par3_rs::ScanLimits::default(),
    )
    .unwrap();
    let mut packets = Vec::new();
    loop {
        match scanner.poll().unwrap() {
            ScanEvent::Packet(packet) => packets.push(packet),
            ScanEvent::End => return packets,
            ScanEvent::NeedData { .. } => panic!("complete official carrier"),
        }
    }
}

#[test]
fn late_metadata_streamed_proofs_restart_selective_download_and_materialization() {
    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(2 << 20);
    options.retained_bytes = 512 << 10;
    options.handles = HandleBudget::new(2);
    options.open_handles = 2;
    options.workers = 1;
    options.stripe_bytes = 127;
    let source = Arc::new(VirtualJob::new());
    let index = packets(common::set_par3(), &options);
    let first = packets(common::set_vol0_par3(), &options)
        .into_iter()
        .find(|packet| packet.payload().is_some())
        .unwrap();
    let mut session =
        Par3RepairSession::new(common::SET_ID, source.clone(), options.clone()).unwrap();
    session.merge(first.clone()).unwrap();
    assert_eq!(
        session.assess().unwrap().status,
        RepairStatus::IncompleteMetadata
    );
    for packet in &index {
        session.merge(packet.clone()).unwrap();
    }
    let layout = session.layout().unwrap().unwrap();

    // The decoder publishes positioned bytes. Missing ranges are never fed as
    // zeroes, and neither these proofs nor their admission require source reads.
    let arrivals: [&[Range<usize>]; 3] = [
        &[4000..5000, 1000..2000, 0..1000],
        &[0..5, 5..10],
        &[3000..4000, 2000..3000],
    ];
    for (file, path) in PATHS.iter().enumerate() {
        let id = SourceId(file as u64 + 1);
        session.bind_file(path, id).unwrap();
        let mut verifier = StreamingVerifier::new(
            layout.clone(),
            file,
            id,
            source.snapshot(id).unwrap().unwrap(),
            options.clone(),
        )
        .unwrap();
        for range in arrivals[file] {
            verifier
                .feed(range.start as u64, &source.bytes[file][range.clone()])
                .unwrap();
        }
        session.add_evidence(verifier.finish()).unwrap();
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.status, RepairStatus::NeedRecovery);
    assert_eq!(assessment.lost_blocks.len(), 2);
    assert_eq!(assessment.files[0].verified_prefix, 2000);
    assert_eq!(assessment.files[0].unresolved, vec![2000..4000]);
    assert!(assessment.files[1].complete);
    assert_eq!(assessment.requirements[0].additional, 1);
    assert_eq!(session.merge(first.clone()).unwrap(), MergeEffect::Replay);
    session.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);

    // In production the digest goes in trusted job metadata; blob storage alone
    // cannot establish authority. Only finalized extent evidence is persisted.
    let checkpoints: Vec<_> = PATHS
        .iter()
        .map(|path| session.checkpoint_file(path).unwrap().unwrap())
        .collect();
    drop(layout);
    drop(session);
    let reopen = |options: &ExecutionOptions| {
        let mut session =
            Par3RepairSession::new(common::SET_ID, source.clone(), options.clone()).unwrap();
        for packet in &index {
            session.merge(packet.clone()).unwrap();
        }
        session.merge(first.clone()).unwrap();
        for (file, path) in PATHS.iter().enumerate() {
            session.bind_file(path, SourceId(file as u64 + 1)).unwrap();
            session
                .replay_evidence(checkpoints[file].as_bytes(), checkpoints[file].digest())
                .unwrap();
        }
        session
    };
    let mut session = reopen(&options);
    let need = session.assess().unwrap().requirements[0].clone();
    let downloaded = packets(common::set_vol1_par3(), &options)
        .into_iter()
        .find(|packet| {
            packet.payload().is_some_and(|payload| {
                matches!(payload.kind(), PayloadKind::Recovery { matrix, index, .. }
                if matrix == need.matrix && index % need.cohorts == need.cohort
                    && need.recovery_indices.contains(&index)
                    && !need.available.contains(&index))
            })
        })
        .unwrap();
    session.merge(downloaded.clone()).unwrap();
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(
        session.merge(downloaded.clone()).unwrap(),
        MergeEffect::Replay
    );
    session.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);

    let output = common::TempTree::new("weaver-consumer");
    let clean = output.path().join("b.txt");
    std::fs::write(&clean, common::b_txt()).unwrap();
    let clean_before = std::fs::metadata(&clean).unwrap().modified().unwrap();
    options.cancel.cancel();
    assert!(matches!(
        session.repair(output.path(), false),
        Err(EngineError::Cancelled)
    ));
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 1);
    assert_eq!(options.handles.used(), 0);
    drop(session);

    // Cancellation tokens belong to an operation lifetime; replay into a new
    // session shares resource ceilings without inheriting cancellation.
    options.cancel = CancellationToken::default();
    let mut session = reopen(&options);
    session.merge(downloaded.clone()).unwrap();
    session.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    source.generations[1].store(2, Ordering::Relaxed);
    assert!(matches!(
        session.replay_evidence(checkpoints[1].as_bytes(), checkpoints[1].digest()),
        Err(EngineError::SourceChanged(SourceId(2)))
    ));
    session.assess().unwrap();
    assert_eq!(
        source.read_bytes.load(Ordering::Relaxed),
        10,
        "only the changed binding is reread"
    );
    let reads = source.reads.load(Ordering::Relaxed);
    session.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), reads);
    let report = session.repair(output.path(), false).unwrap();
    assert_eq!(report.installed.len(), 2);
    assert!(
        !report
            .installed
            .iter()
            .any(|installed| installed.path == clean)
    );
    for (file, path) in PATHS.iter().enumerate() {
        assert_eq!(
            std::fs::read(output.path().join(path)).unwrap(),
            source.bytes[file]
        );
    }
    assert_eq!(
        std::fs::metadata(&clean).unwrap().modified().unwrap(),
        clean_before
    );
    assert!(session.retained_bytes() <= options.retained_bytes);
    assert!(options.memory.peak() <= options.memory.limit());
    assert!(options.handles.peak() <= 2);
    assert_eq!(options.handles.used(), 0);
    drop(session);
    drop(downloaded);
    drop(first);
    drop(index);
    drop(checkpoints);
    assert_eq!(options.memory.used(), 0);
}
