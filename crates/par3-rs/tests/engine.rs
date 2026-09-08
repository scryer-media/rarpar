//! Engine contracts exercised against unmodified official reference packets.
mod common;

use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use par3_rs::ScanLimits;
use par3_rs::evidence::{ExtentVerdict, StreamingVerifier, verify_source};
use par3_rs::ingest::{IncrementalSet, MergeEffect, PacketScanner, ScanEvent};
use par3_rs::layout::BlockLayout;
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};
use par3_rs::source::{MemorySourceAccess, SourceAccess, SourceId, SourceSnapshot};

struct ArrivingSource {
    bytes: Vec<u8>,
    visible: AtomicUsize,
    generation: AtomicU64,
    reads: AtomicUsize,
}

impl SourceAccess for ArrivingSource {
    fn snapshot(&self, _: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok(Some(SourceSnapshot {
            len: self.bytes.len() as u64,
            generation: self.generation.load(Ordering::Relaxed),
        }))
    }
    fn read_at(&self, _: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let offset = (offset as usize).min(self.bytes.len());
        let len = out
            .len()
            .min(self.visible.load(Ordering::Relaxed).saturating_sub(offset));
        out[..len].copy_from_slice(&self.bytes[offset..offset + len]);
        Ok(len)
    }
    fn next_available(&self, _: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        let end = self.visible.load(Ordering::Relaxed) as u64;
        Ok((offset < end).then_some(offset..end))
    }
}

#[test]
fn replay_rehomes_payloads_when_the_previous_provider_fails() {
    struct FallibleSource {
        inner: MemorySourceAccess,
        failed: std::sync::atomic::AtomicBool,
    }
    impl SourceAccess for FallibleSource {
        fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
            if self.failed.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "withdrawn carrier",
                ));
            }
            self.inner.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
            self.snapshot(source)?;
            self.inner.read_at(source, offset, out)
        }
        fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
            self.inner.next_available(source, offset)
        }
    }
    let options = ExecutionOptions::default();
    let source = || {
        let mut inner = MemorySourceAccess::default();
        inner.insert(SourceId(9), 1, common::set_vol0_par3().into());
        Arc::new(FallibleSource {
            inner,
            failed: false.into(),
        })
    };
    let old = source();
    let new = source();
    let scan = |access: Arc<FallibleSource>| {
        let mut scanner =
            PacketScanner::new(access, SourceId(9), options.clone(), ScanLimits::default())
                .unwrap();
        let mut packets = Vec::new();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            packets.push(packet);
        }
        packets
    };
    let mut input = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    for packet in scan(old.clone()) {
        input.merge(packet).unwrap();
    }
    let retained = input.retained_bytes();
    old.failed.store(true, Ordering::Relaxed);
    for packet in scan(new) {
        let expected = if packet.payload().is_some() {
            MergeEffect::Payload
        } else {
            MergeEffect::Replay
        };
        assert_eq!(input.merge(packet.clone()).unwrap(), expected);
        assert_eq!(input.merge(packet).unwrap(), MergeEffect::Replay);
    }
    assert_eq!(input.retained_bytes(), retained);
    for payload in input.payloads() {
        payload.validate(&options).unwrap();
    }
}

#[test]
fn split_arrivals_authenticate_without_retaining_recovery_bytes() {
    let bytes = common::set_vol0_par3();
    let expected = common::scan(&bytes);
    let source = Arc::new(ArrivingSource {
        visible: AtomicUsize::new(0),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
        bytes,
    });
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 53;
    let budget = options.memory.clone();
    let mut scanner = PacketScanner::new(
        source.clone(),
        SourceId(1),
        options.clone(),
        ScanLimits::default(),
    )
    .unwrap();
    let mut set = IncrementalSet::new(common::SET_ID, options).unwrap();
    let mut hashes = Vec::new();
    for visible in 0..=source.bytes.len() {
        source.visible.store(visible, Ordering::Relaxed);
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            hashes.push(packet.hash());
            assert_ne!(set.merge(packet.clone()).unwrap(), MergeEffect::Replay);
            assert_eq!(set.merge(packet).unwrap(), MergeEffect::Replay);
        }
    }
    assert_eq!(
        hashes,
        expected
            .iter()
            .map(|(_, packet)| packet.hash())
            .collect::<Vec<_>>()
    );
    assert_eq!(set.metadata().unwrap().unwrap().files().len(), 3);
    let payload = set.payloads().next().unwrap();
    assert_eq!(payload.len(), 2000);
    let mut range = [0; 21];
    assert_eq!(payload.read_at(120, &mut range).unwrap(), 21);
    let recovery = common::gf8_set();
    assert_eq!(range, recovery.recovery_blocks()[0].data()[120..141]);
    // Parsed enum/vector storage is charged conservatively rather than using
    // wire length as a proxy. No recovery block allocation is retained.
    assert!(budget.used() < 64 << 10);
    drop(scanner);
    drop(set);
    assert_eq!(budget.used(), 0);
}

#[test]
fn carrier_read_ahead_reads_each_byte_once_and_rejects_changed_generations() {
    let bytes = common::set_vol0_par3();
    let expected = common::scan(&bytes);
    let source = Arc::new(ArrivingSource {
        visible: AtomicUsize::new(bytes.len()),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
        bytes,
    });
    let options = ExecutionOptions::default();
    let mut scanner = PacketScanner::new(
        source.clone(),
        SourceId(1),
        options.clone(),
        ScanLimits::default(),
    )
    .unwrap();
    let mut hashes = Vec::new();
    while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
        hashes.push(packet.hash());
    }
    assert_eq!(
        hashes,
        expected
            .iter()
            .map(|(_, packet)| packet.hash())
            .collect::<Vec<_>>()
    );
    assert_eq!(options.scan_work.used(), source.bytes.len() as u64);
    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        source.bytes.len().div_ceil(64 << 10)
    );
    scanner.seek(0).unwrap();
    assert!(matches!(scanner.poll().unwrap(), ScanEvent::Packet(_)));
    source.generation.store(2, Ordering::Relaxed);
    assert!(matches!(
        scanner.poll(),
        Err(EngineError::SourceChanged(SourceId(1)))
    ));
}

#[test]
fn scan_work_is_cumulative_across_replays_seeks_and_scanners() {
    use par3_rs::runtime::ScanWorkBudget;
    let bytes = common::set_vol0_par3();
    let source = Arc::new(ArrivingSource {
        visible: AtomicUsize::new(bytes.len()),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
        bytes,
    });
    let mut options = ExecutionOptions::default();
    let scan = |options: &ExecutionOptions| {
        PacketScanner::new(
            source.clone(),
            SourceId(1),
            options.clone(),
            ScanLimits::default(),
        )
        .unwrap()
    };
    let mut first = scan(&options);
    while let ScanEvent::Packet(_) = first.poll().unwrap() {}
    let work = options.scan_work.used();
    assert!(
        work <= 2 * source.bytes.len() as u64,
        "known boundaries must not repeatedly prefetch whole volumes"
    );
    options.scan_work = ScanWorkBudget::new(work);
    let mut exact = scan(&options);
    while let ScanEvent::Packet(_) = exact.poll().unwrap() {}
    assert_eq!(options.scan_work.used(), work);
    let reads = source.reads.load(Ordering::Relaxed);
    exact.seek(0).unwrap();
    assert!(matches!(
        exact.poll(),
        Err(EngineError::ResourceLimit("cumulative scanning work"))
    ));
    assert!(matches!(
        scan(&options).poll(),
        Err(EngineError::ResourceLimit("cumulative scanning work"))
    ));
    assert_eq!(source.reads.load(Ordering::Relaxed), reads);
    // Empty polls are work too: callers cannot retry missing bytes indefinitely.
    source.visible.store(0, Ordering::Relaxed);
    options.stripe_bytes = 48;
    options.scan_work = ScanWorkBudget::new(96);
    let mut waiting = scan(&options);
    assert!(matches!(
        waiting.poll().unwrap(),
        ScanEvent::NeedData { .. }
    ));
    assert!(matches!(
        waiting.poll().unwrap(),
        ScanEvent::NeedData { .. }
    ));
    assert!(matches!(
        waiting.poll(),
        Err(EngineError::ResourceLimit("cumulative scanning work"))
    ));
}

#[test]
fn payload_rejects_changed_generation_and_cancellation() {
    let bytes = common::set_vol0_par3();
    let source = Arc::new(ArrivingSource {
        visible: AtomicUsize::new(bytes.len()),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
        bytes,
    });
    let options = ExecutionOptions::default();
    let mut scanner = PacketScanner::new(
        source.clone(),
        SourceId(1),
        options.clone(),
        ScanLimits::default(),
    )
    .unwrap();
    let payload = loop {
        if let ScanEvent::Packet(packet) = scanner.poll().unwrap()
            && let Some(payload) = packet.payload()
        {
            break payload.clone();
        }
    };
    payload.validate(&options).unwrap();
    source.generation.store(2, Ordering::Relaxed);
    assert!(matches!(
        payload.read_at(0, &mut [0; 1]),
        Err(EngineError::SourceChanged(_))
    ));
    options.cancel.cancel();
    assert!(matches!(scanner.poll(), Err(EngineError::Cancelled)));
}

#[test]
fn changed_recovery_is_removed_without_rereading_sources_and_replay_rebinds_it() {
    use par3_rs::session::{Par3RepairSession, RepairStatus};
    let options = ExecutionOptions::default();
    let mut protected = MemorySourceAccess::default();
    let mut damaged = common::a_bin();
    damaged[2300] ^= 1;
    protected.insert(SourceId(1), 1, damaged.into());
    protected.insert(SourceId(2), 1, common::b_txt().into());
    protected.insert(SourceId(3), 1, common::c_bin().into());
    let mut session =
        Par3RepairSession::new(common::SET_ID, Arc::new(protected), options.clone()).unwrap();
    for (name, id) in [("a.bin", 1), ("b.txt", 2), ("sub/c.bin", 3)] {
        session.bind_file(name, SourceId(id)).unwrap();
    }
    let bytes = common::set_vol0_par3();
    let carrier = Arc::new(ArrivingSource {
        visible: AtomicUsize::new(bytes.len()),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
        bytes,
    });
    let scan = || {
        let mut scanner = PacketScanner::new(
            carrier.clone(),
            SourceId(9),
            options.clone(),
            ScanLimits::default(),
        )
        .unwrap();
        let mut packets = Vec::new();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            packets.push(packet);
        }
        packets
    };
    for packet in scan() {
        session.merge(packet).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let verifications = session.diagnostics().source_verifications;
    carrier.generation.store(2, Ordering::Relaxed);
    carrier.reads.store(0, Ordering::Relaxed);
    assert_eq!(session.assess().unwrap().status, RepairStatus::NeedRecovery);
    assert_eq!(carrier.reads.load(Ordering::Relaxed), 0);
    assert_eq!(session.diagnostics().source_verifications, verifications);
    for packet in scan() {
        session.merge(packet).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    // Rebind an identical packet before assessment has discarded its old link.
    carrier.generation.store(3, Ordering::Relaxed);
    for packet in scan() {
        let expected = if packet.payload().is_some() {
            MergeEffect::Payload
        } else {
            MergeEffect::Replay
        };
        assert_eq!(session.merge(packet).unwrap(), expected);
    }
    carrier.reads.store(0, Ordering::Relaxed);
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(carrier.reads.load(Ordering::Relaxed), 0);
    assert_eq!(session.diagnostics().source_verifications, verifications);
}

#[test]
fn matching_numeric_source_ids_do_not_prove_a_common_carrier() {
    let options = ExecutionOptions::default();
    let scan = || {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, common::set_vol0_par3().into());
        let mut scanner = PacketScanner::new(
            Arc::new(access),
            SourceId(1),
            options.clone(),
            ScanLimits::default(),
        )
        .unwrap();
        let mut packets = Vec::new();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            packets.push(packet);
        }
        packets
    };
    let mut packets = scan();
    assert!(par3_rs::carrier::CarrierPlan::capture(&packets, &options).is_ok());
    let independent = scan();
    assert!(!packets[0].origin().same_carrier(&independent[0].origin()));
    packets[1] = independent[1].clone();
    assert!(par3_rs::carrier::CarrierPlan::capture(&packets, &options).is_err());
}

#[test]
fn bounded_out_of_order_evidence_distinguishes_damage_and_verified_prefix() {
    let set = common::gf8_set();
    let options = ExecutionOptions::default();
    let layout = Arc::new(BlockLayout::new(&set, &options).unwrap());
    let data = common::a_bin();
    let snapshot = SourceSnapshot {
        len: data.len() as u64,
        generation: 1,
    };
    let mut verifier =
        StreamingVerifier::new(layout.clone(), 0, SourceId(3), snapshot, options.clone()).unwrap();
    verifier.feed(1000, &data[1000..]).unwrap();
    verifier.feed(0, &data[..1000]).unwrap();
    let evidence = verifier.finish();
    assert!(evidence.protected_complete());
    assert_eq!(evidence.verified_prefix(&layout).unwrap(), 5000);
    let mut damaged = data;
    damaged[2400] ^= 1;
    let mut verifier =
        StreamingVerifier::new(layout.clone(), 0, SourceId(3), snapshot, options).unwrap();
    verifier.feed(0, &damaged).unwrap();
    let evidence = verifier.finish();
    assert!(!evidence.protected_complete());
    assert_eq!(evidence.verified_prefix(&layout).unwrap(), 2000);
    assert_eq!(evidence.verdicts()[1], ExtentVerdict::Damaged);
    assert_eq!(
        evidence.unresolved_ranges(&layout).unwrap(),
        vec![2000..4000]
    );
}

#[test]
fn forward_memory_reader_verifies_and_memory_limit_fails_before_allocation() {
    let set = common::gf8_set();
    let options = ExecutionOptions::default();
    let layout = Arc::new(BlockLayout::new(&set, &options).unwrap());
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(7), 4, common::a_bin().into());
    assert!(
        verify_source(layout, 0, &access, SourceId(7), &options)
            .unwrap()
            .protected_complete()
    );
    let mut small = ExecutionOptions::default();
    small.memory = MemoryBudget::new(8);
    assert!(matches!(
        PacketScanner::new(Arc::new(access), SourceId(7), small, ScanLimits::default()),
        Err(EngineError::ResourceLimit(_))
    ));
}

#[test]
fn arrivals_preserve_verified_extents_without_rereading_them() {
    let options = ExecutionOptions::default();
    let layout = Arc::new(BlockLayout::new(&common::gf8_set(), &options).unwrap());
    let source = ArrivingSource {
        bytes: common::a_bin(),
        visible: AtomicUsize::new(2000),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
    };
    let first = verify_source(layout.clone(), 0, &source, SourceId(1), &options).unwrap();
    assert_eq!(first.verified_prefix(&layout).unwrap(), 2000);
    source.visible.store(5000, Ordering::Relaxed);
    source.reads.store(0, Ordering::Relaxed);
    let complete =
        par3_rs::evidence::verify_arrivals(layout.clone(), &first, &source, &options).unwrap();
    assert!(complete.protected_complete());
    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        2,
        "only the unresolved block and tail are read"
    );
    source.reads.store(0, Ordering::Relaxed);
    let replay = par3_rs::evidence::verify_arrivals(layout, &complete, &source, &options).unwrap();
    assert!(replay.protected_complete());
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn sliding_placement_restores_a_missing_file_from_an_explicit_virtual_candidate() {
    use par3_rs::placement::{PlacementOptions, search_extent};
    use par3_rs::session::RepairStatus;
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.stripe_bytes = 127;
    let mut access = MemorySourceAccess::default();
    let mut moved = vec![0xa5; 4097];
    moved.extend(common::a_bin());
    access.insert(SourceId(1), 1, moved.into());
    access.insert(SourceId(2), 1, common::b_txt().into());
    access.insert(SourceId(3), 1, common::c_bin().into());
    let access = Arc::new(access);
    let mut session =
        par3_rs::Par3RepairSession::new(common::SET_ID, access.clone(), options.clone()).unwrap();
    merge_carrier(&mut session, common::set_par3(), &options);
    session.bind_file("b.txt", SourceId(2)).unwrap();
    session.bind_file("sub/c.bin", SourceId(3)).unwrap();
    let layout = session.layout().unwrap().unwrap();
    let limits = PlacementOptions::default();
    for extent in 0..layout.files()[0].extents.len() {
        let report = search_extent(
            &layout,
            0,
            extent,
            access.as_ref(),
            &[SourceId(1)],
            &limits,
            &options,
        )
        .unwrap();
        assert!(!report.matches.is_empty());
        session.add_placement(report.matches[0].clone()).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert!(session.assess().unwrap().lost_blocks.is_empty());
    let output = common::TempTree::new("placed-virtual");
    let report = session.repair(output.path(), false).unwrap();
    assert_eq!(report.installed.len(), 1);
    assert_eq!(
        std::fs::read(output.path().join("a.bin")).unwrap(),
        common::a_bin()
    );
}

fn merge_carrier(
    session: &mut par3_rs::Par3RepairSession,
    bytes: Vec<u8>,
    options: &ExecutionOptions,
) {
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(99), 1, bytes.into());
    let mut scanner = PacketScanner::new(
        Arc::new(source),
        SourceId(99),
        options.clone(),
        ScanLimits::default(),
    )
    .unwrap();
    loop {
        match scanner.poll().unwrap() {
            ScanEvent::Packet(packet) => {
                session.merge(packet).unwrap();
            }
            ScanEvent::End => break,
            ScanEvent::NeedData { offset } => panic!("complete carrier needs data at {offset}"),
        }
    }
}

#[test]
fn checkpoint_restart_preserves_partial_proofs_and_rejects_stale_or_altered_bytes() {
    let options = ExecutionOptions::default();
    let source = Arc::new(ArrivingSource {
        bytes: common::a_bin(),
        visible: AtomicUsize::new(2000),
        generation: AtomicU64::new(1),
        reads: AtomicUsize::new(0),
    });
    let reopen = || {
        let mut session =
            par3_rs::Par3RepairSession::new(common::SET_ID, source.clone(), options.clone())
                .unwrap();
        merge_carrier(&mut session, common::set_par3(), &options);
        session.bind_file("a.bin", SourceId(1)).unwrap();
        session
    };
    let mut original = reopen();
    original.assess().unwrap();
    let checkpoint = original.checkpoint_file("a.bin").unwrap().unwrap();
    // The host persists this digest independently of the checkpoint blob.
    let trusted_digest = checkpoint.digest();
    drop(original);
    source.reads.store(0, Ordering::Relaxed);
    let mut restored = reopen();
    restored
        .replay_evidence(checkpoint.as_bytes(), trusted_digest)
        .unwrap();
    restored.assess().unwrap();
    restored.assess().unwrap();
    merge_carrier(&mut restored, common::set_vol0_par3(), &options);
    restored.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    source.visible.store(5000, Ordering::Relaxed);
    restored.source_arrived(SourceId(1)).unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 2);
    let complete = restored.checkpoint_file("a.bin").unwrap().unwrap();
    drop(restored);
    source.reads.store(0, Ordering::Relaxed);
    let mut restored = reopen();
    restored
        .replay_evidence(complete.as_bytes(), complete.digest())
        .unwrap();
    restored.source_arrived(SourceId(1)).unwrap();
    restored.assess().unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);

    let baseline = options.memory.used();
    let mut altered = complete.as_bytes().to_vec();
    *altered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        restored.replay_evidence(&altered, complete.digest()),
        Err(EngineError::InvalidState(
            "evidence checkpoint digest mismatch"
        ))
    ));
    assert!(restored.replay_evidence(&[], complete.digest()).is_err());
    restored.bind_file("a.bin", SourceId(2)).unwrap();
    assert!(
        restored
            .replay_evidence(complete.as_bytes(), complete.digest())
            .is_err()
    );
    restored.bind_file("a.bin", SourceId(1)).unwrap();
    source.generation.store(2, Ordering::Relaxed);
    assert!(matches!(
        restored.replay_evidence(complete.as_bytes(), complete.digest()),
        Err(EngineError::SourceChanged(SourceId(1)))
    ));
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    assert!(options.memory.used() <= baseline);
    drop(restored);
    drop(complete);
    drop(checkpoint);
    assert_eq!(options.memory.used(), 0);
}

#[test]
fn checkpoint_allocation_and_cancellation_release_reservations() {
    let options = ExecutionOptions::default();
    let layout = Arc::new(BlockLayout::new(&common::gf8_set(), &options).unwrap());
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, common::a_bin().into());
    let evidence = verify_source(layout, 0, &access, SourceId(1), &options).unwrap();
    assert_eq!(evidence.whole_matches(), Some(true));
    let mut constrained = options.clone();
    constrained.memory = MemoryBudget::new(1);
    assert!(matches!(
        evidence.checkpoint(&constrained),
        Err(EngineError::ResourceLimit(_))
    ));
    assert_eq!(constrained.memory.used(), 0);
    let before = options.memory.used();
    let checkpoint = evidence.checkpoint(&options).unwrap();
    assert_eq!(options.memory.used(), before + checkpoint.retained_bytes());
    drop(checkpoint);
    options.cancel.cancel();
    assert!(matches!(
        evidence.checkpoint(&options),
        Err(EngineError::Cancelled)
    ));
    assert_eq!(options.memory.used(), before);
    drop(evidence);
    assert_eq!(options.memory.used(), 0);
}

#[test]
fn retained_virtual_repair_reuses_analysis_when_recovery_arrives() {
    use par3_rs::session::RepairStatus;
    let mut options = ExecutionOptions::default();
    options.workers = 2;
    options.stripe_bytes = 128;
    let mut access = MemorySourceAccess::default();
    let mut bytes = common::a_bin();
    bytes[2300] ^= 1;
    access.insert(SourceId(1), 1, bytes.into());
    access.insert(SourceId(2), 1, common::b_txt().into());
    access.insert(SourceId(3), 1, common::c_bin().into());
    let mut session =
        par3_rs::Par3RepairSession::new(common::SET_ID, Arc::new(access), options.clone()).unwrap();
    session.bind_file("a.bin", SourceId(1)).unwrap();
    session.bind_file("b.txt", SourceId(2)).unwrap();
    session.bind_file("sub/c.bin", SourceId(3)).unwrap();
    merge_carrier(&mut session, common::set_par3(), &options);
    assert_eq!(session.assess().unwrap().status, RepairStatus::NeedRecovery);
    assert_eq!(session.assess().unwrap().lost_blocks, vec![1]);
    assert_eq!(session.diagnostics().source_verifications, 3);
    let before = session.diagnostics().assessment_reuses;
    session.assess().unwrap();
    assert!(session.diagnostics().assessment_reuses > before);
    merge_carrier(&mut session, common::set_vol0_par3(), &options);
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(session.diagnostics().source_verifications, 3);
    let directory = common::TempTree::new("retained-virtual");
    let report = session.repair(directory.path(), true).unwrap();
    assert_eq!(report.installed.len(), 1);
    assert_eq!(report.reconstructed_blocks, 1);
    assert_eq!(
        std::fs::read(directory.path().join("a.bin")).unwrap(),
        common::a_bin()
    );
    assert!(!directory.path().join("b.txt").exists());
    assert!(!directory.path().join("sub/c.bin").exists());
}
