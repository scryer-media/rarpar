//! What the engine reserves, where it is attributed, and when it is given back.
//!
//! Every test here reads [`MemoryBudget::ledger`], which is the only surface
//! that says *which* structure holds a budget's bytes. The questions it answers
//! are the ones a host asks when a job is refused: did anything leak, does the
//! set fit at all, and is a peer holding the memory instead.
mod common;

use par3_rs::ScanLimits;
use par3_rs::ingest::{IncrementalSet, PacketScanner, ScanEvent};
use par3_rs::runtime::{
    EngineError, ExecutionOptions, LimitCause, MemoryBudget, MemoryCategory, ProgressCallback,
    ProgressPhase, Stage,
};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{MemorySourceAccess, SourceId};
use std::sync::Arc;

/// Scan one carrier's packets with `options`, to the end of the source.
fn packets(bytes: Vec<u8>, options: &ExecutionOptions) -> Vec<par3_rs::ingest::IngestedPacket> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(9), 1, bytes.into());
    let mut scanner = PacketScanner::new(
        Arc::new(access),
        SourceId(9),
        options.clone(),
        ScanLimits::default(),
    )
    .unwrap();
    let mut collected = Vec::new();
    while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
        collected.push(packet);
    }
    collected
}

/// The three-file reference set, with `a.bin` damaged in one block.
fn damaged_session(options: &ExecutionOptions) -> Par3RepairSession {
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
    for packet in packets(common::set_vol0_par3(), options) {
        session.merge(packet).unwrap();
    }
    session
}

#[test]
fn a_verify_and_repair_returns_every_ledger_category_to_zero() {
    let options = ExecutionOptions::default();
    let mut session = damaged_session(&options);
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let output = common::TempTree::new("ledger-zero");
    assert_eq!(
        session
            .repair(output.path(), false)
            .unwrap()
            .reconstructed_blocks,
        1
    );
    assert_eq!(
        std::fs::read(output.path().join("a.bin")).unwrap(),
        common::a_bin()
    );

    // While the session lives its retained state is still charged, and the
    // ledger must agree with the budget about how much and to whom.
    let held = options.memory.ledger();
    assert_eq!(held.current(), options.memory.used() as u64);
    assert!(held.category(MemoryCategory::CarrierPackets).current > 0);

    drop(session);
    let ledger = options.memory.ledger();
    assert_eq!(options.memory.used(), 0);
    for (category, entry) in ledger.iter() {
        assert_eq!(
            entry.current,
            0,
            "{} still holds {} bytes after the session was dropped",
            category.name(),
            entry.current
        );
    }
    // Nothing on a verify-and-repair path may reserve without naming itself.
    let uncategorized = ledger.category(MemoryCategory::Uncategorized);
    assert_eq!(
        uncategorized.reservations, 0,
        "{} untagged reservations were taken",
        uncategorized.reservations
    );
    // The work actually happened, and the categories that did it say so.
    assert!(ledger.category(MemoryCategory::ResolvedMetadata).peak > 0);
    assert!(ledger.category(MemoryCategory::LayoutEvidence).peak > 0);
    assert!(ledger.category(MemoryCategory::Assessment).peak > 0);
    assert!(ledger.category(MemoryCategory::CodecScratch).peak > 0);
}

/// Build a set of `blocks` 64-byte blocks and return its carriers' bytes.
fn many_block_carriers(
    blocks: usize,
    interleave: u64,
    seed: &[u8],
    tree: &common::TempTree,
) -> (par3_rs::InputSetId, Vec<u8>, Vec<std::path::PathBuf>) {
    use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
    let mut bytes = vec![0; blocks * 64];
    let mut hash = blake3::Hasher::new();
    hash.update(seed);
    hash.finalize_xof().fill(&mut bytes);
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.clone().into());
    let mut options = CreationOptions {
        block_size: 64,
        recovery_count: 3,
        codec: CreationCodec::Fft {
            capacity_log2: 0,
            interleave,
        },
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.memory = MemoryBudget::new(768 << 20);
    options.execution.retained_bytes = 384 << 20;
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options.clone(),
    )
    .unwrap();
    let id = plan.input_set_id();
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    (id, bytes, paths)
}

#[test]
fn a_many_block_set_resolves_under_a_ceiling_the_old_whole_ceiling_reservation_refused() {
    let tree = common::TempTree::new("measured-resolution");
    let (id, _bytes, paths) =
        many_block_carriers(16_384, 2, b"PAR3 measured metadata charge", &tree);

    // Resolution is budgeted on its own, so read the index carrier alone.
    let index = std::fs::read(&paths[0]).unwrap();
    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(8 << 20);
    options.retained_bytes = 4 << 20;

    let scanned = packets(index, &options);
    // What the previous accounting would have demanded before resolving
    // anything: sixteen times each packet's wire length, plus per-packet
    // bookkeeping, reserved as one block against the retained ceiling.
    let whole_ceiling: usize = 8192
        + scanned
            .iter()
            .filter_map(|packet| packet.metadata())
            .map(|packet| packet.len() as usize * 16 + 1024)
            .sum::<usize>();
    assert!(
        whole_ceiling > options.retained_bytes,
        "this set must be one the old reservation refused: it asked for {whole_ceiling} bytes \
         against a {} byte ceiling",
        options.retained_bytes
    );

    let mut set = IncrementalSet::new(id, options.clone()).unwrap();
    for packet in scanned {
        set.merge(packet).unwrap();
    }
    let resolved = set.metadata().unwrap().expect("a complete index carrier");
    assert_eq!(resolved.files().len(), 1);
    let capacity = resolved.retained_capacity_bytes();
    println!(
        "16,384 blocks: old whole-ceiling reservation {whole_ceiling} bytes, \
         resolved capacity {capacity} bytes, ceiling {}, budget peak {}",
        options.retained_bytes,
        options.memory.peak()
    );
    assert!(
        capacity < options.retained_bytes,
        "the live structures must fit: {capacity} bytes against {}",
        options.retained_bytes
    );
    drop(resolved);
    drop(set);
    assert_eq!(options.memory.used(), 0);
    let ledger = options.memory.ledger();
    assert_eq!(ledger.current(), 0);
    assert_eq!(
        ledger.category(MemoryCategory::Uncategorized).reservations,
        0
    );
}

#[test]
fn an_expanding_metadata_graph_is_refused_by_name_rather_than_by_exhaustion() {
    use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource};
    // A set whose directory tree is wide and deep enough that resolving it
    // costs many times what its packets weigh. Nothing here is hand-assembled:
    // the carrier is written by this crate's own creation engine.
    let tree = common::TempTree::new("expanding-graph");
    let mut access = MemorySourceAccess::default();
    let mut sources = Vec::new();
    for index in 0..256u64 {
        access.insert(SourceId(index + 1), 1, vec![index as u8; 64].into());
        let nesting: String = (0..8)
            .map(|level| format!("a-directory-with-a-deliberately-long-name-{index}-{level}/"))
            .collect();
        sources.push(CreationSource {
            name: format!("{nesting}file-{index}.bin"),
            source: SourceId(index + 1),
        });
    }
    let mut creation = CreationOptions {
        block_size: 64,
        recovery_count: 1,
        ..CreationOptions::default()
    };
    creation.execution.workers = 1;
    let plan = CreationPlan::build(Arc::new(access), &sources, creation).unwrap();
    let id = plan.input_set_id();
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    let index = std::fs::read(&paths[0]).unwrap();

    // What retaining the packets themselves costs, so every ceiling below is
    // one that admits them and only starves the expansion.
    let generous = ExecutionOptions::default();
    let footprint = {
        let mut set = IncrementalSet::new(id, generous.clone()).unwrap();
        for packet in packets(index.clone(), &generous) {
            set.merge(packet).unwrap();
        }
        let held = set.retained_bytes();
        assert!(set.metadata().unwrap().is_some(), "the carrier is complete");
        held
    };

    let mut refusals = 0usize;
    let mut expansion_refusals = 0usize;
    let mut resolutions = 0usize;
    for step in 1..=16usize {
        let mut options = ExecutionOptions::default();
        options.memory = MemoryBudget::new(64 << 20);
        options.retained_bytes = footprint + footprint * step / 4;
        let mut set = IncrementalSet::new(id, options.clone()).unwrap();
        for packet in packets(index.clone(), &options) {
            set.merge(packet).unwrap();
        }
        match set.metadata() {
            Ok(Some(_)) => resolutions += 1,
            Ok(None) => panic!("the carrier is complete; resolution cannot ask for more packets"),
            Err(EngineError::ResourceLimit(limit)) => {
                refusals += 1;
                expansion_refusals += usize::from(limit.what == "metadata expansion");
                assert!(
                    limit.what.contains("metadata"),
                    "the refusal must name the limit it hit: {limit}"
                );
                assert!(
                    limit.need > 0,
                    "a measured refusal states what it needed: {limit}"
                );
                assert!(
                    limit.limit > 0,
                    "a measured refusal states its ceiling: {limit}"
                );
                // The budget here is 64 MiB against ceilings measured in tens
                // of kilobytes, and this session is alone on it. Nothing can
                // release to make room, so every refusal must be terminal or a
                // host would requeue the job forever.
                assert_eq!(
                    limit.cause(),
                    LimitCause::ExceedsLimit,
                    "no peer holds this budget, so the refusal cannot be contention: {limit}"
                );
                assert!(!limit.contended(), "{limit}");
            }
            Err(other) => panic!("an expanding graph must be refused cleanly: {other:?}"),
        }
        drop(set);
        assert_eq!(options.memory.used(), 0, "a refused resolution kept bytes");
        assert_eq!(options.memory.ledger().current(), 0);
    }
    assert!(refusals > 0, "some ceiling in this sweep must be too small");
    assert!(
        expansion_refusals > 0,
        "the directory expansion itself must be what refuses at least once"
    );
    assert!(resolutions > 0, "some ceiling in this sweep must be enough");
}

#[test]
fn a_refusal_says_whether_it_can_never_fit_or_a_peer_is_holding_the_memory() {
    let scan_options = ExecutionOptions::default();

    // What one session of this set actually costs, measured rather than assumed.
    let footprint = {
        let options = ExecutionOptions::default();
        let mut set = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
        for packet in packets(common::set_vol0_par3(), &scan_options) {
            set.merge(packet).unwrap();
        }
        let used = options.memory.used();
        drop(set);
        assert_eq!(options.memory.used(), 0);
        used
    };
    assert!(footprint > 0);

    // A budget too small for the very first packet: no peer can ever release
    // enough, because the request is larger than the whole ceiling.
    let mut alone = ExecutionOptions::default();
    alone.memory = MemoryBudget::new(64);
    let mut refused = IncrementalSet::new(common::SET_ID, alone.clone()).unwrap();
    let error = packets(common::set_vol0_par3(), &scan_options)
        .into_iter()
        .find_map(|packet| refused.merge(packet).err())
        .expect("a 64 byte budget cannot hold a packet");
    match error {
        EngineError::ResourceLimit(limit) => {
            assert_eq!(limit.cause(), LimitCause::ExceedsLimit, "{limit}");
            assert!(!limit.contended());
            assert!(limit.need > limit.limit, "{limit}");
            assert!(limit.to_string().contains("does not fit alone"), "{limit}");
        }
        other => panic!("expected a measured resource limit: {other:?}"),
    }
    drop(refused);
    assert_eq!(alone.memory.used(), 0);

    // Now two sessions share one budget with room for roughly one of them. The
    // second asks for exactly what the first was granted, so its refusal is
    // contention and not geometry.
    let shared = MemoryBudget::new(footprint + footprint / 2);
    let mut options = ExecutionOptions::default();
    options.memory = shared.clone();
    let mut first = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    for packet in packets(common::set_vol0_par3(), &scan_options) {
        first.merge(packet).unwrap();
    }
    let mut second = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    let error = packets(common::set_vol0_par3(), &scan_options)
        .into_iter()
        .find_map(|packet| second.merge(packet).err())
        .expect("the budget has room for one session, not two");
    match error {
        EngineError::ResourceLimit(limit) => {
            assert_eq!(limit.cause(), LimitCause::PeerContention, "{limit}");
            assert!(limit.contended());
            assert!(limit.need <= limit.limit, "{limit}");
            assert!(limit.need > limit.available, "{limit}");
            assert!(
                limit
                    .to_string()
                    .contains("does not fit beside the memory already reserved"),
                "{limit}"
            );
        }
        other => panic!("expected a measured resource limit: {other:?}"),
    }
    drop(second);
    drop(first);
    assert_eq!(shared.used(), 0);
    assert_eq!(shared.ledger().current(), 0);
}

#[test]
fn a_resolution_a_peer_is_squeezing_out_is_contention_and_resolves_once_the_peer_leaves() {
    // Scanning is done on its own ample budget so that only the sets under test
    // draw on the shared one, and the packets are rehomed as they are merged.
    let scan_options = ExecutionOptions::default();

    // What one session of this set costs end to end, measured rather than
    // assumed: the bytes its packets hold, and the peak a full resolution hits.
    let solo = ExecutionOptions::default();
    let mut probe = IncrementalSet::new(common::SET_ID, solo.clone()).unwrap();
    for packet in packets(common::set_vol0_par3(), &scan_options) {
        probe.merge(packet).unwrap();
    }
    let held = solo.memory.used();
    assert!(
        probe.metadata().unwrap().is_some(),
        "the reference carrier resolves when nothing competes"
    );
    let solo_peak = solo.memory.peak();
    drop(probe);
    assert!(held > 0 && solo_peak > held);

    // A budget with room for one resolution and a little more. Peers are added
    // until the subject can no longer resolve; nothing about the subject, its
    // options or its packets changes as they arrive.
    let shared = MemoryBudget::new(solo_peak + held);
    let mut options = ExecutionOptions::default();
    options.memory = shared.clone();
    let mut subject = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    for packet in packets(common::set_vol0_par3(), &scan_options) {
        subject.merge(packet).unwrap();
    }
    assert!(
        subject.metadata().unwrap().is_some(),
        "the subject resolves while it is alone on the shared budget"
    );

    let mut peers = Vec::new();
    let refusal = loop {
        assert!(
            peers.len() < 64,
            "the shared budget never became contended enough to refuse"
        );
        let mut peer = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
        for packet in packets(common::set_vol0_par3(), &scan_options) {
            if peer.merge(packet).is_err() {
                break;
            }
        }
        peers.push(peer);
        match subject.metadata() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("the carrier is complete; resolution cannot ask for more packets"),
            Err(EngineError::ResourceLimit(limit)) => break limit,
            Err(other) => panic!("a contended resolution must be refused cleanly: {other:?}"),
        }
    };
    assert_eq!(
        refusal.cause(),
        LimitCause::PeerContention,
        "this set resolved alone under the same options, so its refusal is retryable: {refusal}"
    );
    assert!(refusal.contended(), "{refusal}");
    assert!(
        refusal.need <= refusal.limit,
        "a retryable refusal fits its ceiling: {refusal}"
    );

    // The whole point of calling it contention: releasing admits it unchanged.
    drop(peers);
    assert!(
        subject.metadata().unwrap().is_some(),
        "the same request must be admitted once the peers release"
    );
    drop(subject);
    assert_eq!(shared.used(), 0);
    assert_eq!(shared.ledger().current(), 0);
}

#[test]
fn a_retained_ceiling_refusal_is_terminal_even_when_the_budget_is_untouched() {
    let scan_options = ExecutionOptions::default();

    // `retained_bytes` is this session's own ceiling. However much of the
    // shared budget is free, and however long a host waits, nothing else is
    // drawing on it, so both refusals below have to read as terminal.
    let ample = || {
        let mut options = ExecutionOptions::default();
        options.memory = MemoryBudget::new(64 << 20);
        options
    };

    // Small enough that retaining the packets themselves overruns it.
    let mut options = ample();
    options.retained_bytes = 1024;
    let mut set = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    let error = packets(common::set_vol0_par3(), &scan_options)
        .into_iter()
        .find_map(|packet| set.merge(packet).err())
        .expect("a 1 KiB retained ceiling cannot hold this set's packets");
    match error {
        EngineError::ResourceLimit(limit) => {
            assert_eq!(limit.what, "retained metadata");
            assert_eq!(
                limit.cause(),
                LimitCause::ExceedsLimit,
                "a per-session ceiling is never waited out: {limit}"
            );
            assert!(!limit.contended(), "{limit}");
            assert!(limit.need > limit.limit, "{limit}");
        }
        other => panic!("expected a measured resource limit: {other:?}"),
    }
    drop(set);
    assert_eq!(options.memory.used(), 0);

    // Wide enough for the packets, too narrow to resolve them.
    let footprint = {
        let held = ExecutionOptions::default();
        let mut set = IncrementalSet::new(common::SET_ID, held.clone()).unwrap();
        for packet in packets(common::set_vol0_par3(), &scan_options) {
            set.merge(packet).unwrap();
        }
        set.retained_bytes()
    };
    let mut options = ample();
    options.retained_bytes = footprint + 4096;
    let mut set = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    for packet in packets(common::set_vol0_par3(), &scan_options) {
        set.merge(packet).unwrap();
    }
    match set.metadata() {
        Err(EngineError::ResourceLimit(limit)) => {
            assert!(limit.what.contains("metadata"), "{limit}");
            assert_eq!(
                limit.cause(),
                LimitCause::ExceedsLimit,
                "the budget is 64 MiB and untouched; only the session's own \
                 ceiling refused this: {limit}"
            );
            assert!(!limit.contended(), "{limit}");
            assert!(limit.to_string().contains("does not fit alone"), "{limit}");
        }
        Ok(_) => panic!("a ceiling below the resolution base cannot resolve this set"),
        Err(other) => panic!("expected a measured resource limit: {other:?}"),
    }
    drop(set);
    assert_eq!(options.memory.used(), 0);
    assert_eq!(options.memory.ledger().current(), 0);
}

fn cancel_at(stage: Stage) -> ExecutionOptions {
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let cancel = options.cancel.clone();
    options.progress = Some(ProgressCallback::new(move |event| {
        if event.stage == stage && event.phase == ProgressPhase::Begin {
            cancel.cancel();
        }
    }));
    options
}

#[test]
fn cancelling_metadata_resolution_leaves_no_bytes_behind() {
    let options = cancel_at(Stage::Metadata);
    let before = options.memory.available();
    let carrier = packets(common::set_vol0_par3(), &options);
    let mut set = IncrementalSet::new(common::SET_ID, options.clone()).unwrap();
    for packet in carrier {
        set.merge(packet).unwrap();
    }
    let held = options.memory.used();
    assert!(matches!(set.metadata(), Err(EngineError::Cancelled)));
    assert_eq!(
        options.memory.used(),
        held,
        "a cancelled resolution keeps nothing"
    );
    drop(set);
    assert_eq!(options.memory.used(), 0);
    assert_eq!(options.memory.available(), before);
    assert_eq!(options.memory.ledger().current(), 0);
}

#[test]
fn cancelling_verification_and_repair_leaves_no_bytes_behind() {
    for stage in [Stage::Verify, Stage::Repair] {
        let options = cancel_at(stage);
        let before = options.memory.available();
        let mut session = damaged_session(&options);
        let tree = common::TempTree::new("cancel-ledger");
        let error = match stage {
            Stage::Verify => session.assess().map(|_| ()).unwrap_err(),
            _ => {
                // Assessment must complete before repair can be cancelled, so
                // arm the token only once the repair stage opens.
                let mut plain = ExecutionOptions::default();
                plain.workers = 1;
                let mut ready = damaged_session(&plain);
                assert_eq!(ready.assess().unwrap().status, RepairStatus::Ready);
                drop(ready);
                let _ = session.assess();
                session.repair(tree.path(), false).map(|_| ()).unwrap_err()
            }
        };
        assert!(matches!(error, EngineError::Cancelled), "{error}");
        drop(session);
        assert_eq!(options.memory.used(), 0, "{stage:?} leaked bytes");
        assert_eq!(options.memory.available(), before);
        for (category, entry) in options.memory.ledger().iter() {
            assert_eq!(
                entry.current,
                0,
                "{} leaked after {stage:?}",
                category.name()
            );
        }
    }
}

/// The geometry the memory arc exists for: 131,072 full 64-byte blocks across
/// three interleaved cohorts, verified and repaired under half a gigabyte.
///
/// Run with `cargo nextest run -p par3-rs --run-ignored only -E
/// 'test(a_hundred_and_thirty_one_thousand_block_set_under_half_a_gigabyte)'`.
/// Fitting is the objective; the test reports the ledger either way.
#[test]
#[ignore = "geometry probe: minutes of encoding and a 512 MiB budget"]
fn a_hundred_and_thirty_one_thousand_block_set_under_half_a_gigabyte() {
    let tree = common::TempTree::new("geometry-probe");
    // `interleave` is the count above one, so two gives three cohorts.
    let (id, bytes, paths) =
        many_block_carriers(131_072, 2, b"PAR3 geometry probe 131072 blocks", &tree);

    let mut damaged = bytes.clone();
    // One block in each of the three cohorts, so every cohort has to decode.
    for block in [7usize, 40_001, 131_070] {
        damaged[block * 64 + 11] ^= 0x80;
    }
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 2, damaged.into());

    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.memory = MemoryBudget::new(512 << 20);
    options.retained_bytes = 256 << 20;

    let report = (|| -> Result<usize, EngineError> {
        let mut session = Par3RepairSession::new(id, Arc::new(access), options.clone())?;
        session.bind_file("input.bin", SourceId(1))?;
        for path in &paths {
            for packet in packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet)?;
            }
        }
        let assessment = session.assess()?;
        assert_eq!(assessment.status, RepairStatus::Ready);
        let output = common::TempTree::new("geometry-probe-out");
        let repaired = session.repair(output.path(), false)?.reconstructed_blocks;
        assert_eq!(
            std::fs::read(output.path().join("input.bin")).unwrap(),
            bytes
        );
        Ok(repaired as usize)
    })();

    println!("--- 131,072-block probe, 512 MiB budget, 256 MiB retained ---");
    match &report {
        Ok(blocks) => println!("repaired {blocks} blocks"),
        Err(EngineError::ResourceLimit(limit)) => println!(
            "refused: what={} need={} limit={} available={} cause={:?}",
            limit.what,
            limit.need,
            limit.limit,
            limit.available,
            limit.cause()
        ),
        Err(error) => println!("failed: {error}"),
    }
    println!(
        "budget peak {} of {}",
        options.memory.peak(),
        options.memory.limit()
    );
    for (category, entry) in options.memory.ledger().iter() {
        println!(
            "{:<28} peak {:>12}  reservations {:>8}",
            category.name(),
            entry.peak,
            entry.reservations
        );
    }
    report.expect("the probe reports its refusal above before failing");
}
