//! What the engine reserves, where it is attributed, and when it is given back.
//!
//! Every test here reads [`MemoryBudget::ledger`], which is the only surface
//! that says *which* structure holds a budget's bytes. The questions it answers
//! are the ones a host asks when a job is refused: did anything leak, does the
//! set fit at all, and is a peer holding the memory instead.
mod common;

use par3_rs::ScanLimits;
use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource, Deduplication};
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
#[test]
fn a_many_block_set_resolves_under_a_ceiling_the_old_whole_ceiling_reservation_refused() {
    let tree = common::TempTree::new("measured-resolution");
    let (id, _bytes, paths) =
        common::many_block_carriers(16_384, 2, b"PAR3 measured metadata charge", &tree);

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

/// Cancellation at every stage of a repair, including the two M1 added to the
/// inventory: the assessment handover, where scratch is released and the
/// measured result is charged, and the tiled Cauchy decode, where only part of
/// the row bank is materialised at a time.
///
/// Every stage must refund exactly: the ledger and `available()` return to
/// their pre-session values, no output is installed, and a fresh session over
/// the same inputs still produces the same bytes.
#[test]
fn cancelling_verification_and_repair_leaves_no_bytes_behind() {
    for stage in [Stage::Verify, Stage::Assess, Stage::Repair, Stage::Decode] {
        let options = cancel_at(stage);
        let before = options.memory.available();
        let mut session = damaged_session(&options);
        let tree = common::TempTree::new("cancel-ledger");
        let during_repair = matches!(stage, Stage::Repair | Stage::Decode);
        let error = if during_repair {
            // Assessment must complete before repair can be cancelled, so
            // arm the token only once the repair stage opens.
            let mut plain = ExecutionOptions::default();
            plain.workers = 1;
            let mut ready = damaged_session(&plain);
            assert_eq!(ready.assess().unwrap().status, RepairStatus::Ready);
            drop(ready);
            let _ = session.assess();
            session.repair(tree.path(), false).map(|_| ()).unwrap_err()
        } else {
            session.assess().map(|_| ()).unwrap_err()
        };
        match &error {
            // Cancelled before anything was staged.
            EngineError::Cancelled => {}
            // Cancelled with work on disk. That is recoverable, not silent: the
            // error names what was installed and what was left behind. Nothing
            // was verified here, so nothing was installed.
            EngineError::RepairInterrupted {
                installed,
                temporary,
                cause,
            } if during_repair => {
                assert!(
                    matches!(**cause, EngineError::Cancelled),
                    "{stage:?}: {cause}"
                );
                assert!(
                    installed.is_empty(),
                    "{stage:?} installed output before it was cancelled: {installed:?}"
                );
                for path in temporary {
                    assert_ne!(
                        path,
                        &tree.path().join("a.bin"),
                        "{stage:?} left a temporary in an installed file's place"
                    );
                }
            }
            other => panic!("{stage:?} failed for another reason: {other}"),
        }
        if during_repair {
            assert!(
                !tree.path().join("a.bin").exists(),
                "{stage:?} installed a file it never verified"
            );
        }
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

        // The same inputs still repair to the same bytes afterwards.
        let mut plain = ExecutionOptions::default();
        plain.workers = 1;
        let mut retry = damaged_session(&plain);
        assert_eq!(retry.assess().unwrap().status, RepairStatus::Ready);
        let output = common::TempTree::new("cancel-ledger-retry");
        assert_eq!(
            retry
                .repair(output.path(), false)
                .unwrap()
                .reconstructed_blocks,
            1,
            "{stage:?} left the inputs unrepairable"
        );
        assert_eq!(
            std::fs::read(output.path().join("a.bin")).unwrap(),
            common::a_bin(),
            "{stage:?} changed the repaired bytes"
        );
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
        common::many_block_carriers(131_072, 2, b"PAR3 geometry probe 131072 blocks", &tree);

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

    // Sample the ledger at every stage boundary, so the probe reports the same
    // working-set inventory as the many-blocks fixture at eight times the size.
    let mut samples = Vec::new();
    let report = (|| -> Result<usize, EngineError> {
        let sample = |label: &'static str, options: &ExecutionOptions| common::StageSample {
            label,
            ledger: options.memory.ledger(),
            used: options.memory.used(),
            peak: options.memory.peak(),
        };
        let mut session = Par3RepairSession::new(id, Arc::new(access), options.clone())?;
        session.bind_file("input.bin", SourceId(1))?;
        for path in &paths {
            for packet in packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet)?;
            }
        }
        samples.push(sample("scan + merge", &options));
        assert!(session.layout()?.is_some());
        samples.push(sample("metadata + layout", &options));
        let assessment = session.assess()?;
        assert_eq!(assessment.status, RepairStatus::Ready);
        samples.push(sample("verify + assess", &options));
        let output = common::TempTree::new("geometry-probe-out");
        let repaired = session.repair(output.path(), false)?.reconstructed_blocks;
        samples.push(sample("after repair", &options));
        assert_eq!(
            std::fs::read(output.path().join("input.bin")).unwrap(),
            bytes
        );
        Ok(repaired as usize)
    })();
    samples.push(common::StageSample {
        label: "session dropped",
        ledger: options.memory.ledger(),
        used: options.memory.used(),
        peak: options.memory.peak(),
    });

    println!("--- 131,072-block probe, 512 MiB budget, 256 MiB retained ---");
    common::report(
        &samples,
        131_072,
        "131,072 blocks, one file, 256 MiB retained",
    );
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

/// Cancelling a verification that has started a private hashing pool, and one
/// whose verification buffer grew to a megabyte under the shared budget, must
/// refund both exactly. Those are C1's new reservations on the verify path:
/// the pool's worker stacks and the enlarged `SourceScratch` buffer.
#[test]
fn cancelling_a_parallel_verification_refunds_its_pool_and_its_buffer() {
    // One source over the 8 MiB gate that starts a pool at all.
    let mut bytes = vec![0u8; 12 << 20];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 parallel hash cancellation");
    hash.finalize_xof().fill(&mut bytes);
    let tree = common::TempTree::new("cancel-parallel-hash");
    let set = {
        use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
        tree.write("in/large.bin", &bytes);
        let options = CreateOptions::default()
            .with_block_size(65_536)
            .with_recovery(RecoveryAmount::Blocks(2));
        let base = tree.path().join("in");
        let files = [std::path::PathBuf::from("large.bin")];
        create(
            &InputSpec::new(&base, &files),
            &tree.path().join("set"),
            &options,
        )
        .expect("a set over the parallel gate")
    };
    assert!(set.files_written.len() > 1, "the set has a volume");

    let index = set.files_written[0].clone();
    let packets: Vec<_> = par3_rs::scan_packets_from_path(&index)
        .expect("the index scans")
        .into_iter()
        .map(|(_, packet)| packet)
        .collect();
    let parsed = par3_rs::Par3Set::from_packets(packets).expect("a set");
    let id = parsed[0].input_set_id();

    for workers in [1usize, 8] {
        let mut options = cancel_at(Stage::Verify);
        options.workers = workers;
        let before = options.memory.available();
        let mut protected = MemorySourceAccess::default();
        protected.insert(SourceId(1), 1, bytes.clone().into());
        let mut session = Par3RepairSession::new(id, Arc::new(protected), options.clone()).unwrap();
        session.bind_file("large.bin", SourceId(1)).unwrap();
        for packet in packets_from(&index, &options) {
            session.merge(packet).unwrap();
        }
        assert!(
            matches!(session.assess(), Err(EngineError::Cancelled)),
            "{workers} workers: verification was not cancelled"
        );
        drop(session);
        assert_eq!(options.memory.used(), 0, "{workers} workers leaked bytes");
        assert_eq!(options.memory.available(), before);
        for (category, entry) in options.memory.ledger().iter() {
            assert_eq!(
                entry.current,
                0,
                "{} leaked after a cancelled parallel verification",
                category.name()
            );
        }
    }
}

/// Scan one carrier file's packets with `options`.
fn packets_from(
    path: &std::path::Path,
    options: &ExecutionOptions,
) -> Vec<par3_rs::ingest::IngestedPacket> {
    packets(std::fs::read(path).expect("a carrier"), options)
}

/// Cancelling an FFT decode refunds the transform plan as exactly as everything
/// else, whether the cancellation lands before the plan is built or after it.
#[test]
fn cancelling_an_fft_decode_refunds_the_transform_plan() {
    use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let inputs = 900usize;
    let block = 8192u64;
    let geometry = FftGeometry::new(inputs as u64, 7).unwrap();
    let mut all = vec![0u8; inputs * block as usize];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 plan cancellation");
    hash.finalize_xof().fill(&mut all);
    let data: Vec<&[u8]> = all.chunks_exact(block as usize).collect();

    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(256 << 20);
    let codec = FftCodec::new(geometry, options.clone()).unwrap();
    let mut parity = vec![vec![0u8; block as usize]; 4];
    codec
        .encode(
            block,
            0,
            4,
            |index, offset, out| {
                out.copy_from_slice(&data[index][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, out| {
                parity[index][offset as usize..offset as usize + out.len()].copy_from_slice(out);
                Ok(())
            },
        )
        .unwrap();
    drop(codec);
    assert_eq!(options.memory.used(), 0);

    // `None` cancels as the decode stage opens, before the plan is built;
    // `Some(1)` and `Some(inputs)` cancel at the first and the last row the
    // workspace takes, with the plan built and its charge held. Cancellation
    // inside the pruned transform itself is covered by the unit test
    // `fft::plan_tests::a_cancelled_pruned_transform_gives_back_everything_the_plan_held`,
    // which is the only place the token can be set between the two.
    for after in [None, Some(1), Some(inputs)] {
        let mut options = ExecutionOptions::default();
        options.memory = MemoryBudget::new(256 << 20);
        if after.is_none() {
            let cancel = options.cancel.clone();
            options.progress = Some(ProgressCallback::new(move |event| {
                if event.stage == Stage::Decode && event.phase == ProgressPhase::Begin {
                    cancel.cancel();
                }
            }));
        }
        let before = options.memory.available();
        let codec = FftCodec::new(geometry, options.clone()).unwrap();
        let reads = AtomicUsize::new(0);
        let cancel = options.cancel.clone();
        let error = codec
            .decode(
                block,
                &[5],
                &[0],
                |row, offset, out| {
                    if let Some(limit) = after
                        && reads.fetch_add(1, Ordering::Relaxed) + 1 >= limit
                    {
                        cancel.cancel();
                    }
                    let from = match row {
                        FftInput::Original(index) => data[index],
                        FftInput::Recovery(index) => &parity[index],
                    };
                    out.copy_from_slice(&from[offset as usize..offset as usize + out.len()]);
                    Ok(())
                },
                |_, _, _| Ok(()),
            )
            .expect_err("a cancelled decode");
        assert!(
            matches!(error, EngineError::Cancelled),
            "{after:?}: {error:?}"
        );
        drop(codec);
        assert_eq!(options.memory.used(), 0, "{after:?} leaked bytes");
        assert_eq!(options.memory.available(), before);
        for (category, entry) in options.memory.ledger().iter() {
            assert_eq!(
                entry.current,
                0,
                "{} leaked after a cancelled decode at {after:?}",
                category.name()
            );
        }
    }
}

/// A carrier whose `files` sources hold the same bytes, so aligned
/// deduplication leaves every block named by one extent per file. The body's
/// 251-byte period means the file also dedups against itself, which is why the
/// aliased block count below is far smaller than `blocks`; what matters for the
/// charge is the extent count, which is `files` per aliased block.
fn aliased_set(files: usize, blocks: u64, block_size: u64) -> par3_rs::Par3Set {
    let body: Arc<[u8]> = (0..blocks * block_size)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>()
        .into();
    let mut access = MemorySourceAccess::default();
    let mut sources = Vec::new();
    for index in 0..files {
        access.insert(SourceId(index as u64), 1, Arc::clone(&body));
        sources.push(CreationSource {
            name: format!("copy{index}.bin"),
            source: SourceId(index as u64),
        });
    }
    let mut options = CreationOptions {
        block_size,
        recovery_count: 1,
        deduplication: Deduplication::Aligned,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.memory = MemoryBudget::new(1 << 30);
    options.execution.retained_bytes = 1 << 30;
    let plan = CreationPlan::build(Arc::new(access), &sources, options).unwrap();
    let carriers = common::TempTree::new("alias-charge");
    let paths = plan
        .execute(&carriers.path().join("set"), carriers.path())
        .unwrap();
    let packets = common::packets_of(&std::fs::read(&paths[0]).unwrap());
    par3_rs::Par3Set::from_packets_for(packets, plan.input_set_id()).unwrap()
}

/// Options with a private budget large enough for any layout here.
fn roomy() -> ExecutionOptions {
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.memory = MemoryBudget::new(256 << 20);
    options.retained_bytes = 256 << 20;
    options
}

/// What the alias containers really hold: one ordered-map entry per aliased
/// block and one location per extent naming it. Measured through the public
/// iterator, so the test does not restate the charge's own arithmetic.
fn measured_aliases(layout: &par3_rs::layout::BlockLayout) -> (usize, usize) {
    let mut blocks = 0usize;
    let mut locations = 0usize;
    for (_, at) in layout.blocks() {
        if at.len() > 1 {
            blocks += 1;
            locations += at.len();
        }
    }
    (blocks, locations)
}

#[test]
fn the_alias_charge_counts_one_location_for_every_extent_naming_a_block() {
    let options = roomy();
    let layout = par3_rs::layout::BlockLayout::new(&aliased_set(8, 50, 64), &options).unwrap();
    let (blocks, locations) = measured_aliases(&layout);
    assert_eq!(
        (blocks, locations),
        (50, 400),
        "eight copies of fifty blocks name each of them eight times"
    );
    assert_eq!(layout.aliased_blocks(), blocks);

    // The live bytes those containers hold. The charge rounds the per-block
    // vectors up to the capacity doubling can leave them at, so it must sit
    // between this and twice its location term, and never below it.
    let entry = 2 * (size_of::<u64>() + size_of::<Vec<(usize, usize)>>()) + 32;
    let live = blocks * entry + locations * size_of::<(usize, usize)>();
    let settled = layout.retained_bytes();
    assert!(
        settled >= live,
        "a layout holding {live} alias bytes settled at {settled}"
    );
    assert!(
        settled < 2 * live,
        "the alias charge is an upper bound, not a multiple: {settled} against {live}"
    );
    drop(layout);
    assert_eq!(options.memory.used(), 0);
}

#[test]
fn a_carrier_that_aliases_deeply_is_refused_before_the_locations_exist() {
    // Under a roomy budget the same set settles well over a mebibyte, all of
    // it locations: thirty-two files naming two thousand blocks each.
    let wide = aliased_set(32, 2000, 64);
    let roomy = roomy();
    let materialised = par3_rs::layout::BlockLayout::new(&wide, &roomy)
        .unwrap()
        .retained_bytes();
    assert!(
        materialised > (1 << 20),
        "the refusal below is only interesting if this really exceeds the ceiling: {materialised}"
    );

    let mut tight = ExecutionOptions::default();
    tight.workers = 1;
    tight.memory = MemoryBudget::new(256 << 20);
    tight.retained_bytes = 1 << 20;
    match par3_rs::layout::BlockLayout::new(&wide, &tight) {
        Err(EngineError::ResourceLimit(limit)) => {
            assert_eq!(limit.what, "retained layout aliases", "{limit}");
            assert_eq!(limit.cause(), LimitCause::ExceedsLimit, "{limit}");
            assert!(limit.need > limit.limit, "{limit}");
        }
        other => panic!("a 1 MiB ceiling must refuse {materialised} bytes: {other:?}"),
    }
    assert_eq!(tight.memory.used(), 0, "the refusal left bytes behind");
    for (category, entry) in tight.memory.ledger().iter() {
        assert_eq!(entry.current, 0, "{} leaked", category.name());
    }

    // The same blocks at a quarter of the depth still fit: it is the number of
    // extents naming each block that the old charge missed, not the blocks.
    let shallow = par3_rs::layout::BlockLayout::new(&aliased_set(4, 2000, 64), &tight).unwrap();
    assert!(shallow.retained_bytes() < (1 << 20));
    assert_eq!(shallow.aliased_blocks(), 251);
}

#[test]
fn cancelling_inside_the_alias_loop_gives_back_the_sweep_workspace() {
    let wide = aliased_set(32, 2000, 64);
    let options = roomy();
    let cancel = options.cancel.clone();
    let budget = options.memory.clone();
    // The alias reservation is over two megabytes and every other layout
    // reservation together is under a hundred kilobytes, so crossing this
    // threshold means the sweep has finished, the workspace is still held and
    // the location loop has begun.
    let watching = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready = Arc::clone(&watching);
    let watcher = std::thread::spawn(move || {
        ready.store(true, std::sync::atomic::Ordering::Release);
        while budget.used() < 1 << 20 {
            std::hint::spin_loop();
        }
        cancel.cancel();
    });
    while !watching.load(std::sync::atomic::Ordering::Acquire) {
        std::hint::spin_loop();
    }
    let error = par3_rs::layout::BlockLayout::new(&wide, &options)
        .expect_err("cancelled while the locations were being written");
    watcher.join().unwrap();
    assert!(matches!(error, EngineError::Cancelled), "{error:?}");
    assert_eq!(options.memory.used(), 0, "a cancelled sweep leaked bytes");
    for (category, entry) in options.memory.ledger().iter() {
        assert_eq!(
            entry.current,
            0,
            "{} leaked after a cancelled build_index",
            category.name()
        );
    }
}

/// What building a GF(2^16) field peaks at, computed the way the engine's own
/// `gf::construction_cost` does: two `u32` working tables and the narrowed
/// table taken from the larger stage, plus the field itself. The engine's
/// constant is internal, so the arithmetic is restated here and the refusal
/// below proves the engine agrees with it.
fn gf16_construction_bytes() -> usize {
    const ORDER: usize = 1 << 16;
    let log_words = ORDER * size_of::<u32>();
    let exp_words = 2 * (ORDER - 1) * size_of::<u32>();
    let log_symbols = ORDER * 2;
    let exp_symbols = 2 * (ORDER - 1) * 2;
    (log_words + exp_words + log_symbols).max(exp_words + log_symbols + exp_symbols)
        + size_of::<par3_rs::Gf16>()
}

/// Encode a 300-block GF(2^16) Cauchy set under `budget`, returning what
/// creation did with it. Three hundred blocks put the set past the 256-column
/// GF(2^8) boundary, so the two-byte field is the one that gets built.
fn create_gf16_under(budget: usize) -> Result<(), EngineError> {
    let body: Arc<[u8]> = (0..300u64 * 64)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>()
        .into();
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, body);
    let mut options = CreationOptions {
        block_size: 64,
        recovery_count: 4,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.memory = MemoryBudget::new(budget);
    options.execution.retained_bytes = budget;
    let sources = [CreationSource {
        name: "a.bin".into(),
        source: SourceId(1),
    }];
    let plan = CreationPlan::build(Arc::new(access), &sources, options)?;
    assert_eq!(plan.requirements().field.size, 2, "not the two-byte field");
    let carriers = common::TempTree::new("field-budget");
    plan.execute(&carriers.path().join("set"), carriers.path())?;
    Ok(())
}

#[test]
fn creation_reserves_what_building_the_field_really_costs() {
    let construction = gf16_construction_bytes();
    assert!(
        construction > (512 << 10),
        "the round number this replaced was an under-statement of {construction}"
    );

    // One byte short of the field is a refusal, by name, before construction.
    match create_gf16_under(construction - 1) {
        Err(EngineError::ResourceLimit(limit)) => {
            assert_eq!(limit.what, "codec tables", "{limit}");
            assert_eq!(limit.need, construction, "{limit}");
            assert_eq!(limit.cause(), LimitCause::ExceedsLimit, "{limit}");
        }
        other => panic!("a budget below the field's construction cost must refuse: {other:?}"),
    }

    // And the old constant is genuinely admitted by the old arithmetic and
    // refused by the new: a budget above 512 KiB but below the real cost.
    match create_gf16_under(768 << 10) {
        Err(EngineError::ResourceLimit(limit)) => {
            assert_eq!(limit.what, "codec tables", "{limit}");
            assert_eq!(limit.need, construction, "{limit}");
        }
        other => panic!("768 KiB does not hold a {construction} byte field: {other:?}"),
    }

    // With room for the field and the rest of the encode, it succeeds.
    create_gf16_under(construction + (1 << 20)).expect("a roomy budget builds the set");
}

/// A single-file carrier whose External Data packet describes 20 000 blocks,
/// so one metadata packet is most of the carrier and its parsed body is the
/// same order of size as the wire bytes it is read from.
fn wide_external_data_carrier() -> Vec<u8> {
    let body: Arc<[u8]> = (0..20_000u64 * 64)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>()
        .into();
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, body);
    let mut options = CreationOptions {
        block_size: 64,
        recovery_count: 1,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.memory = MemoryBudget::new(1 << 30);
    options.execution.retained_bytes = 1 << 30;
    let sources = [CreationSource {
        name: "wide.bin".into(),
        source: SourceId(1),
    }];
    let plan = CreationPlan::build(Arc::new(access), &sources, options).unwrap();
    let carriers = common::TempTree::new("wide-external-data");
    let paths = plan
        .execute(&carriers.path().join("set"), carriers.path())
        .unwrap();
    std::fs::read(&paths[0]).unwrap()
}

/// Scan every packet of `bytes` under `budget`, returning the widest packet
/// seen or the refusal that stopped the scan.
fn scan_under(bytes: Vec<u8>, budget: usize) -> Result<u64, EngineError> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(9), 1, bytes.into());
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.memory = MemoryBudget::new(budget);
    options.retained_bytes = budget;
    let mut scanner = PacketScanner::new(
        Arc::new(access),
        SourceId(9),
        options,
        ScanLimits::default(),
    )?;
    let mut widest = 0;
    while let ScanEvent::Packet(packet) = scanner.poll()? {
        widest = widest.max(packet.origin().length);
    }
    Ok(widest)
}

/// PR #73 finding 6. `Packet::parse` builds the parsed body's owned containers
/// while the wire copy it reads from is still held, so both are live at once.
/// The charge for the pair has to be taken before parsing: taking it afterwards
/// means the allocation has already happened by the time the budget is asked,
/// and a budget with room for one copy quietly holds two.
#[test]
fn a_metadata_packet_is_admitted_for_its_wire_bytes_and_its_parsed_body_together() {
    let carrier = wide_external_data_carrier();
    let wire = scan_under(carrier.clone(), 256 << 20).expect("a roomy budget scans it") as usize;
    assert!(
        wire > 400_000,
        "the External Data packet should dominate this carrier: {wire}"
    );

    // Room for the wire copy and the scan buffer, but not for the parsed body
    // beside them. The refusal must come from the second charge, not the first.
    match scan_under(carrier.clone(), 2 * wire) {
        Err(EngineError::ResourceLimit(limit)) => {
            assert!(
                limit.to_string().contains("carrier and packet storage"),
                "{limit}"
            );
            let held = limit.limit - limit.available;
            assert!(
                held >= limit.need,
                "the budget was refused while holding only {held} bytes, so this is the \
                 first charge for the packet and not the parse overlap: {limit}"
            );
        }
        other => panic!("a budget of {} must refuse the pair: {other:?}", 2 * wire),
    }

    // With room for both, the same carrier scans through.
    assert_eq!(
        scan_under(carrier, 4 * wire).expect("both copies fit"),
        wire as u64
    );
}
