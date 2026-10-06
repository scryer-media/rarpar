//! Measured work and cancellation are observable without source rereads.
mod common;
use par3_rs::runtime::{EngineError, ExecutionOptions, ProgressCallback, ProgressPhase, Stage};
use par3_rs::source::{MemorySourceAccess, SourceId};
use std::sync::{Arc, Mutex};

#[test]
fn verification_measures_real_reads_and_balances_stage_events() {
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 127;
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    options.progress = Some(ProgressCallback::new(move |event| {
        observed.lock().unwrap().push(event)
    }));
    let layout = Arc::new(par3_rs::layout::BlockLayout::new(&common::gf8_set(), &options).unwrap());
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, common::a_bin().into());
    let proof = par3_rs::evidence::verify_source(layout.clone(), 0, &source, SourceId(1), &options)
        .unwrap();
    assert!(proof.protected_complete());
    let io = options.diagnostics.source_io();
    assert_eq!(io.read_bytes, 5000);
    assert_eq!(io.read_requested, 5000);
    assert_eq!(io.read_calls, 5000u64.div_ceil(127));
    assert_eq!(options.diagnostics.file_io().read_bytes, 0);
    assert_eq!(options.diagnostics.stage(Stage::Verify).completed, 5000);
    let replay = par3_rs::evidence::verify_arrivals(layout, &proof, &source, &options).unwrap();
    assert!(replay.protected_complete());
    assert_eq!(options.diagnostics.source_io(), io);
    let events = events.lock().unwrap();
    let begins: Vec<_> = events
        .iter()
        .filter(|e| e.phase == ProgressPhase::Begin)
        .map(|e| e.operation)
        .collect();
    let ends: Vec<_> = events
        .iter()
        .filter(|e| e.phase == ProgressPhase::End)
        .map(|e| e.operation)
        .collect();
    assert_eq!(begins, ends);
    assert!(!begins.is_empty());
}

#[test]
fn creation_reports_only_outputs_installed_before_cancellation() {
    use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource};
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let cancel = options.cancel.clone();
    options.progress = Some(ProgressCallback::new(move |event| {
        if event.stage == Stage::Create && event.phase == ProgressPhase::Advance {
            cancel.cancel();
        }
    }));
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, common::a_bin().into());
    let plan = CreationPlan::build(
        Arc::new(source),
        &[CreationSource {
            source: SourceId(1),
            name: "a.bin".into(),
        }],
        CreationOptions {
            block_size: 1024,
            recovery_count: 2,
            execution: options.clone(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let tree = common::TempTree::new("partial-creation");
    match plan
        .execute(&tree.path().join("set"), tree.path())
        .unwrap_err()
    {
        EngineError::OutputInterrupted { installed, cause } => {
            assert_eq!(installed, vec![tree.path().join("set.par3")]);
            assert!(matches!(*cause, EngineError::Cancelled));
            let bytes = std::fs::read(&installed[0]).unwrap();
            assert!(!common::packets_of(&bytes).is_empty());
        }
        error => panic!("partial installation was lost: {error}"),
    }
    assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 1);
    assert_eq!(options.handles.used(), 0);
}

#[test]
fn cancelling_encoding_from_progress_cleans_spool_and_staging_for_both_codecs() {
    use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
    // The default budget holds the two rows resident, so nothing reaches disk
    // before the cancellation; 64 KiB has no room for them beside the carrier
    // stage, so the rows go to a spool file that has to be cleaned up.
    for (codec, memory) in [
        (CreationCodec::Cauchy, None),
        (CreationCodec::Cauchy, Some(64 << 10)),
        (
            CreationCodec::Fft {
                capacity_log2: 3,
                interleave: 0,
            },
            None,
        ),
        (
            CreationCodec::Fft {
                capacity_log2: 3,
                interleave: 0,
            },
            Some(64 << 10),
        ),
    ] {
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = 128;
        if let Some(memory) = memory {
            options.memory = par3_rs::runtime::MemoryBudget::new(memory);
        }
        let cancel = options.cancel.clone();
        options.progress = Some(ProgressCallback::new(move |event| {
            if event.stage == Stage::Encode && event.phase == ProgressPhase::Advance {
                cancel.cancel();
            }
        }));
        let mut source = MemorySourceAccess::default();
        source.insert(SourceId(1), 1, common::a_bin().into());
        let plan = CreationPlan::build(
            Arc::new(source),
            &[CreationSource {
                source: SourceId(1),
                name: "a.bin".into(),
            }],
            CreationOptions {
                codec,
                block_size: 1024,
                recovery_count: 2,
                execution: options.clone(),
                ..CreationOptions::default()
            },
        )
        .unwrap();
        let retained = options.memory.used();
        let tree = common::TempTree::new("cancel-progress");
        let error = plan
            .execute(&tree.path().join("set"), tree.path())
            .unwrap_err();
        assert!(matches!(error, EngineError::Cancelled), "{error}");
        assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 0);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.memory.used(), retained);
        assert_eq!(
            options.diagnostics.file_io().write_bytes > 0,
            memory.is_some(),
            "{codec:?} {memory:?}: only the spooled rows reach disk"
        );
        assert!(options.diagnostics.stage(Stage::Encode).completed > 0);
        assert_eq!(options.diagnostics.stage(Stage::Encode).calls, 1);
        drop(plan);
        assert_eq!(options.memory.used(), 0);
    }
}

// --- Admission, amplification and output tiling (work package M1) -----------

use par3_rs::runtime::{LimitCause, MemoryBudget, MemoryCategory};
use par3_rs::session::{Par3RepairSession, RepairStatus};

/// [`repair_cauchy`] that reports a refusal instead of unwrapping it.
#[allow(clippy::too_many_arguments)]
fn try_repair_cauchy(
    blocks: usize,
    block_size: u64,
    recovery: u64,
    damage: &[usize],
    workers: usize,
    stripe_bytes: usize,
    budget: usize,
    seed: &[u8],
) -> Result<ExecutionOptions, par3_rs::runtime::EngineError> {
    let tree = common::TempTree::new("serial-retry-cauchy");
    let set = common::cauchy_block_set(blocks, block_size, recovery, seed, &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for block in damage {
        damaged[block * block_size as usize + 11] ^= 0x80;
    }
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 2, damaged.into());

    let mut options = ExecutionOptions::default();
    options.workers = workers;
    options.stripe_bytes = stripe_bytes;
    options.memory = MemoryBudget::new(budget);
    options.retained_bytes = budget / 2;

    let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone())?;
    session.bind_file(&name, SourceId(1))?;
    for path in &set.paths {
        for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
            session.merge(packet)?;
        }
    }
    assert_eq!(session.assess()?.status, RepairStatus::Ready);
    let output = common::TempTree::new("serial-retry-cauchy-out");
    let report = session.repair(output.path(), false)?;
    assert_eq!(report.reconstructed_blocks, damage.len() as u64);
    assert_eq!(
        std::fs::read(output.path().join(&name)).unwrap(),
        bytes,
        "the repair did not reproduce the input"
    );
    drop(session);
    assert_eq!(options.memory.used(), 0, "the session leaked");
    Ok(options)
}

/// Repair one Cauchy set at a chosen worker count and budget, returning the
/// repaired bytes and the options the run used, so a caller can read both the
/// output and every counter the run produced.
#[allow(clippy::too_many_arguments)]
fn repair_cauchy(
    blocks: usize,
    block_size: u64,
    recovery: u64,
    damage: &[usize],
    workers: usize,
    stripe_bytes: usize,
    budget: usize,
    seed: &[u8],
) -> (Vec<u8>, ExecutionOptions) {
    let tree = common::TempTree::new("tiled-cauchy");
    let set = common::cauchy_block_set(blocks, block_size, recovery, seed, &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for block in damage {
        damaged[block * block_size as usize + 11] ^= 0x80;
    }
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 2, damaged.into());

    let mut options = ExecutionOptions::default();
    options.workers = workers;
    options.stripe_bytes = stripe_bytes;
    options.memory = MemoryBudget::new(budget);
    options.retained_bytes = budget / 2;

    let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
    session.bind_file(&name, SourceId(1)).unwrap();
    for path in &set.paths {
        for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
            session.merge(packet).unwrap();
        }
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let output = common::TempTree::new("tiled-cauchy-out");
    let repaired = session.repair(output.path(), false).unwrap();
    assert_eq!(repaired.reconstructed_blocks, damage.len() as u64);
    let rebuilt = std::fs::read(output.path().join(&name)).unwrap();
    assert_eq!(rebuilt, bytes, "the repair did not reproduce the input");
    drop(session);
    assert_eq!(options.memory.used(), 0, "the session leaked");
    (rebuilt, options)
}

/// Deliverable 6. The Cauchy row bank no longer materialises every recovered
/// row before scattering any of them: it produces `t` rows at a time, where `t`
/// comes from the admitted worker capacity. The output must not care.
///
/// Both runs are hashed and compared, and so are the write calls: tiling
/// preserves column order and still issues one scatter per column, so it buys
/// its smaller bank without extra seeks.
#[test]
fn output_tiling_changes_the_row_bank_and_nothing_else() {
    let damage = [1usize, 3, 5, 7, 9, 11, 13, 15];
    let seed = b"PAR3 cauchy output tiling";
    let (serial, serial_options) = repair_cauchy(512, 64, 16, &damage, 1, 4096, 32 << 20, seed);
    let (tiled, tiled_options) = repair_cauchy(512, 64, 16, &damage, 8, 4096, 32 << 20, seed);

    let digest = |bytes: &[u8]| {
        let mut hash = blake3::Hasher::new();
        hash.update(bytes);
        hash.finalize().to_hex().to_string()
    };
    assert_eq!(
        digest(&serial),
        digest(&tiled),
        "tiling changed the repaired bytes"
    );

    let narrow = serial_options.diagnostics.admission();
    let wide = tiled_options.diagnostics.admission();
    println!(
        "tile {} -> {} ({} rows lost), stripe {} -> {}",
        narrow.output_tile,
        wide.output_tile,
        damage.len(),
        narrow.stripe_bytes,
        wide.stripe_bytes
    );
    assert_eq!(
        narrow.output_tile, 1,
        "one worker must tile one row at a time"
    );
    assert!(
        wide.output_tile > narrow.output_tile,
        "more workers did not widen the tile"
    );
    assert!(
        wide.output_tile <= damage.len() as u64,
        "the tile exceeded the rows there are to recover"
    );

    // Extra seeks: the measurement the brief asks for. Scattering is per
    // column, so a narrower tile costs no additional writes.
    let narrow_io = serial_options.diagnostics.file_io();
    let wide_io = tiled_options.diagnostics.file_io();
    println!(
        "write calls {} -> {}, write bytes {} -> {}",
        narrow_io.write_calls, wide_io.write_calls, narrow_io.write_bytes, wide_io.write_bytes
    );
    assert_eq!(
        narrow_io.write_calls, wide_io.write_calls,
        "tiling changed the number of writes"
    );
    assert_eq!(narrow_io.write_bytes, wide_io.write_bytes);
}

/// Deliverable 5. Every counter the brief names is readable after a repair, the
/// ledger is reachable through the diagnostics without a second copy, and the
/// amplification counters actually moved.
#[test]
fn a_repair_reports_its_widths_its_caches_and_what_it_moved_onto_io() {
    let (_, options) = repair_cauchy(
        512,
        64,
        8,
        &[1usize, 3, 5, 7],
        2,
        4096,
        32 << 20,
        b"PAR3 admission diagnostics",
    );
    let diagnostics = &options.diagnostics;

    // The ledger is delegated, not duplicated.
    let ledger = diagnostics
        .memory()
        .expect("a stage ran against the budget");
    assert_eq!(
        ledger.category(MemoryCategory::Assessment).peak,
        options
            .memory
            .ledger()
            .category(MemoryCategory::Assessment)
            .peak
    );
    assert!(
        ledger.category(MemoryCategory::CodecScratch).peak > 0,
        "the codec ran but charged no scratch"
    );
    for (category, entry) in ledger.iter() {
        assert_eq!(entry.current, 0, "{} is still held", category.name());
    }

    let admission = diagnostics.admission();
    assert!(admission.stripe_bytes > 0, "no stripe was recorded");
    assert!(admission.stripe_buffers > 0);
    assert!(admission.output_tile > 0);
    assert!(admission.workers > 0);
    assert!(admission.verify_batch > 0, "no verification batch recorded");

    let amplification = diagnostics.amplification();
    println!(
        "reread {} bytes, reconstructed {} bytes",
        amplification.reread_bytes, amplification.reconstructed_bytes
    );
    assert!(
        amplification.reconstructed_bytes > 0,
        "four blocks were rebuilt but nothing was counted"
    );

    // A repair that fits needs no refusals and no narrowing.
    assert_eq!(diagnostics.refusals(), Default::default());
    println!(
        "waits {:?}, caches {:?}",
        diagnostics.waits(),
        diagnostics.caches()
    );
}

/// Deliverable 4. Under pressure the engine narrows rather than failing, and
/// when even the minimum will not fit it refuses once, with honest numbers, and
/// never spins.
#[test]
fn pressure_narrows_the_stripe_before_it_refuses_and_refuses_only_once() {
    // A budget that cannot hold the configured 1 MiB stripes but can hold a
    // narrow one. The repair must still complete, with the narrowing recorded.
    let (_, tight) = repair_cauchy(
        64,
        64 << 10,
        8,
        &[1usize, 3, 5, 7, 9, 11, 13, 15],
        1,
        1 << 20,
        512 << 10,
        b"PAR3 pressure narrowing",
    );
    let waits = tight.diagnostics.waits();
    let admission = tight.diagnostics.admission();
    println!(
        "narrowed to {} bytes, waits {waits:?}",
        admission.stripe_bytes
    );
    assert!(
        admission.stripe_bytes < (64 << 10),
        "the stripe was not narrowed below the block"
    );
    assert!(
        waits.stripe_narrowed > 0 || waits.workers_refused > 0,
        "narrowing happened but nothing recorded it"
    );

    // Under a budget below any useful working set the engine refuses instead of
    // looping. The carriers are scanned under a budget of their own so that the
    // refusal under test comes from the repair session.
    let tree = common::TempTree::new("pressure-refusal");
    let set = common::cauchy_block_set(64, 64 << 10, 8, b"PAR3 pressure refusal", &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for block in [1usize, 3, 5, 7] {
        damaged[block * (64 << 10) + 11] ^= 0x80;
    }
    let scanning = ExecutionOptions::default();
    let carriers: Vec<_> = set
        .paths
        .iter()
        .flat_map(|path| common::scanned_packets(std::fs::read(path).unwrap(), &scanning))
        .collect();

    let attempt = |budget: usize| -> (par3_rs::runtime::ResourceLimit, ExecutionOptions) {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 2, damaged.clone().into());
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.memory = MemoryBudget::new(budget);
        options.retained_bytes = budget;
        let refused = (|| -> Result<(), EngineError> {
            let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone())?;
            session.bind_file(&name, SourceId(1))?;
            for packet in carriers.clone() {
                session.merge(packet)?;
            }
            session.assess()?;
            let output = common::TempTree::new("pressure-refusal-out");
            session.repair(output.path(), false)?;
            Ok(())
        })();
        let EngineError::ResourceLimit(limit) =
            refused.expect_err("a starved budget admitted a repair")
        else {
            panic!("pressure produced something other than a resource limit");
        };
        assert_eq!(options.memory.used(), 0, "the refused attempt kept memory");
        (limit, options)
    };

    // Small enough that no arrangement of this session fits: terminal.
    let (terminal, terminal_options) = attempt(48 << 10);
    println!(
        "terminal: what={} need={} limit={} available={} cause={:?}",
        terminal.what,
        terminal.need,
        terminal.limit,
        terminal.available,
        terminal.cause()
    );
    assert_eq!(
        terminal.cause(),
        LimitCause::ExceedsLimit,
        "a request that cannot fit at all was offered as retryable"
    );
    assert!(
        terminal.need > terminal.limit,
        "a terminal refusal that fits"
    );
    // Counted exactly once, at the boundary the host sees, and by cause.
    assert_eq!(
        terminal_options.diagnostics.refusals(),
        par3_rs::runtime::RefusalSnapshot {
            exceeds_limit: 1,
            peer_contention: 0,
            unmeasured: 0,
        }
    );

    // Large enough that the request would fit on an empty budget, but this
    // session's own earlier reservations are still holding it. M0's semantics
    // call that `PeerContention`: the holder may be a peer or this session, and
    // the host decides which from its own in-flight knowledge.
    let (contended, options) = attempt(160 << 10);
    println!(
        "contended: what={} need={} limit={} available={} cause={:?}",
        contended.what,
        contended.need,
        contended.limit,
        contended.available,
        contended.cause()
    );
    assert_eq!(contended.cause(), LimitCause::PeerContention);
    assert!(
        contended.need <= contended.limit,
        "a retryable refusal that cannot fit"
    );
    assert!(
        contended.available <= contended.limit,
        "more was available than the ceiling allows"
    );
    assert!(
        contended.limit <= options.memory.limit(),
        "the refusal measured against more than the budget"
    );
    // Nothing was refused without being measured, and no admission site spun.
    let refusals = options.diagnostics.refusals();
    println!("refusals {refusals:?}");
    assert_eq!(
        refusals,
        par3_rs::runtime::RefusalSnapshot {
            exceeds_limit: 0,
            peer_contention: 1,
            unmeasured: 0,
        },
        "an admission site retried instead of refusing once"
    );
}

/// PR #73 finding 4. The Cauchy output tile is the width the repair actually
/// runs at, so it must come from the pool that was admitted, not the worker
/// count that was configured. Under a budget too small for two worker stacks
/// the pool is serial whatever `workers` says, and a tile taken from `workers`
/// would size the row bank for parallelism that does not exist.
#[test]
fn a_repair_squeezed_onto_one_thread_banks_one_output_row() {
    let damage = [1usize, 3, 5, 7];
    let seed = b"PAR3 serial tile";
    // Enough for the layout, the evidence and the stripe bank; not enough for
    // the 320 KiB stacks two workers would need beside them.
    let (_, squeezed) = repair_cauchy(64, 1024, 8, &damage, 8, 4096, 512 << 10, seed);
    let narrow = squeezed.diagnostics.admission();
    assert_eq!(narrow.workers, 1, "this budget was meant to be serial");
    assert_eq!(
        narrow.output_tile, 1,
        "a serial pool tiled {} rows at a time",
        narrow.output_tile
    );
    assert_eq!(
        narrow.stripe_buffers,
        damage.len() as u64 + 1 + 3,
        "the row bank was sized for workers that were never admitted"
    );

    // The same repair with room for its workers banks a wider tile, so the
    // narrow figures above are the budget's doing and not the geometry's.
    let (_, roomy) = repair_cauchy(64, 1024, 8, &damage, 8, 4096, 32 << 20, seed);
    let wide = roomy.diagnostics.admission();
    assert!(wide.workers > 1 && wide.output_tile > 1, "{wide:?}");
    assert_eq!(
        wide.stripe_buffers,
        damage.len() as u64 + wide.output_tile + 3
    );
}

/// PR #73 round 3, finding 3. The worker pool was admitted against a headroom
/// that counted the serial bank's stripes but not its row headers, so there was
/// a band of budgets in which the pool took the bytes the headers needed and the
/// stripe admission then refused a repair that would have run serially. More
/// memory refusing what less memory accepted is never acceptable.
///
/// The band is only a few hundred bytes wide — the headers are `(n + tile)`
/// pointers — so this sweeps the budgets around the point where the pool starts
/// being admitted and asserts the outcome is monotone. The two liveness
/// assertions at the end keep it honest: the window has to straddle the
/// admission threshold, or it proves nothing.
///
/// The window reaches past the point where the pool's narrowed stripe first
/// fits, up to where its bank also leaves the staged proof its frontiers:
/// below that the pool gives way to the serial bank.
#[test]
fn a_larger_budget_never_refuses_a_repair_a_smaller_one_completed() {
    if std::thread::available_parallelism().is_ok_and(|threads| threads.get() < 2) {
        eprintln!("a single-core host never admits a pool here, skipping");
        return;
    }
    let damage = [1usize, 3, 5, 7];
    let seed = b"PAR3 serial retry";
    let mut first_ok = None;
    let mut widths = Vec::new();
    for budget in ((732 << 10)..=(752 << 10)).step_by(128) {
        match try_repair_cauchy(64, 1024, 8, &damage, 8, 4096, budget, seed) {
            Ok(options) => {
                let admission = options.diagnostics.admission();
                widths.push(admission.workers);
                if first_ok.is_none() {
                    first_ok = Some(budget);
                }
            }
            Err(error) => {
                panic!("a repair that fits at {first_ok:?} bytes was refused at {budget}: {error}")
            }
        }
    }
    assert!(
        widths.contains(&1),
        "no budget in the window ran serially, so it does not straddle the pool threshold"
    );
    assert!(
        widths.iter().any(|workers| *workers > 1),
        "no budget in the window admitted a pool, so it does not straddle the threshold"
    );
}

/// Surviving stripes are folded into the syndromes a group at a time, the
/// group sized from what the stripe bank leaves. At the smallest budget that
/// still admits the full stripe there is no room for a second stripe, so the
/// fold is one stripe at a time; with room, it is sixteen. The repaired bytes
/// must not care, and neither may the reads, the writes or the stripe.
#[test]
fn the_syndrome_group_changes_scratch_and_nothing_else() {
    // Every recovery row is spent, on stripes as wide as a block, so the stripe
    // bank is the widest thing the repair holds and its minimum is the budget's.
    let (blocks, block_size, recovery) = (48usize, 64u64 << 10, 16u64);
    let stripe = block_size as usize;
    let damage: Vec<usize> = (0..recovery as usize).map(|lost| lost * 3 + 1).collect();
    let tree = common::TempTree::new("syndrome-groups");
    let set =
        common::cauchy_block_set(blocks, block_size, recovery, b"PAR3 syndrome groups", &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for block in &damage {
        damaged[block * stripe + 11] ^= 0x80;
    }
    let scanning = ExecutionOptions::default();
    let carriers: Vec<_> = set
        .paths
        .iter()
        .flat_map(|path| common::scanned_packets(std::fs::read(path).unwrap(), &scanning))
        .collect();
    let full = |budget: usize, workers: usize| -> Option<ExecutionOptions> {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 2, damaged.clone().into());
        let mut options = ExecutionOptions::default();
        options.workers = workers;
        options.stripe_bytes = stripe;
        options.memory = MemoryBudget::new(budget);
        let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).ok()?;
        session.bind_file(&name, SourceId(1)).ok()?;
        for packet in &carriers {
            session.merge(packet.clone()).ok()?;
        }
        if session.assess().ok()?.status != RepairStatus::Ready {
            return None;
        }
        let output = common::TempTree::new("syndrome-groups-out");
        let report = session.repair(output.path(), false).ok()?;
        assert_eq!(report.reconstructed_blocks, recovery);
        assert!(
            std::fs::read(output.path().join(&name)).unwrap() == bytes,
            "{workers} workers at {budget}: the repair did not reproduce the input"
        );
        drop(session);
        assert_eq!(options.memory.used(), 0, "the session leaked");
        Some(options)
            .filter(|options| options.diagnostics.admission().stripe_bytes == stripe as u64)
    };
    let scratch = |options: &ExecutionOptions| {
        options
            .diagnostics
            .memory()
            .unwrap()
            .category(MemoryCategory::CodecScratch)
            .peak
    };
    let roomy = 32 << 20;
    for workers in [1, 4] {
        let wide = full(roomy, workers).expect("the roomy repair");
        let (mut low, mut high) = (0usize, roomy);
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if full(middle, workers).is_some() {
                high = middle;
            } else {
                low = middle;
            }
        }
        // Scratch paths are charged too and their names grow with a counter,
        // so stand a little above the edge: far less than the slack and the
        // stripe a second source would need.
        let narrow = full(high + 4096, workers).unwrap();
        let (narrow_admission, wide_admission) =
            (narrow.diagnostics.admission(), wide.diagnostics.admission());
        // Both outputs were already compared with the input. With workers the
        // roomy repair also holds a second set of sixteen to read ahead into;
        // a serial one never does.
        if narrow_admission.output_tile == wide_admission.output_tile {
            let read_ahead = if workers > 1 { 16 } else { 0 };
            assert_eq!(
                scratch(&wide) - scratch(&narrow),
                (15 + read_ahead) * stripe as u64,
                "{workers} workers: the roomy fold was not sixteen stripes wide"
            );
        }
        assert_eq!(
            narrow.diagnostics.source_io(),
            wide.diagnostics.source_io(),
            "{workers} workers: the group changed the reads"
        );
        let (narrow_io, wide_io) = (narrow.diagnostics.file_io(), wide.diagnostics.file_io());
        assert_eq!(narrow_io.write_calls, wide_io.write_calls, "{workers}");
        assert_eq!(narrow_io.write_bytes, wide_io.write_bytes, "{workers}");
    }
}

/// With a pool, the calling thread reads the next group of surviving stripes
/// into a second set while the workers fold the last one. That set is taken
/// only from budget left after the first and the slack, so a budget exactly as
/// large as the roomy repair's peak keeps the sixteen-stripe group and drops
/// the second set. Reading ahead or not, the repaired bytes, the reads, their
/// order-sensitive checks and the writes must be the same.
#[test]
fn reading_ahead_changes_scratch_and_nothing_else() {
    let (blocks, block_size, recovery) = (48usize, 64u64 << 10, 16u64);
    let stripe = block_size as usize;
    let tree = common::TempTree::new("read-ahead");
    let set = common::cauchy_block_set(blocks, block_size, recovery, b"PAR3 read ahead", &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for lost in 0..recovery as usize {
        damaged[(lost * 3 + 1) * stripe + 11] ^= 0x80;
    }
    let scanning = ExecutionOptions::default();
    let carriers: Vec<_> = set
        .paths
        .iter()
        .flat_map(|path| common::scanned_packets(std::fs::read(path).unwrap(), &scanning))
        .collect();
    let repair = |budget: usize| -> ExecutionOptions {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 2, damaged.clone().into());
        let mut options = ExecutionOptions::default();
        options.workers = 4;
        options.stripe_bytes = stripe;
        options.memory = MemoryBudget::new(budget);
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file(&name, SourceId(1)).unwrap();
        for packet in &carriers {
            session.merge(packet.clone()).unwrap();
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let output = common::TempTree::new("read-ahead-out");
        let report = session.repair(output.path(), false).unwrap();
        assert_eq!(report.reconstructed_blocks, recovery);
        assert!(
            std::fs::read(output.path().join(&name)).unwrap() == bytes,
            "{budget}: the repair did not reproduce the input"
        );
        drop(session);
        assert_eq!(options.memory.used(), 0, "the session leaked");
        options
    };
    let scratch = |options: &ExecutionOptions| {
        options
            .diagnostics
            .memory()
            .unwrap()
            .category(MemoryCategory::CodecScratch)
            .peak
    };
    let ahead = repair(32 << 20);
    let alternating = repair(ahead.memory.peak());
    let (ahead_admission, alternating_admission) = (
        ahead.diagnostics.admission(),
        alternating.diagnostics.admission(),
    );
    assert_eq!(ahead_admission.stripe_bytes, stripe as u64);
    assert_eq!(ahead_admission, alternating_admission);
    assert!(ahead_admission.workers > 1, "the roomy repair had no pool");
    assert_eq!(
        scratch(&ahead) - scratch(&alternating),
        16 * stripe as u64,
        "the tighter repair should keep its group and drop only the second set"
    );
    assert_eq!(
        ahead.diagnostics.source_io(),
        alternating.diagnostics.source_io(),
        "reading ahead changed the reads"
    );
    assert_eq!(
        ahead.diagnostics.file_io(),
        alternating.diagnostics.file_io(),
        "reading ahead changed the staged file I/O"
    );
}

/// Wave-2 review, finding F1. The syndrome group and the read-ahead set take
/// what the stripe bank leaves, down to the slack. With stripes narrower than
/// a block, the staged proof holds a hash frontier open for every extent
/// written in pieces; when those grabs took the bytes the frontiers needed,
/// the proof gave up and the staged output was read back, at budgets where a
/// smaller one read nothing back. Read-back must never grow with the budget,
/// and with the frontiers reserved ahead of the bank's narrowing and of both
/// grabs, no budget the repair completes in reads back at all.
#[test]
fn w2review_read_ahead_starves_proof_frontiers_into_read_back() {
    let (blocks, block_size, recovery) = (24usize, 64u64 << 10, 8u64);
    let block = block_size as usize;
    let stripe = 16usize << 10;
    let tree = common::TempTree::new("proof-frontiers");
    let set = common::cauchy_block_set(
        blocks,
        block_size,
        recovery,
        b"PAR3 w2review frontier",
        &tree,
    );
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for lost in 0..recovery as usize {
        damaged[(lost * 3 + 1) * block + 11] ^= 0x80;
    }
    let scanning = ExecutionOptions::default();
    let carriers: Vec<_> = set
        .paths
        .iter()
        .flat_map(|path| common::scanned_packets(std::fs::read(path).unwrap(), &scanning))
        .collect();
    let repair = |budget: usize| -> Option<ExecutionOptions> {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 2, damaged.clone().into());
        let mut options = ExecutionOptions::default();
        options.workers = 4;
        options.stripe_bytes = stripe;
        options.memory = MemoryBudget::new(budget);
        let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).ok()?;
        session.bind_file(&name, SourceId(1)).ok()?;
        for packet in &carriers {
            session.merge(packet.clone()).ok()?;
        }
        if session.assess().ok()?.status != RepairStatus::Ready {
            return None;
        }
        let output = common::TempTree::new("proof-frontiers-out");
        let report = session.repair(output.path(), false).ok()?;
        assert_eq!(report.reconstructed_blocks, recovery);
        assert!(
            std::fs::read(output.path().join(&name)).unwrap() == bytes,
            "{budget}: the repair did not reproduce the input"
        );
        drop(session);
        assert_eq!(options.memory.used(), 0, "the session leaked");
        Some(options)
    };
    let scratch = |options: &ExecutionOptions| {
        options
            .diagnostics
            .memory()
            .unwrap()
            .category(MemoryCategory::CodecScratch)
            .peak
    };
    let roomy = repair(64 << 20).expect("the roomy repair");
    assert_eq!(
        roomy.diagnostics.file_io().read_bytes,
        0,
        "the roomy repair read back"
    );
    let peak = roomy.memory.peak();
    let mut rows = Vec::new();
    let mut budget = peak.saturating_sub(1900 << 10);
    while budget <= peak + (64 << 10) {
        if let Some(run) = repair(budget) {
            rows.push((
                budget,
                run.diagnostics.file_io().read_bytes,
                scratch(&run),
                run.diagnostics.admission().stripe_bytes,
            ));
        }
        budget += 8 << 10;
    }
    // The sweep must straddle both grabs: from budgets that leave no room for
    // a second stripe to budgets with the whole read-ahead set.
    // It must also reach budgets whose bank narrows the stripe.
    let widest = scratch(&roomy);
    let narrowest = rows
        .iter()
        .filter(|row| row.3 == stripe as u64)
        .map(|row| row.2)
        .min()
        .unwrap_or(widest);
    assert!(
        widest - narrowest >= 16 * stripe as u64,
        "the sweep did not straddle the group and the read-ahead: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.3 < stripe as u64),
        "the sweep never narrowed the stripe: {rows:?}"
    );
    for pair in rows.windows(2) {
        assert!(
            pair[1].1 <= pair[0].1,
            "budget {} read back {} bytes, budget {} read back {}: {rows:?}",
            pair[0].0,
            pair[0].1,
            pair[1].0,
            pair[1].1
        );
    }
    assert!(
        rows.iter().all(|row| row.1 == 0),
        "a completed repair read back: {rows:?}"
    );
}

/// PR #73 finding 10. Successive stripe passes walk disjoint slices of every
/// block, so a repair that cannot hold a whole block reads each source byte
/// exactly once. `reread_bytes` is what a host uses to see I/O amplification,
/// and reporting the whole source as reread made it useless. The cost of the
/// extra walks is real and is reported as passes instead.
#[test]
fn stripe_passes_over_a_block_are_passes_and_not_rereads() {
    let damage = [2usize, 9];
    // A 64 KiB block walked in 4 KiB stripes: sixteen passes, no byte twice.
    let (_, options) = repair_cauchy(
        32,
        64 << 10,
        4,
        &damage,
        1,
        4096,
        32 << 20,
        b"PAR3 stripe passes",
    );
    let amplification = options.diagnostics.amplification();
    let admission = options.diagnostics.admission();
    println!(
        "stripe {} over a 65536 byte block: {} passes, {} bytes reread, {} reconstructed",
        admission.stripe_bytes,
        amplification.stripe_passes,
        amplification.reread_bytes,
        amplification.reconstructed_bytes
    );
    assert!(
        admission.stripe_bytes < 64 << 10,
        "the stripe was not narrower than the block"
    );
    assert!(
        amplification.stripe_passes > 0,
        "a narrow stripe made no extra passes"
    );
    assert_eq!(
        amplification.reread_bytes, 0,
        "disjoint stripe passes were counted as rereads"
    );
    assert!(amplification.reconstructed_bytes > 0);

    // PR #73 round 5, finding D. A pass is one extra walk over the source, so
    // the count follows the block and the stripe and nothing else. It used to
    // be taken inside the loop over surviving blocks, which multiplied every
    // pass by however many blocks the set happened to have and made the number
    // unreadable — here, 31 times too large.
    let expected = (64u64 << 10).div_ceil(admission.stripe_bytes) - 1;
    assert_eq!(
        amplification.stripe_passes, expected,
        "a {} byte stripe over a 65536 byte block is {expected} extra passes, whatever the block count",
        admission.stripe_bytes
    );
}

/// PR #73 round 5, finding D again, at the second site. Round 5 fixed the pass
/// counter in the reconstruction loop and left the copy loop — the one a repair
/// with nothing lost takes, where every block is available from an alias — still
/// counting a pass per block per window. A set with four blocks reported four
/// times the passes a set with one block did, for the same walk.
///
/// The set here is two files with identical bytes under aligned deduplication,
/// so every block of each is named by the other. Damaging one file loses
/// nothing: the copy path stages it and fills it from its twin, in windows,
/// because the block is wider than the copy window.
#[test]
fn a_copy_that_walks_a_block_in_windows_counts_one_pass_per_window() {
    use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource, Deduplication};

    let blocks = 4u64;
    let block_size = 64u64 << 10;
    let stripe = 4096usize;
    let mut bytes = vec![0u8; (blocks * block_size) as usize];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 copy stripe passes");
    hash.finalize_xof().fill(&mut bytes);

    let mut creating = MemorySourceAccess::default();
    creating.insert(SourceId(1), 1, bytes.clone().into());
    creating.insert(SourceId(2), 1, bytes.clone().into());
    let mut creation = CreationOptions {
        block_size,
        recovery_count: 0,
        deduplication: Deduplication::Aligned,
        ..CreationOptions::default()
    };
    creation.execution.workers = 1;
    let tree = common::TempTree::new("copy-stripe-passes");
    let plan = CreationPlan::build(
        Arc::new(creating),
        &[
            CreationSource {
                name: "original.bin".into(),
                source: SourceId(1),
            },
            CreationSource {
                name: "twin.bin".into(),
                source: SourceId(2),
            },
        ],
        creation,
    )
    .unwrap();
    let id = plan.input_set_id();
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();

    // Only the twin is damaged, and every block it loses survives in the
    // original, so the repair copies rather than reconstructs.
    let mut damaged = bytes.clone();
    damaged[11] ^= 0x80;
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 2, bytes.clone().into());
    access.insert(SourceId(2), 2, damaged.into());

    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.stripe_bytes = stripe;
    options.memory = MemoryBudget::new(64 << 20);
    options.retained_bytes = 32 << 20;

    let mut session = Par3RepairSession::new(id, Arc::new(access), options.clone()).unwrap();
    session.bind_file("original.bin", SourceId(1)).unwrap();
    session.bind_file("twin.bin", SourceId(2)).unwrap();
    for path in &paths {
        for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
            session.merge(packet).unwrap();
        }
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.status, RepairStatus::Ready);
    assert!(
        assessment.lost_blocks.is_empty(),
        "the damaged blocks must survive in the twin, or this is not the copy path"
    );

    let output = common::TempTree::new("copy-stripe-passes-out");
    let report = session.repair(output.path(), false).unwrap();
    assert_eq!(report.reconstructed_blocks, 0, "nothing was reconstructed");
    assert_eq!(
        std::fs::read(output.path().join("twin.bin")).unwrap(),
        bytes,
        "the copy did not reproduce the input"
    );

    let amplification = options.diagnostics.amplification();
    let expected = block_size.div_ceil(stripe as u64) - 1;
    println!(
        "copying {blocks} blocks of {block_size} bytes in {stripe} byte windows: {} passes",
        amplification.stripe_passes
    );
    assert_eq!(
        amplification.stripe_passes,
        expected,
        "one walk over {blocks} blocks in {} windows is {expected} extra passes, not {} per block",
        block_size.div_ceil(stripe as u64),
        amplification.stripe_passes
    );
    // The twin's three intact blocks are each named by two intact extents, so
    // the copy reads each a second time and compares: the alias check, which
    // is the only genuine reread this engine makes.
    assert_eq!(
        amplification.reread_bytes,
        (blocks - 1) * block_size,
        "each intact aliased block is read once more for its check"
    );
    drop(session);
    assert_eq!(options.memory.used(), 0, "the session leaked");
}

/// A repair proves each staged output from the bytes it writes, whether a
/// stripe covers a whole block or a block is written over several passes, so
/// no staged byte is read back. Only `SyncFiles`, the default, synchronizes it.
#[test]
fn repair_proves_staged_outputs_and_syncs_only_when_asked() {
    use par3_rs::session_repair::RepairDurability;
    let tree = common::TempTree::new("staged-proof");
    let set = common::cauchy_block_set(64, 4096, 8, b"PAR3 staged proof", &tree);
    let (name, bytes) = set.contents[0].clone();
    let mut damaged = bytes.clone();
    for block in [2usize, 5, 9] {
        damaged[block * 4096 + 17] ^= 0x80;
    }
    for (stripe, durability, syncs) in [
        (4096, RepairDurability::SyncFiles, 1),
        (1024, RepairDurability::SyncFiles, 1),
        (4096, RepairDurability::Buffered, 0),
        (1024, RepairDurability::Buffered, 0),
    ] {
        let case = format!("{stripe}-byte stripes, {durability:?}");
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, damaged.clone().into());
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = stripe;
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file(&name, SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let output = common::TempTree::new("staged-proof-out");
        let report = session
            .repair_with_durability(output.path(), false, durability)
            .unwrap();
        assert_eq!(report.reconstructed_blocks, 3, "{case}");
        assert_eq!(
            std::fs::read(output.path().join(&name)).unwrap(),
            bytes,
            "{case}"
        );
        let io = options.diagnostics.file_io();
        assert_eq!(io.read_bytes, 0, "{case}: a staged output was read back");
        assert_eq!(io.write_bytes, bytes.len() as u64, "{case}");
        assert_eq!(options.diagnostics.file_sync().calls, syncs, "{case}");
        drop(session);
        assert_eq!(options.memory.used(), 0, "{case}: the session leaked");
    }
}

// --- Planning hash pool (W2.5) ------------------------------------------------

use par3_rs::source::{SourceAccess, SourceSnapshot};

/// A memory source whose forward reader returns at most 7000 bytes a call and
/// stops at half the file, so planning reads short and then positionally, and
/// optionally fails outright at one offset.
struct Trickle {
    inner: MemorySourceAccess,
    fail_at: Option<u64>,
}

struct TrickleReader {
    inner: Box<dyn std::io::Read + Send>,
    at: u64,
    stop: u64,
    fail_at: Option<u64>,
}

impl std::io::Read for TrickleReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self
            .fail_at
            .is_some_and(|fail| fail < self.at + out.len() as u64)
        {
            return Err(std::io::Error::other("injected source fault"));
        }
        let take = out.len().min(7000).min((self.stop - self.at) as usize);
        let read = self.inner.read(&mut out[..take])?;
        self.at += read as u64;
        Ok(read)
    }
}

impl SourceAccess for Trickle {
    fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
        self.inner.snapshot(source)
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
    fn open_sequential(
        &self,
        source: SourceId,
    ) -> std::io::Result<Option<Box<dyn std::io::Read + Send>>> {
        let stop = self
            .inner
            .snapshot(source)?
            .map_or(0, |snapshot| snapshot.len / 2);
        Ok(self.inner.open_sequential(source)?.map(|inner| {
            Box::new(TrickleReader {
                inner,
                at: 0,
                stop,
                fail_at: self.fail_at,
            }) as Box<dyn std::io::Read + Send>
        }))
    }
}

/// A large source plans its hashes on a pool that reads ahead of the walk:
/// the file hash and chunk hashes run on the workers while the next buffer is
/// read. The reads must be the serial walk's, call for call and byte for byte,
/// and the set must be the same set. Only the stacks and the two parallel-hash
/// buffers may differ. A small source beside it keeps the serial walk.
#[test]
fn a_planning_pool_changes_scratch_and_nothing_else() {
    use par3_rs::creation::{CreationDurability, CreationOptions, CreationPlan, CreationSource};
    // The smallest source that may start a planning pool.
    let large = 8usize << 20;
    let small: Vec<u8> = (0..70_000usize).map(|i| (i * 7 + i / 251) as u8).collect();
    // Blocks of a buffer, of a stripe, and of neither; tails that are inline,
    // just inline, just described, and described.
    for (block_size, tail) in [
        (1u64 << 20, 17usize),
        (64 << 10, 3000),
        (100_000, 39),
        (100_000, 40),
    ] {
        let bytes: Vec<u8> = (0..large + tail)
            .map(|i| (i * 131 + i / 977) as u8)
            .collect();
        let plan = |workers: usize, fail_at: Option<u64>| {
            let mut inner = MemorySourceAccess::default();
            inner.insert(SourceId(1), 1, bytes.clone().into());
            inner.insert(SourceId(2), 1, small.clone().into());
            let mut options = CreationOptions {
                block_size,
                recovery_count: 2,
                ..CreationOptions::default()
            };
            options.execution.workers = workers;
            let execution = options.execution.clone();
            let plan = CreationPlan::build(
                Arc::new(Trickle { inner, fail_at }),
                &[
                    CreationSource {
                        name: "large.bin".into(),
                        source: SourceId(1),
                    },
                    CreationSource {
                        name: "small.bin".into(),
                        source: SourceId(2),
                    },
                ],
                options,
            );
            (plan, execution)
        };
        let run = |workers: usize| {
            let (plan, execution) = plan(workers, None);
            let plan = plan.unwrap();
            let reads = execution.diagnostics.source_io();
            let verify = execution.diagnostics.stage(Stage::Verify);
            let ledger = execution.diagnostics.memory().unwrap();
            let stacks = ledger.category(MemoryCategory::WorkerStacks).peak;
            let scratch = ledger.category(MemoryCategory::SourceScratch).peak;
            let tree =
                common::TempTree::new(&format!("planning-pool-{block_size}-{tail}-{workers}"));
            let carriers: Vec<Vec<u8>> = plan
                .execute_with_durability(
                    &tree.path().join("set"),
                    tree.path(),
                    CreationDurability::Buffered,
                )
                .unwrap()
                .iter()
                .map(|path| std::fs::read(path).unwrap())
                .collect();
            (
                carriers,
                reads,
                (verify.calls, verify.completed),
                stacks,
                scratch,
            )
        };
        let case = format!("{block_size}-byte blocks, {tail}-byte tail");
        let (serial, serial_reads, serial_verify, serial_stacks, serial_scratch) = run(1);
        assert_eq!(serial_stacks, 0, "{case}");
        let (pooled, pooled_reads, pooled_verify, pooled_stacks, pooled_scratch) = run(4);
        assert!(pooled_stacks > 0, "{case}: planning started no pool");
        assert_eq!(
            pooled_scratch - serial_scratch,
            2 << 20,
            "{case}: not two parallel-hash buffers"
        );
        assert_eq!(
            pooled_reads, serial_reads,
            "{case}: the pool changed the reads"
        );
        assert_eq!(
            pooled_verify, serial_verify,
            "{case}: chunk hashes or progress"
        );
        assert!(pooled == serial, "{case}: the pool changed the set");
        // A read that fails ahead of the walk fails the plan as the serial walk
        // does, after the same reads, never sooner or later.
        let fail_at = Some(large as u64 / 2 - 5000);
        let (serial_error, serial_execution) = plan(1, fail_at);
        let (pooled_error, pooled_execution) = plan(4, fail_at);
        let (serial_error, pooled_error) = (
            serial_error
                .err()
                .expect("the serial plan read past the fault"),
            pooled_error
                .err()
                .expect("the pooled plan read past the fault"),
        );
        assert_eq!(pooled_error.to_string(), serial_error.to_string(), "{case}");
        assert_eq!(
            pooled_execution.diagnostics.source_io(),
            serial_execution.diagnostics.source_io(),
            "{case}: a failed read changed the reads"
        );
    }
    // A set of small sources never starts a planning pool.
    let mut inner = MemorySourceAccess::default();
    inner.insert(SourceId(2), 1, small.clone().into());
    let mut options = CreationOptions::default();
    options.execution.workers = 4;
    let execution = options.execution.clone();
    CreationPlan::build(
        Arc::new(inner),
        &[CreationSource {
            name: "small.bin".into(),
            source: SourceId(2),
        }],
        options,
    )
    .unwrap();
    let ledger = execution.diagnostics.memory().unwrap();
    assert_eq!(ledger.category(MemoryCategory::WorkerStacks).peak, 0);
}

/// Wave-2 review, finding F2. With blocks shorter than the 40-byte inline
/// tail threshold, every full block is shorter than it too. The serial walk
/// hashes such a block as a block; the pooled read-ahead took it for an inline
/// tail, never queued it, and failed the plan. One worker and four must agree.
#[test]
fn w2review_pooled_planning_blocks_under_tail_len() {
    use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource, Deduplication};
    for block_size in [40u64, 42, 38, 32] {
        let bytes: Vec<u8> = (0..(8usize << 20) + 5)
            .map(|i| ((i % block_size as usize) * 7 + 1) as u8)
            .collect();
        let build = |workers: usize| {
            let mut inner = MemorySourceAccess::default();
            inner.insert(SourceId(1), 1, bytes.clone().into());
            let mut options = CreationOptions {
                block_size,
                recovery_count: 1,
                deduplication: Deduplication::Aligned,
                ..CreationOptions::default()
            };
            options.execution.workers = workers;
            options.execution.retained_bytes = 2 << 30;
            options.execution.memory = MemoryBudget::new(4 << 30);
            let execution = options.execution.clone();
            let plan = CreationPlan::build(
                Arc::new(inner),
                &[CreationSource {
                    name: "a.bin".into(),
                    source: SourceId(1),
                }],
                options,
            )
            .map_err(|error| error.to_string());
            let reads = execution.diagnostics.source_io();
            let tree = common::TempTree::new(&format!("tiny-blocks-{block_size}-{workers}"));
            let carriers = plan.map(|plan| {
                plan.execute(&tree.path().join("set"), tree.path())
                    .unwrap()
                    .iter()
                    .map(|path| std::fs::read(path).unwrap())
                    .collect::<Vec<_>>()
            });
            (carriers, reads)
        };
        let (serial, serial_io) = build(1);
        let (pooled, pooled_io) = build(4);
        assert!(serial.is_ok(), "block {block_size}: {:?}", serial.err());
        assert!(serial == pooled, "block {block_size}: {:?}", pooled.err());
        assert_eq!(serial_io, pooled_io, "block {block_size}");
    }
}

// --- Clone staging -----------------------------------------------------------

/// What one disk repair alone did. Every file it reads is a source on disk;
/// the recovery data comes from memory.
struct DiskRepair {
    read_bytes: u64,
    write_bytes: u64,
    clones: u64,
    syncs: u64,
}

/// Write every file of `set` into `inputs`, file `damaged` holding `on_disk`
/// under the name `stored` (its own name when that is where it belongs), bind
/// each to its path, and repair into `output`.
fn repair_disk_files(
    set: &common::ManyBlockSet,
    damaged: usize,
    on_disk: &[u8],
    stored: &str,
    inputs: &common::TempTree,
    output: &std::path::Path,
    backup: bool,
) -> DiskRepair {
    use par3_rs::source::DiskSourceAccess;
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let mut access = DiskSourceAccess::with_options(options.clone());
    for (index, (name, bytes)) in set.contents.iter().enumerate() {
        let path = if index == damaged {
            inputs.write(stored, on_disk)
        } else {
            inputs.write(name, bytes)
        };
        access.insert(SourceId(index as u64 + 1), path);
    }
    let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
    for (index, (name, _)) in set.contents.iter().enumerate() {
        session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
    }
    for path in &set.paths {
        for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
            session.merge(packet).unwrap();
        }
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let before = options.diagnostics.file_io();
    let report = session.repair(output, backup).unwrap();
    let after = options.diagnostics.file_io();
    assert_eq!(report.installed.len(), 1, "only the damaged file is staged");
    let (name, bytes) = &set.contents[damaged];
    assert_eq!(
        &std::fs::read(output.join(name)).unwrap(),
        bytes,
        "the installed file differs from the input"
    );
    let run = DiskRepair {
        read_bytes: after.read_bytes - before.read_bytes,
        write_bytes: after.write_bytes - before.write_bytes,
        clones: options.diagnostics.file_clones(),
        syncs: options.diagnostics.file_sync().calls,
    };
    drop(session);
    assert_eq!(options.memory.used(), 0, "the session leaked");
    assert_eq!(options.handles.used(), 0, "a handle leaked");
    run
}

/// Whether this target clones a file repaired in place. macOS always can on
/// APFS; a Linux filesystem without reflink falls back to the copy, which is
/// what the tests then check instead.
fn expect_clone(run: &DiskRepair) -> bool {
    if cfg!(target_os = "macos") {
        assert_eq!(run.clones, 1, "an in-place repair on APFS must clone");
    }
    run.clones == 1
}

/// A 64 MiB file with one damaged block, repaired in place, writes one block:
/// the staged clone already holds the other 63, so they are read once for the
/// syndromes and never written, and nothing is read back. The default numbered
/// backup keeps the damaged bytes, sharing every extent but the one rewritten.
#[test]
fn a_file_repaired_in_place_from_its_clone_writes_only_its_lost_block() {
    let block = 1u64 << 20;
    let tree = common::TempTree::new("clone-in-place");
    let set = common::cauchy_block_set(64, block, 2, b"PAR3 clone staging", &tree);
    let bytes = &set.contents[0].1;
    let mut damaged = bytes.clone();
    damaged[7 * block as usize + 11] ^= 0x80;
    for backup in [false, true] {
        let inputs = common::TempTree::new("clone-in-place-inputs");
        let run = repair_disk_files(
            &set,
            0,
            &damaged,
            "input.bin",
            &inputs,
            inputs.path(),
            backup,
        );
        let len = bytes.len() as u64;
        // The surviving blocks, read once for the syndromes; no read-back.
        assert_eq!(run.read_bytes, len - block);
        assert_eq!(run.syncs, 1);
        if expect_clone(&run) {
            assert_eq!(run.write_bytes, block, "backup {backup}");
        } else {
            assert_eq!(run.write_bytes, len, "backup {backup}");
        }
        if backup {
            assert_eq!(
                std::fs::read(inputs.path().join("input.bin.1")).unwrap(),
                damaged,
                "the backup holds the damaged file"
            );
        }
    }
}

/// A file whose every block is intact but whose length is wrong stages on the
/// copy path. Cloned and cut back, it costs no read and no write at all; one
/// cut short inside its last block loses that block, and the clone, extended,
/// writes that one block alone. Copied instead, where the filesystem has no
/// clones, each reads every block it still holds.
#[test]
fn a_clone_cut_or_extended_to_its_length_writes_only_what_it_lacks() {
    let block = 64u64 << 10;
    let tree = common::TempTree::new("clone-length");
    let set = common::cauchy_block_set(16, block, 2, b"PAR3 clone length", &tree);
    let bytes = &set.contents[0].1;
    let len = bytes.len() as u64;
    let mut grown = bytes.clone();
    grown.extend_from_slice(b"trailing bytes that are not part of the file");
    let short = bytes[..bytes.len() - 1000].to_vec();
    for (case, on_disk, written, read, copied) in [
        ("grown", grown, 0, 0, len),
        ("short", short, block, len - block, len - block),
    ] {
        let inputs = common::TempTree::new("clone-length-inputs");
        let run = repair_disk_files(
            &set,
            0,
            &on_disk,
            "input.bin",
            &inputs,
            inputs.path(),
            false,
        );
        if expect_clone(&run) {
            assert_eq!(run.read_bytes, read, "{case}");
            assert_eq!(run.write_bytes, written, "{case}");
        } else {
            assert_eq!(run.read_bytes, copied, "{case}");
            assert_eq!(run.write_bytes, len, "{case}");
        }
    }
}

/// An FFT-coded set takes the same path: the damaged file of four, repaired in
/// place, writes the one block it lost.
#[test]
fn an_fft_repair_in_place_writes_only_the_lost_block() {
    let tree = common::TempTree::new("clone-fft");
    let set = common::many_block_set(4, 16, 0, 4, b"PAR3 clone fft", &tree);
    let mut damaged = set.contents[1].1.clone();
    damaged[70] ^= 0x80;
    let inputs = common::TempTree::new("clone-fft-inputs");
    let run = repair_disk_files(
        &set,
        1,
        &damaged,
        "input1.bin",
        &inputs,
        inputs.path(),
        false,
    );
    if expect_clone(&run) {
        assert_eq!(run.write_bytes, 64);
    } else {
        assert_eq!(run.write_bytes, damaged.len() as u64);
    }
}

/// Only the file the evidence verified is ever cloned, from its registry's own
/// handle, wherever the output goes. A source found under another name, and a
/// separate output directory whose destination holds a different file with the
/// same bytes, both clone that source, and the source itself is never changed.
#[test]
fn a_moved_source_or_another_file_at_the_destination_clones_the_verified_source() {
    let block = 64u64 << 10;
    let tree = common::TempTree::new("clone-moved");
    let set = common::cauchy_block_set(16, block, 2, b"PAR3 clone moved", &tree);
    let bytes = &set.contents[0].1;
    let len = bytes.len() as u64;
    let mut damaged = bytes.clone();
    damaged[3 * block as usize] ^= 0x80;

    let inputs = common::TempTree::new("clone-moved-inputs");
    let run = repair_disk_files(
        &set,
        0,
        &damaged,
        "moved.bin",
        &inputs,
        inputs.path(),
        false,
    );
    let written = if expect_clone(&run) { block } else { len };
    assert_eq!(run.write_bytes, written, "a moved source");
    assert_eq!(run.read_bytes, len - block, "no read-back");
    assert_eq!(
        std::fs::read(inputs.path().join("moved.bin")).unwrap(),
        damaged
    );

    let inputs = common::TempTree::new("clone-other-inputs");
    let output = common::TempTree::new("clone-other-output");
    output.write("input.bin", &damaged);
    let run = repair_disk_files(
        &set,
        0,
        &damaged,
        "input.bin",
        &inputs,
        output.path(),
        false,
    );
    let written = if expect_clone(&run) { block } else { len };
    assert_eq!(run.write_bytes, written, "another file at the destination");
    assert_eq!(run.read_bytes, len - block, "no read-back");
    assert_eq!(
        std::fs::read(inputs.path().join("input.bin")).unwrap(),
        damaged
    );
}

/// REVIEW: a registry that wraps the disk one and serves bytes the file does
/// not hold yet (here: one block still in its write-back cache), forwarding
/// the disk snapshot but not `open_file`. `SourceAccess::open_file` says the
/// engine stages from a local file only through that hook; repair must
/// install the bytes the registry served and the evidence verified.
#[test]
fn review_repair_never_clones_a_file_its_registry_did_not_hand_over() {
    use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceSnapshot};
    struct Overlay {
        inner: DiskSourceAccess,
        at: u64,
        bytes: Vec<u8>,
    }
    impl SourceAccess for Overlay {
        fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
            self.inner.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read_at(source, offset, out)?;
            if source == SourceId(1) {
                let end = offset + read as u64;
                let (start, stop) = (
                    offset.max(self.at),
                    end.min(self.at + self.bytes.len() as u64),
                );
                if start < stop {
                    out[(start - offset) as usize..(stop - offset) as usize].copy_from_slice(
                        &self.bytes[(start - self.at) as usize..(stop - self.at) as usize],
                    );
                }
            }
            Ok(read)
        }
        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<std::ops::Range<u64>>> {
            self.inner.next_available(source, offset)
        }
    }
    let block = 64u64 << 10;
    let tree = common::TempTree::new("review-overlay");
    let set = common::cauchy_block_set(16, block, 2, b"PAR3 review overlay", &tree);
    let (name, bytes) = &set.contents[0];
    // Block 3 is damaged everywhere; block 9 is only stale on disk.
    let mut on_disk = bytes.clone();
    on_disk[3 * block as usize] ^= 0x80;
    let cached = 9 * block as usize..10 * block as usize;
    on_disk[cached.clone()].fill(0);
    let inputs = common::TempTree::new("review-overlay-inputs");
    let path = inputs.write(name, &on_disk);
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let mut inner = DiskSourceAccess::with_options(options.clone());
    inner.insert(SourceId(1), path.clone());
    let access = Overlay {
        inner,
        at: cached.start as u64,
        bytes: bytes[cached].to_vec(),
    };
    let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
    session.bind_file(name, SourceId(1)).unwrap();
    for carrier in &set.paths {
        for packet in common::scanned_packets(std::fs::read(carrier).unwrap(), &options) {
            session.merge(packet).unwrap();
        }
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.status, RepairStatus::Ready);
    assert_eq!(assessment.lost_blocks, vec![3]);
    let report = session.repair(inputs.path(), false);
    let clones = options.diagnostics.file_clones();
    let installed = std::fs::read(&path).unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert!(
        installed == *bytes,
        "the installed file is not the one the evidence verified (clones {clones}, block 9 zero: {})",
        installed[9 * block as usize..10 * block as usize]
            .iter()
            .all(|&b| b == 0)
    );
    assert_eq!(
        clones, 0,
        "a file the registry never handed over was cloned"
    );
}

/// REVIEW (invariant 8): the destination is rewritten in place after its
/// clone was taken, while repair is reading it for the syndromes. The clone
/// holds the old bytes; the repair must end in `SourceChanged`, install
/// nothing and leave no temporary.
#[cfg(unix)]
#[test]
fn review_a_destination_rewritten_after_its_clone_ends_in_source_changed() {
    use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceFile, SourceSnapshot};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Rewriter {
        inner: DiskSourceAccess,
        path: std::path::PathBuf,
        armed: AtomicBool,
    }
    impl SourceAccess for Rewriter {
        fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
            self.inner.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            if self.armed.swap(false, Ordering::SeqCst) {
                use std::os::unix::fs::FileExt;
                let file = std::fs::OpenOptions::new().write(true).open(&self.path)?;
                // A held block (12), not the lost one (3).
                file.write_all_at(&[0x5a], 12 * (64 << 10) + 5)?;
            }
            self.inner.read_at(source, offset, out)
        }
        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<std::ops::Range<u64>>> {
            self.inner.next_available(source, offset)
        }
        fn open_file(&self, source: SourceId) -> std::io::Result<Option<SourceFile>> {
            self.inner.open_file(source)
        }
    }
    let block = 64u64 << 10;
    let tree = common::TempTree::new("review-rewrite");
    let set = common::cauchy_block_set(16, block, 2, b"PAR3 review rewrite", &tree);
    let (name, bytes) = &set.contents[0];
    let mut on_disk = bytes.clone();
    on_disk[3 * block as usize] ^= 0x80;
    let inputs = common::TempTree::new("review-rewrite-inputs");
    let path = inputs.write(name, &on_disk);
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let mut inner = DiskSourceAccess::with_options(options.clone());
    inner.insert(SourceId(1), path.clone());
    let access = Arc::new(Rewriter {
        inner,
        path: path.clone(),
        armed: AtomicBool::new(false),
    });
    let mut session = Par3RepairSession::new(set.id, access.clone(), options.clone()).unwrap();
    session.bind_file(name, SourceId(1)).unwrap();
    for carrier in &set.paths {
        for packet in common::scanned_packets(std::fs::read(carrier).unwrap(), &options) {
            session.merge(packet).unwrap();
        }
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.lost_blocks, vec![3]);
    access.armed.store(true, Ordering::SeqCst);
    let report = session.repair(inputs.path(), false);
    let clones = options.diagnostics.file_clones();
    assert!(!access.armed.load(Ordering::SeqCst), "repair read nothing");
    let Err(EngineError::RepairInterrupted {
        installed,
        temporary,
        cause,
    }) = report
    else {
        panic!("{report:?} (clones {clones})");
    };
    assert!(
        matches!(*cause, EngineError::SourceChanged(SourceId(1))),
        "{cause:?}"
    );
    assert!(installed.is_empty());
    let mut rewritten = on_disk.clone();
    rewritten[12 * block as usize + 5] = 0x5a;
    assert!(
        std::fs::read(&path).unwrap() == rewritten,
        "something was installed"
    );
    // Only the reported temporaries (and their private staging directory).
    for path in &temporary {
        std::fs::remove_file(path).unwrap();
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }
    let left: Vec<_> = std::fs::read_dir(inputs.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        left,
        vec![std::ffi::OsString::from(name)],
        "clones {clones}"
    );
}
