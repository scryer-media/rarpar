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
    for codec in [
        CreationCodec::Cauchy,
        CreationCodec::Fft {
            capacity_log2: 3,
            interleave: 0,
        },
    ] {
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = 128;
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
        assert!(options.diagnostics.file_io().write_bytes > 0);
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
    for budget in ((732 << 10)..=(742 << 10)).step_by(128) {
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
}
