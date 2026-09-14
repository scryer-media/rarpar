//! What each stage of a repair holds at once, and what it still holds when the
//! next stage begins.
//!
//! This is the inventory the memory arc is steered by. Every number comes from
//! [`MemoryBudget::ledger`] rather than from an estimate: `current` at a stage
//! boundary is what that stage left resident, and a category whose `current` is
//! still high one boundary later is coexisting with its successor's peak. The
//! test prints the table and then asserts the bounds that must not regress.
mod common;

use common::{report, walk_stages};
use par3_rs::runtime::{ExecutionOptions, MemoryBudget, MemoryCategory};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{MemorySourceAccess, SourceId};
use std::sync::Arc;

#[test]
fn every_stage_of_a_many_block_repair_states_what_it_holds() {
    let blocks = 16_384usize;
    let (samples, repaired) = walk_stages(
        blocks,
        2,
        &[7, 4_001, 16_383],
        b"PAR3 stage working set inventory",
        128 << 20,
        64 << 20,
    );
    report(
        &samples,
        blocks as u64,
        "16,384 blocks, one file, 64 MiB retained",
    );
    assert_eq!(repaired, 3);

    let by = |label: &str| {
        samples
            .iter()
            .find(|sample| sample.label == label)
            .expect("sampled stage")
    };
    let resident =
        |label: &str, category: MemoryCategory| by(label).ledger.category(category).current;

    // Nothing survives the session.
    let end = by("session dropped");
    assert_eq!(end.used, 0, "the session released everything");
    for (category, entry) in end.ledger.iter() {
        assert_eq!(entry.current, 0, "{} leaked", category.name());
    }

    // The bound this work package exists to hold: what assessment retains is
    // proportional to files and losses, not to the block count. Anything that
    // scales per block belongs to the layout, and is charged once.
    let assessment = resident("verify + assess", MemoryCategory::Assessment);
    assert!(
        assessment < blocks as u64 * 64,
        "assessment retains {assessment} bytes for {blocks} blocks, which is per-block state"
    );

    // Layout and evidence no longer follow the block count: a contiguous
    // mapping is one run, and its checksums are the set's, shared not copied.
    let layout = resident("verify + assess", MemoryCategory::LayoutEvidence);
    assert!(
        layout < blocks as u64 * 8,
        "layout and evidence retain {layout} bytes for {blocks} blocks, \
         which is per-block extent state"
    );

    // The set's checksums are stored once, as runs, at what a `BlockChecksum`
    // actually is rather than at what an ordered-map node would cost.
    let metadata = resident("verify + assess", MemoryCategory::ResolvedMetadata);
    assert!(
        metadata < blocks as u64 * 40,
        "resolved metadata retains {metadata} bytes for {blocks} blocks; \
         a block checksum is 24 bytes"
    );

    // Carrier bytes do not survive the metadata they were parsed into.
    let carrier_after_layout = resident("metadata + layout", MemoryCategory::CarrierPackets);
    let carrier_after_merge = resident("scan + merge", MemoryCategory::CarrierPackets);
    assert!(
        carrier_after_layout <= carrier_after_merge,
        "carrier storage grew after the layout was built"
    );
}

/// One point on the scaling grid: the shape of the set, and what the stages
/// held while repairing it under a fixed budget.
struct ScalePoint {
    label: String,
    blocks: u64,
    layout: u64,
    assessment: u64,
    peak: usize,
}

/// Repair one damaged set under `budget` and report what the stages held.
///
/// `reversed` delivers the carriers' packets back to front, which is the
/// out-of-order arrival a host produces when volumes finish downloading in a
/// different order than they were written.
#[allow(clippy::too_many_arguments)]
fn scale_point(
    label: &str,
    files: usize,
    blocks_per_file: usize,
    interleave: u64,
    recovery: u64,
    damage: &[usize],
    reversed: bool,
    budget: usize,
    retained: usize,
) -> ScalePoint {
    let tree = common::TempTree::new("stage-scale");
    let seed = format!("PAR3 stage scaling {label}");
    let set = common::many_block_set(
        files,
        blocks_per_file,
        interleave,
        recovery,
        seed.as_bytes(),
        &tree,
    );

    let mut access = MemorySourceAccess::default();
    for (index, (name, bytes)) in set.contents.iter().enumerate() {
        let mut damaged = bytes.clone();
        for block in damage {
            // Damage is addressed in the set's global block numbering.
            let local = block.wrapping_sub(index * blocks_per_file);
            if *block >= index * blocks_per_file && local < blocks_per_file {
                damaged[local * 64 + 11] ^= 0x80;
            }
        }
        let _ = name;
        access.insert(SourceId(index as u64 + 1), 2, damaged.into());
    }

    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.memory = MemoryBudget::new(budget);
    options.retained_bytes = retained;

    let mut session = Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
    for (index, (name, _)) in set.contents.iter().enumerate() {
        session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
    }
    let mut paths = set.paths.clone();
    if reversed {
        paths.reverse();
    }
    for path in &paths {
        let mut arriving = common::scanned_packets(std::fs::read(path).unwrap(), &options);
        if reversed {
            arriving.reverse();
        }
        for packet in arriving {
            session.merge(packet).unwrap();
        }
    }
    assert!(session.layout().unwrap().is_some(), "{label}: no layout");
    let layout = options
        .memory
        .ledger()
        .category(MemoryCategory::LayoutEvidence)
        .current;
    assert_eq!(
        session.assess().unwrap().status,
        RepairStatus::Ready,
        "{label}: not repairable"
    );
    let assessment = options
        .memory
        .ledger()
        .category(MemoryCategory::Assessment)
        .current;

    let output = common::TempTree::new("stage-scale-out");
    session.repair(output.path(), false).unwrap();
    // Only damaged files are rebuilt; an intact file is left where it is.
    for (index, (name, bytes)) in set.contents.iter().enumerate() {
        let hurt = damage
            .iter()
            .any(|block| (index * blocks_per_file..(index + 1) * blocks_per_file).contains(block));
        let rebuilt = output.path().join(name);
        if hurt {
            assert_eq!(
                &std::fs::read(&rebuilt).unwrap(),
                bytes,
                "{label}: {name} did not repair"
            );
        } else {
            assert!(!rebuilt.exists(), "{label}: {name} was rebuilt unasked");
        }
    }
    let peak = options.memory.peak();
    drop(session);
    assert_eq!(options.memory.used(), 0, "{label}: the session leaked");

    ScalePoint {
        label: label.to_owned(),
        blocks: (files * blocks_per_file) as u64,
        layout,
        assessment,
        peak,
    }
}

/// The first overlap M1 removed: `assess` used to charge its whole result while
/// layout and evidence were still fully resident, and that charge was a flat
/// per-block estimate. It is now a scratch reservation released at the handover
/// plus a retained charge measured from the result, so what survives assessment
/// scales with files and losses rather than with the block count.
///
/// The budget is fixed at 16 MiB with a 12 MiB retained ceiling across the whole
/// grid. Before the change the same 16,384-block point peaked at 21,126,190
/// bytes and retained about 19 MB, so it could not have run here at all.
#[test]
fn what_assessment_retains_does_not_follow_the_block_count() {
    let mut grid = Vec::new();
    for (label, files, per_file) in [
        ("2k blocks, 1 file", 1usize, 2_048usize),
        ("4k blocks, 1 file", 1, 4_096),
        ("4k blocks, 4 files", 4, 1_024),
        ("8k blocks, 1 file", 1, 8_192),
        ("16k blocks, 2 files", 2, 8_192),
    ] {
        grid.push(scale_point(
            label,
            files,
            per_file,
            2,
            3,
            &[1, 2, 3],
            false,
            16 << 20,
            12 << 20,
        ));
    }
    // More damage, more carriers, and carriers arriving back to front.
    grid.push(scale_point(
        "8k blocks, 6 carriers, reversed arrival",
        2,
        4_096,
        2,
        6,
        &[1, 2, 3, 4, 5, 6],
        true,
        16 << 20,
        12 << 20,
    ));

    println!(
        "{:<40} {:>8} {:>14} {:>14} {:>12}",
        "case", "blocks", "layout/block", "assessment", "peak"
    );
    for point in &grid {
        println!(
            "{:<40} {:>8} {:>14.1} {:>14} {:>12}",
            point.label,
            point.blocks,
            point.layout as f64 / point.blocks as f64,
            point.assessment,
            point.peak
        );
    }

    let smallest = grid
        .iter()
        .map(|point| point.assessment)
        .min()
        .expect("a grid point");
    for point in &grid {
        // Sixteen times the blocks must not mean measurably more retained
        // assessment state. Files and losses may move it; blocks may not.
        assert!(
            point.assessment <= smallest * 4,
            "{}: assessment retains {} bytes against {} at the smallest set",
            point.label,
            point.assessment,
            smallest
        );
        assert!(
            point.assessment < point.blocks * 8,
            "{}: assessment retains {} bytes for {} blocks, which is per-block state",
            point.label,
            point.assessment,
            point.blocks
        );
    }
}

/// The second overlap: the layout charged a flat 512 bytes per extent whether or
/// not the extent held anything. It now charges what its own containers report,
/// and the charge is trued up to the built layout's measured capacity.
#[test]
fn the_layout_charge_follows_the_layout_it_built() {
    for point in [
        scale_point(
            "4k blocks, 1 file",
            1,
            4_096,
            2,
            3,
            &[1, 2, 3],
            false,
            8 << 20,
            4 << 20,
        ),
        scale_point(
            "8k blocks, 4 files",
            4,
            2_048,
            2,
            3,
            &[1, 2, 3],
            false,
            8 << 20,
            4 << 20,
        ),
    ] {
        let per_block = point.layout as f64 / point.blocks as f64;
        println!("{}: layout {per_block:.2} bytes per block", point.label);
        // A contiguous mapping is a run and its checksums are the set's, so the
        // only per-block cost left in this category is the packed verdict.
        assert!(
            per_block < 8.0,
            "{}: layout and evidence hold {per_block:.2} bytes per block, \
             which is per-block extent state again",
            point.label
        );
    }
}

/// Two sessions on one budget. Neither may be starved by the other's peak, and
/// the shared ledger must return to zero when both are dropped.
#[test]
fn two_sessions_share_one_budget_and_both_finish() {
    let budget = MemoryBudget::new(8 << 20);
    let mut ran = 0;
    for seed in [b"PAR3 contention A".as_slice(), b"PAR3 contention B"] {
        let tree = common::TempTree::new("stage-contention");
        let set = common::many_block_set(1, 4_096, 2, 3, seed, &tree);
        let mut access = MemorySourceAccess::default();
        let (name, bytes) = &set.contents[0];
        let mut damaged = bytes.clone();
        for block in [1usize, 2, 3] {
            damaged[block * 64 + 11] ^= 0x80;
        }
        access.insert(SourceId(1), 2, damaged.into());

        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.memory = budget.clone();
        options.retained_bytes = 4 << 20;
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file(name, SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in common::scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        // Hold this session resident while the next one is built and repaired.
        assert!(session.layout().unwrap().is_some());
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let output = common::TempTree::new("stage-contention-out");
        session.repair(output.path(), false).unwrap();
        assert_eq!(&std::fs::read(output.path().join(name)).unwrap(), bytes);
        ran += 1;
        // Deliberately keep `session` alive past the assertion below on the
        // first pass by leaking it into the loop's scope: dropping happens at
        // the end of the iteration, after the peer session has been measured.
        assert!(budget.used() > 0, "a live session holds nothing");
        drop(session);
    }
    assert_eq!(ran, 2);
    assert_eq!(budget.used(), 0, "the shared budget did not return to zero");
    for (category, entry) in budget.ledger().iter() {
        assert_eq!(entry.current, 0, "{} leaked", category.name());
    }
}
