//! Putting damaged files back, against the reference implementation's archives
//! and against sets this crate wrote itself.
//!
//! Every case damages a *regenerated input file* in a scratch directory — never
//! the `.par3` bytes, which are the reference's and are never edited. The oracle
//! archives cover a set the reference laid out, one tail to a block; the sets
//! created here cover what the oracles do not: packed tail blocks, files that
//! are nothing but a packed tail, and empty files.
//!
//! Setting `PAR3_KEEP_OUTPUT` keeps each scratch tree and prints where it is, so
//! a damaged tree can be handed to the reference binary.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use common::{
    TempTree, a_bin, assert_block_eq, b_txt, big_bin, c_bin, gf8_contents, gf8_set, gf16_contents,
    gf16_set, packets_of, set_par3, set_vol0_par3, set_vol1_par3, write_gf8_inputs,
    write_gf16_inputs,
};
use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::repair::{RepairLimits, RepairOptions, plan_repair, repair_set};
use par3_rs::{
    CodecLimits, FileVerdict, Par3Error, Par3Set, verify_file, verify_file_at_path, verify_set,
};

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// The GF(2^8) oracle archive with its three input files on disk.
fn gf8_tree(label: &str) -> (TempTree, Par3Set) {
    let tree = TempTree::new(label);
    write_gf8_inputs(&tree);
    (tree, gf8_set())
}

/// The GF(2^16) oracle archive with its one input file on disk.
fn gf16_tree(label: &str) -> (TempTree, Par3Set) {
    let tree = TempTree::new(label);
    write_gf16_inputs(&tree);
    (tree, gf16_set())
}

/// Deterministic bytes, so a kept output can be regenerated from the test alone.
fn filler(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(37).wrapping_add(seed.wrapping_mul(101))) as u8)
        .collect()
}

/// A set this crate wrote, whose tail blocks are packed.
///
/// `big.bin` is four whole blocks and a 500-byte tail; `small/a.bin` is a
/// 500-byte tail that shares that same block; `small/b.bin`, `small/c.bin` and
/// `small/d.bin` are 300-byte tails that share one block between the three of
/// them; and `empty.bin` has no bytes and no block at all.
fn packed_tree(label: &str, recovery: u64) -> (TempTree, Par3Set, Vec<(&'static str, Vec<u8>)>) {
    let contents: Vec<(&'static str, Vec<u8>)> = vec![
        ("big.bin", filler(1, 4500)),
        ("small/a.bin", filler(2, 500)),
        ("small/b.bin", filler(3, 300)),
        ("small/c.bin", filler(4, 300)),
        ("small/d.bin", filler(5, 300)),
        ("empty.bin", Vec::new()),
    ];
    let tree = TempTree::new(label);
    for (name, data) in &contents {
        tree.write(name, data);
    }

    let names: Vec<PathBuf> = contents
        .iter()
        .map(|(name, _)| PathBuf::from(name))
        .collect();
    let inputs = InputSpec::new(tree.path(), &names);
    let report = create(
        &inputs,
        &tree.path().join("set.par3"),
        &CreateOptions::default()
            .with_block_size(1000)
            .with_recovery(RecoveryAmount::Blocks(recovery)),
    )
    .expect("the set is created");
    assert_eq!(
        report.packed_tails, 3,
        "three tails share a block with another"
    );

    let packets = report
        .files_written
        .iter()
        .flat_map(|path| packets_of(&std::fs::read(path).expect("a written file")))
        .collect();
    let set = Par3Set::from_packets_for(packets, report.set_id).expect("the set reads back");
    (tree, set, contents)
}

/// Flip every bit of one byte of a file already in the tree.
fn flip(tree: &TempTree, name: &str, at: usize) {
    let mut data = tree.read(name);
    data[at] ^= 0xff;
    tree.write(name, &data);
}

/// Cut a file short.
fn truncate(tree: &TempTree, name: &str, len: usize) {
    let data = tree.read(name);
    tree.write(name, &data[..len]);
}

/// Delete a file from the tree.
fn remove(tree: &TempTree, name: &str) {
    std::fs::remove_file(tree.path().join(name)).expect("the file is removed");
}

/// Every file in the tree, by path, with its length and last-modified time.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("a readable directory") {
            let entry = entry.expect("a directory entry");
            let metadata = entry.metadata().expect("metadata");
            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                out.insert(
                    entry.path(),
                    (
                        metadata.len(),
                        metadata.modified().expect("a modified time"),
                    ),
                );
            }
        }
    }
    out
}

/// Repair the tree and insist that every protected file came back byte for byte.
fn repair_and_check(
    tree: &TempTree,
    set: &Par3Set,
    contents: &[(&str, Vec<u8>)],
    options: &RepairOptions,
) -> par3_rs::RepairReport {
    let report = repair_set(set, tree.path(), options).expect("the repair runs");
    assert!(
        report.is_complete(),
        "the set is still not complete: {:?}",
        report.verify_after().files()
    );
    for file in report.repaired() {
        assert!(file.verified(), "{} did not check out", file.path());
    }
    for (name, expected) in contents {
        assert_block_eq(&tree.read(name), expected, name);
    }
    assert!(
        no_temp_files_left(tree.path()),
        "a temporary file was left behind"
    );
    report
}

fn no_temp_files_left(root: &Path) -> bool {
    snapshot(root)
        .keys()
        .all(|path| path.extension().is_none_or(|extension| extension != "tmp"))
}

// ---------------------------------------------------------------------------
// 1. Every kind of damage, on a reference set and on one of ours
// ---------------------------------------------------------------------------

#[test]
fn a_flipped_byte_in_a_full_block_is_repaired() {
    let (tree, set) = gf8_tree("repair-full-block");
    flip(&tree, "a.bin", 2500);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [1u64]);
    assert_eq!(plan.recovery_to_use(), [0u64]);
    assert_eq!(plan.available_recovery(), 2);
    assert_eq!(plan.files_to_rewrite(), ["a.bin"]);
    assert!(plan.needs_repair() && plan.is_possible());
    assert_eq!(plan.missing_recovery_blocks(), 0);

    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert_eq!(report.repaired().len(), 1);
    assert_eq!(report.repaired()[0].path(), "a.bin");
}

#[test]
fn a_flipped_byte_in_a_described_tail_is_repaired() {
    let (tree, set) = gf8_tree("repair-tail");
    // a.bin's tail is its last 1000 bytes, alone in input block 2.
    flip(&tree, "a.bin", 4500);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [2u64]);
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[test]
fn a_flipped_byte_in_an_inline_tail_costs_no_recovery_block() {
    let (tree, set) = gf8_tree("repair-inline-tail");
    // b.txt is ten bytes, so its tail lives in the File packet rather than in a
    // block: nothing is lost, and the file is still rewritten from the packet.
    flip(&tree, "b.txt", 3);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert!(plan.lost_blocks().is_empty());
    assert!(plan.recovery_to_use().is_empty());
    assert_eq!(plan.files_to_rewrite(), ["b.txt"]);

    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert_eq!(report.repaired().len(), 1);
    assert_eq!(tree.read("b.txt"), b_txt());
}

#[test]
fn a_truncation_mid_block_is_repaired() {
    let (tree, set) = gf8_tree("repair-truncated");
    // 3000 bytes of 5000: block 0 survives, block 1 is half gone and the tail
    // block is gone entirely.
    truncate(&tree, "a.bin", 3000);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [1u64, 2]);
    assert_eq!(plan.recovery_to_use(), [0u64, 1]);
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[test]
fn a_truncation_to_zero_bytes_is_repaired() {
    let (tree, set) = gf8_tree("repair-emptied");
    truncate(&tree, "sub/c.bin", 0);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [3u64, 4]);
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[test]
fn a_missing_file_is_rebuilt() {
    let (tree, set) = gf8_tree("repair-missing");
    remove(&tree, "sub/c.bin");

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [3u64, 4]);
    assert_eq!(plan.files_to_rewrite(), ["sub/c.bin"]);
    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert!(
        report.repaired()[0].backup().is_none(),
        "there was nothing to back up"
    );
}

#[test]
fn a_missing_file_in_a_missing_directory_is_rebuilt() {
    let (tree, set) = gf8_tree("repair-missing-dir");
    std::fs::remove_dir_all(tree.path().join("sub")).expect("the directory goes");
    assert!(!tree.path().join("sub").exists());

    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert!(tree.path().join("sub").is_dir());
}

#[test]
fn a_file_longer_than_expected_is_cut_back_without_spending_recovery() {
    let (tree, set) = gf8_tree("repair-overlong");
    let mut longer = c_bin();
    longer.extend_from_slice(b"and then some");
    tree.write("sub/c.bin", &longer);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert!(
        plan.lost_blocks().is_empty(),
        "every block is still there; only the length is wrong"
    );
    assert_eq!(plan.files_to_rewrite(), ["sub/c.bin"]);
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[test]
fn a_multi_block_gf16_file_is_repaired_in_block_and_in_tail() {
    let (tree, set) = gf16_tree("repair-gf16");
    assert_eq!(set.block_count(), 301);
    // One byte in an early block, one in a late one, and one in the 50-byte tail
    // that lives alone in the last block: three losses for three recovery
    // blocks.
    flip(&tree, "big.bin", 7);
    flip(&tree, "big.bin", 25_000);
    flip(&tree, "big.bin", 30_040);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [0u64, 250, 300]);
    assert_eq!(plan.recovery_to_use(), [0u64, 1, 2]);
    repair_and_check(&tree, &set, &gf16_contents(), &RepairOptions::default());
}

#[test]
fn one_tail_of_a_packed_block_is_repaired_and_the_others_are_left_alone() {
    let (tree, set, contents) = packed_tree("repair-packed-tail", 4);
    // small/c.bin is the middle 300 bytes of the block small/b.bin and
    // small/d.bin also write into.
    let before = snapshot(tree.path());
    flip(&tree, "small/c.bin", 100);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(
        plan.lost_blocks(),
        [5u64],
        "one wrong tail spoils the whole block it shares"
    );
    assert_eq!(plan.files_to_rewrite(), ["small/c.bin"]);

    let borrowed: Vec<(&str, Vec<u8>)> = contents
        .iter()
        .map(|(name, data)| (*name, data.clone()))
        .collect();
    repair_and_check(&tree, &set, &borrowed, &RepairOptions::default());

    for neighbour in ["small/b.bin", "small/d.bin", "big.bin"] {
        let path = tree.path().join(neighbour);
        assert_eq!(
            before[&path],
            snapshot(tree.path())[&path],
            "{neighbour} was touched"
        );
    }
}

#[test]
fn a_file_that_is_nothing_but_a_packed_tail_is_rebuilt_when_it_goes_missing() {
    let (tree, set, contents) = packed_tree("repair-packed-missing", 4);
    remove(&tree, "small/b.bin");
    // small/a.bin shares block 4 with big.bin's tail, so removing it exercises
    // the second packed block too.
    remove(&tree, "small/a.bin");

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [4u64, 5]);
    assert_eq!(plan.files_to_rewrite(), ["small/a.bin", "small/b.bin"]);

    let borrowed: Vec<(&str, Vec<u8>)> = contents
        .iter()
        .map(|(name, data)| (*name, data.clone()))
        .collect();
    repair_and_check(&tree, &set, &borrowed, &RepairOptions::default());
}

#[test]
fn an_empty_file_that_went_missing_is_put_back_without_a_recovery_block() {
    let (tree, set, contents) = packed_tree("repair-empty", 1);
    remove(&tree, "empty.bin");

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert!(
        plan.lost_blocks().is_empty(),
        "an empty file holds no block"
    );
    assert_eq!(plan.files_to_rewrite(), ["empty.bin"]);

    let borrowed: Vec<(&str, Vec<u8>)> = contents
        .iter()
        .map(|(name, data)| (*name, data.clone()))
        .collect();
    repair_and_check(&tree, &set, &borrowed, &RepairOptions::default());
    assert_eq!(tree.read("empty.bin"), Vec::<u8>::new());
}

#[test]
fn damage_in_a_full_block_leaves_the_packed_block_that_file_shares_to_be_assembled() {
    let (tree, set, contents) = packed_tree("repair-created-block", 4);
    flip(&tree, "big.bin", 1500);
    flip(&tree, "big.bin", 3200);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(
        plan.lost_blocks(),
        [1u64, 3],
        "two whole blocks; the tail block big.bin shares with small/a.bin survives \
         and has to be put together from both of them, one of which is damaged"
    );

    let borrowed: Vec<(&str, Vec<u8>)> = contents
        .iter()
        .map(|(name, data)| (*name, data.clone()))
        .collect();
    repair_and_check(&tree, &set, &borrowed, &RepairOptions::default());
}

// ---------------------------------------------------------------------------
// 2. The edge of what the recovery data can do
// ---------------------------------------------------------------------------

#[test]
fn losses_equal_to_the_recovery_count_succeed() {
    let (tree, set) = gf8_tree("repair-exactly-enough");
    flip(&tree, "a.bin", 10);
    flip(&tree, "sub/c.bin", 10);

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [0u64, 3]);
    assert_eq!(plan.available_recovery(), 2);
    assert!(plan.is_possible());
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[test]
fn one_loss_too_many_is_refused_and_nothing_on_disk_changes() {
    let (tree, set) = gf8_tree("repair-not-enough");
    flip(&tree, "a.bin", 10);
    flip(&tree, "a.bin", 2010);
    flip(&tree, "sub/c.bin", 10);
    let before = snapshot(tree.path());

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [0u64, 1, 3]);
    assert!(!plan.is_possible());
    assert!(
        plan.recovery_to_use().is_empty(),
        "nothing is reserved for a repair that cannot happen"
    );
    assert_eq!(plan.missing_recovery_blocks(), 1);

    let error = repair_set(&set, tree.path(), &RepairOptions::default())
        .expect_err("three blocks cannot come from two");
    assert!(
        matches!(
            error,
            Par3Error::InsufficientRecovery {
                lost: 3,
                available: 2
            }
        ),
        "unexpected error: {error}"
    );
    assert_eq!(snapshot(tree.path()), before, "the tree was written to");
}

#[test]
fn recovery_from_a_subset_of_volumes() {
    // The index file alone carries the matrix but no recovery block at all.
    let index_only =
        Par3Set::from_packets_for(packets_of(&set_par3()), common::SET_ID).expect("a set");
    let tree = TempTree::new("repair-index-only");
    write_gf8_inputs(&tree);
    flip(&tree, "a.bin", 10);
    let plan = plan_repair(&index_only, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.available_recovery(), 0);
    assert!(!plan.is_possible());
    drop(tree);

    // The index and the first volume: one recovery block, row 0.
    let mut packets = packets_of(&set_par3());
    packets.extend(packets_of(&set_vol0_par3()));
    let first = Par3Set::from_packets_for(packets, common::SET_ID).expect("a set");
    let tree = TempTree::new("repair-first-volume");
    write_gf8_inputs(&tree);
    flip(&tree, "a.bin", 10);
    let plan = plan_repair(&first, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.recovery_to_use(), [0u64]);
    repair_and_check(&tree, &first, &gf8_contents(), &RepairOptions::default());
    drop(tree);

    // The index and the *last* volume: the row that is used is not row 0, which
    // the decoder's geometry has to be wide enough to name.
    let mut packets = packets_of(&set_par3());
    packets.extend(packets_of(&set_vol1_par3()));
    let last = Par3Set::from_packets_for(packets, common::SET_ID).expect("a set");
    let tree = TempTree::new("repair-last-volume");
    write_gf8_inputs(&tree);
    flip(&tree, "sub/c.bin", 3999);
    let plan = plan_repair(&last, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.recovery_to_use(), [1u64]);
    repair_and_check(&tree, &last, &gf8_contents(), &RepairOptions::default());
}

// ---------------------------------------------------------------------------
// 3. What happens to the damaged file
// ---------------------------------------------------------------------------

#[test]
fn the_damaged_file_is_kept_beside_the_repaired_one_and_numbered() {
    let (tree, set) = gf8_tree("repair-backup");
    flip(&tree, "a.bin", 10);
    let damaged_once = tree.read("a.bin");

    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert_eq!(
        report.repaired()[0].backup(),
        Some(tree.path().join("a.bin.1").as_path())
    );
    assert_eq!(tree.read("a.bin.1"), damaged_once);

    flip(&tree, "a.bin", 20);
    let damaged_twice = tree.read("a.bin");
    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert_eq!(
        report.repaired()[0].backup(),
        Some(tree.path().join("a.bin.2").as_path())
    );
    assert_eq!(tree.read("a.bin.1"), damaged_once);
    assert_eq!(tree.read("a.bin.2"), damaged_twice);
}

#[test]
fn without_a_backup_the_damaged_bytes_are_simply_replaced() {
    let (tree, set) = gf8_tree("repair-no-backup");
    flip(&tree, "a.bin", 10);

    let report = repair_and_check(
        &tree,
        &set,
        &gf8_contents(),
        &RepairOptions::default().with_backup(false),
    );
    assert!(report.repaired()[0].backup().is_none());
    assert!(!tree.path().join("a.bin.1").exists());
    assert_eq!(tree.read("a.bin"), a_bin());
}

// ---------------------------------------------------------------------------
// 4. A set with nothing wrong with it
// ---------------------------------------------------------------------------

#[test]
fn a_complete_set_is_not_touched_at_all() {
    let (tree, set) = gf8_tree("repair-complete");
    let before = snapshot(tree.path());

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert!(!plan.needs_repair());
    assert!(plan.lost_blocks().is_empty());
    assert!(plan.is_possible());

    let report = repair_set(&set, tree.path(), &RepairOptions::default()).expect("the repair runs");
    assert!(report.repaired().is_empty());
    assert!(report.is_complete());
    assert!(report.verify_after().is_complete());
    assert_eq!(
        snapshot(tree.path()),
        before,
        "a complete set was written to anyway"
    );
}

// ---------------------------------------------------------------------------
// 5. Limits, and refusals that are about the set rather than the damage
// ---------------------------------------------------------------------------

#[test]
fn a_set_larger_than_the_limits_allow_is_refused_before_anything_is_read() {
    let (tree, set) = gf8_tree("repair-limits");
    let limits = RepairLimits::default().with_max_input_blocks(2);
    let error = plan_repair(&set, tree.path(), &limits).expect_err("five blocks is over two");
    assert!(
        matches!(&error, Par3Error::RepairLimitExceeded { reason } if reason.contains('5')),
        "unexpected error: {error}"
    );

    let limits = RepairLimits::default().with_codec(CodecLimits::new(100));
    flip(&tree, "a.bin", 10);
    let error = repair_set(
        &set,
        tree.path(),
        &RepairOptions::default().with_limits(limits),
    )
    .expect_err("a 2000-byte block is over a 100-byte budget");
    assert!(
        matches!(
            error,
            Par3Error::CodecLimitExceeded { .. } | Par3Error::RepairLimitExceeded { .. }
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn more_lost_blocks_than_the_codec_will_solve_for_is_refused_and_nothing_on_disk_changes() {
    let (tree, set) = gf8_tree("repair-lost-ceiling");
    flip(&tree, "a.bin", 10);
    flip(&tree, "sub/c.bin", 10);
    let before = snapshot(tree.path());

    let plan = plan_repair(&set, tree.path(), &RepairLimits::default()).expect("a plan");
    assert_eq!(plan.lost_blocks(), [0u64, 3]);
    assert!(plan.is_possible(), "two losses, two recovery blocks");

    let limits = RepairLimits::default().with_codec(CodecLimits::default().with_max_lost_blocks(1));
    let error = repair_set(
        &set,
        tree.path(),
        &RepairOptions::default().with_limits(limits),
    )
    .expect_err("two lost blocks are over a ceiling of one");
    assert!(
        matches!(&error, Par3Error::CodecLimitExceeded { reason } if reason.contains("2 lost")),
        "unexpected error: {error}"
    );
    assert_eq!(snapshot(tree.path()), before, "the tree was written to");
    assert!(no_temp_files_left(tree.path()));
}

// ---------------------------------------------------------------------------
// 5a. Links in the tree: what was planted before the repair is never followed
// ---------------------------------------------------------------------------

/// The temporary name a repair gives one of the set's files.
fn temporary_name(set: &Par3Set, name: &str) -> String {
    let index = set
        .files()
        .iter()
        .position(|file| file.path() == name)
        .expect("a file of the set");
    let hex: String = set
        .input_set_id()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    format!("par3_{hex}_{index}.tmp")
}

#[cfg(unix)]
#[test]
fn a_link_planted_under_the_temporary_name_is_refused_and_its_target_is_untouched() {
    let (tree, set) = gf8_tree("repair-planted-link");
    flip(&tree, "a.bin", 10);
    // Somewhere the set never named, reachable through a link under the name
    // the repair is about to use.
    let victim = tree.write("elsewhere/victim.bin", b"not part of the set");
    std::os::unix::fs::symlink(&victim, tree.path().join(temporary_name(&set, "a.bin")))
        .expect("a link");
    let before = snapshot(tree.path());

    let error = repair_set(&set, tree.path(), &RepairOptions::default())
        .expect_err("the temporary name is taken by a link");
    assert!(
        matches!(&error, Par3Error::FileIo { path, .. } if path.ends_with(".tmp")),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read(&victim).expect("the victim is still there"),
        b"not part of the set",
        "the link was followed"
    );
    assert_eq!(snapshot(tree.path()), before, "the tree was written to");
    assert!(
        matches!(
            verify_file(&set, &set.files()[0], &tree.read("a.bin")),
            FileVerdict::Damaged { .. }
        ),
        "the damaged file was replaced"
    );
}

#[test]
fn a_plain_file_left_under_the_temporary_name_by_an_interrupted_repair_is_replaced() {
    let (tree, set) = gf8_tree("repair-stale-temporary");
    flip(&tree, "a.bin", 10);
    tree.write(
        &temporary_name(&set, "a.bin"),
        b"half of an earlier rebuild",
    );
    repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
}

#[cfg(unix)]
#[test]
fn a_directory_of_the_set_that_is_a_link_is_refused_before_its_file_is_rebuilt() {
    let (tree, set) = gf8_tree("repair-linked-directory");
    // `sub/` now points outside the tree the set describes; the file under it
    // reads fine through the link and is damaged.
    let outside = tree.path().join("elsewhere");
    std::fs::create_dir_all(&outside).expect("a directory");
    std::fs::rename(tree.path().join("sub/c.bin"), outside.join("c.bin")).expect("moved");
    std::fs::remove_dir(tree.path().join("sub")).expect("emptied");
    std::os::unix::fs::symlink(&outside, tree.path().join("sub")).expect("a link");
    flip(&tree, "sub/c.bin", 10);
    let before = snapshot(tree.path());

    let error = repair_set(&set, tree.path(), &RepairOptions::default())
        .expect_err("a linked directory is refused");
    assert!(
        matches!(&error, Par3Error::FileIo { path, .. } if path.ends_with("sub")),
        "unexpected error: {error}"
    );
    assert_eq!(snapshot(tree.path()), before, "the tree was written to");
    assert!(no_temp_files_left(tree.path()));
}

// ---------------------------------------------------------------------------
// 6. The streaming verify and the in-memory one agree
// ---------------------------------------------------------------------------

#[test]
fn reading_a_damaged_file_gives_the_same_verdict_as_holding_its_bytes() {
    let set = gf8_set();
    let file = &set.files()[0];
    let whole = a_bin();

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("intact", whole.clone()),
        ("empty", Vec::new()),
        ("truncated mid-block", whole[..3000].to_vec()),
        ("truncated into the tail", whole[..4500].to_vec()),
    ];
    for at in [0usize, 1999, 2000, 4000, 4999] {
        let mut damaged = whole.clone();
        damaged[at] ^= 0xff;
        cases.push(("a flipped byte", damaged));
    }
    let mut longer = whole.clone();
    longer.extend_from_slice(b"more");
    cases.push(("over-long", longer));

    let tree = TempTree::new("repair-verdicts-agree");
    for (what, bytes) in &cases {
        let path = tree.write("a.bin", bytes);
        let streamed = verify_file_at_path(&set, file, &path).expect("the file reads");
        assert_eq!(streamed, verify_file(&set, file, bytes), "{what}");
    }

    // The 30,050-byte GF(2^16) input is far larger than the streaming verify's
    // 64 KiB read buffer and its 100-byte block, so a pass that agreed by
    // holding the file would be holding three hundred times its working set.
    let set16 = gf16_set();
    let file16 = &set16.files()[0];
    let mut damaged = big_bin();
    damaged[29_000] ^= 0xff;
    let path = tree.write("big.bin", &damaged);
    assert_eq!(
        verify_file_at_path(&set16, file16, &path).expect("the file reads"),
        verify_file(&set16, file16, &damaged)
    );

    std::fs::remove_file(tree.path().join("a.bin")).expect("the file goes");
    assert_eq!(
        verify_file_at_path(&set, file, &tree.path().join("a.bin")).expect("a missing file"),
        FileVerdict::Missing
    );
}

#[test]
fn a_repaired_tree_verifies_the_same_way_the_repair_said_it_would() {
    let (tree, set) = gf8_tree("repair-verify-after");
    flip(&tree, "a.bin", 4500);
    let report = repair_and_check(&tree, &set, &gf8_contents(), &RepairOptions::default());
    assert_eq!(
        report.verify_after(),
        &verify_set(&set, tree.path()).expect("verification")
    );
    assert_eq!(report.plan().verify().files().len(), 3);
}
