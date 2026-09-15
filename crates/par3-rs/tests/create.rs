//! The creator on its own terms: what it plans, what it refuses, and whether
//! this crate's reader agrees with what it wrote.
//!
//! `tests/oracle_create.rs` is where the output is held against the reference
//! implementation's. This suite covers everything the oracle archives do not
//! exercise — tail packing, the field boundary, deep directory trees, the block
//! size rule, and every refusal.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{TempTree, assert_block_eq, packets_of, type_sequence};
use par3_rs::create::{
    CreateLimits, CreateOptions, CreateReport, InputSpec, RecoveryAmount, create,
};
use par3_rs::gf::Gf8;
use par3_rs::packet::{ChunkDescription, ChunkTail};
use par3_rs::{Encoder, Geometry, Packet, PacketType, Par3Set, suggest_block_size, verify_set};

/// Deterministic bytes, so a failure is reproducible and a kept output can be
/// regenerated from the test alone.
fn filler(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(37).wrapping_add(seed.wrapping_mul(101))) as u8)
        .collect()
}

/// Create a set from files already written into `tree`, with everything else at
/// its default.
fn create_in(
    tree: &TempTree,
    names: &[&str],
    directories: &[&str],
    stem: &str,
    options: &CreateOptions,
) -> CreateReport {
    let files: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
    let extra: Vec<PathBuf> = directories.iter().map(PathBuf::from).collect();
    let inputs = InputSpec::new(tree.path(), &files).with_directories(&extra);
    create(&inputs, &tree.path().join(stem), options).expect("the set is created")
}

/// Read back everything a report says was written.
fn packets_written(report: &CreateReport) -> Vec<Packet> {
    report
        .files_written
        .iter()
        .flat_map(|path| packets_of(&std::fs::read(path).expect("a written file")))
        .collect()
}

// ---------------------------------------------------------------------------
// 3. Round trip through this crate's own reader
// ---------------------------------------------------------------------------

#[test]
fn a_written_set_reads_back_and_verifies_from_any_one_of_its_files() {
    let tree = TempTree::new("round-trip");
    tree.write("a.bin", &filler(1, 5000));
    tree.write("b.txt", &filler(2, 10));
    tree.write("sub/c.bin", &filler(3, 4000));

    let options = CreateOptions::default()
        .with_block_size(2000)
        .with_recovery(RecoveryAmount::Blocks(3))
        .with_comment("round trip");
    let report = create_in(
        &tree,
        &["a.bin", "b.txt", "sub/c.bin"],
        &[],
        "set.par3",
        &options,
    );
    assert_eq!(report.files_written.len(), 3, "an index and two volumes");

    // Every file on its own describes the whole set, which is the point of
    // repeating the common packets into each volume.
    for path in &report.files_written {
        let packets = packets_of(&std::fs::read(path).expect("a written file"));
        let set = Par3Set::from_packets_for(packets, report.set_id).expect("a set");
        assert_eq!(set.block_size(), 2000);
        assert_eq!(set.block_count(), report.block_count);
        assert_eq!(set.files().len(), 3);
        let verdict = verify_set(&set, tree.path()).expect("verification runs");
        assert!(
            verdict.is_complete(),
            "{}: {:?}",
            path.display(),
            verdict.files()
        );
    }

    // All three files together carry every recovery block, each naming a matrix
    // packet that is present.
    let set = Par3Set::from_packets_for(packets_written(&report), report.set_id).expect("a set");
    let indices: Vec<u64> = set
        .recovery_blocks()
        .iter()
        .map(par3_rs::RecoveryBlock::index)
        .collect();
    assert_eq!(indices, [0, 1, 2]);
    assert!(
        set.recovery_blocks()
            .iter()
            .all(par3_rs::RecoveryBlock::matrix_present)
    );
    assert!(
        set.recovery_external_data().is_empty(),
        "the reference writes no Recovery External Data packets, and neither do we"
    );
    assert_eq!(set.comments(), ["round trip"]);
}

#[test]
fn a_set_with_no_recovery_blocks_is_an_index_alone_with_no_matrix_packet() {
    let tree = TempTree::new("index-only");
    tree.write("a.bin", &filler(4, 3000));

    let report = create_in(
        &tree,
        &["a.bin"],
        &[],
        "index.par3",
        &CreateOptions::default().with_block_size(1000),
    );
    assert_eq!(report.recovery_count, 0);
    assert_eq!(report.files_written.len(), 1);
    assert_eq!(
        type_sequence(&tree.read("index.par3")),
        ["PAR CRE", "PAR STA", "PAR FIL", "PAR ROO", "PAR EXT"]
    );

    let set = Par3Set::from_packets_for(packets_written(&report), report.set_id).expect("a set");
    assert!(set.matrix_packets().is_empty());
    assert!(
        verify_set(&set, tree.path())
            .expect("verification runs")
            .is_complete()
    );
}

// ---------------------------------------------------------------------------
// 4. Tail packing
// ---------------------------------------------------------------------------

/// Four files whose tails share two blocks.
///
/// Regenerate this set by hand with:
/// `PAR3_KEEP_OUTPUT=1 cargo test -p par3-rs --test create tails -- --nocapture`,
/// which prints the directory it left behind. The files are `w.bin` (500),
/// `x.bin` (300), `y.bin` (300) and `z.bin` (300) bytes, block size 1000, and
/// the set is `tails.par3`.
#[test]
fn tails_are_packed_into_shared_blocks_in_the_order_the_reference_would_pick() {
    let tree = TempTree::new("tails");
    let sizes = [
        ("w.bin", 500usize),
        ("x.bin", 300),
        ("y.bin", 300),
        ("z.bin", 300),
    ];
    for (seed, (name, size)) in sizes.iter().enumerate() {
        tree.write(name, &filler(seed as u32 + 10, *size));
    }

    let options = CreateOptions::default()
        .with_block_size(1000)
        .with_recovery(RecoveryAmount::Blocks(1));
    let report = create_in(
        &tree,
        &["w.bin", "x.bin", "y.bin", "z.bin"],
        &[],
        "tails.par3",
        &options,
    );

    // 500 opens block 0; the first 300 goes in behind it; the second 300 does
    // not fit in the 200 bytes left, so it opens block 1; the third follows it.
    assert_eq!(report.block_count, 2);
    assert_eq!(report.packed_tails, 2);

    let set = Par3Set::from_packets_for(packets_written(&report), report.set_id).expect("a set");
    let mut placements: Vec<(String, u64, u64, u64)> = set
        .files()
        .iter()
        .map(|file| {
            let ChunkDescription::Protected { length, tail, .. } =
                &file.chunks().first().expect("one chunk")
            else {
                panic!("every chunk here is protected");
            };
            let ChunkTail::Described {
                block_index,
                offset,
                ..
            } = tail
            else {
                panic!("a 300-byte tail is described, not inline");
            };
            (file.path().to_owned(), *length, *block_index, *offset)
        })
        .collect();
    placements.sort();
    assert_eq!(
        placements,
        [
            ("w.bin".to_owned(), 500, 0, 0),
            ("x.bin".to_owned(), 300, 0, 500),
            ("y.bin".to_owned(), 300, 1, 0),
            ("z.bin".to_owned(), 300, 1, 300),
        ]
    );

    // A tail block holds the concatenated tails and then zeros, and that padded
    // block is what the encoder saw: encoding the two blocks built here by hand
    // reproduces the recovery block that was written.
    let mut block0 = tree.read("w.bin");
    block0.extend(tree.read("x.bin"));
    block0.resize(1000, 0);
    let mut block1 = tree.read("y.bin");
    block1.extend(tree.read("z.bin"));
    block1.resize(1000, 0);

    let mut encoder = Encoder::new(
        Gf8::new(Gf8::DEFAULT_GENERATOR).expect("GF(2^8)"),
        Geometry {
            block_size: 1000,
            input_blocks: 2,
            recovery_blocks: 1,
            first_recovery: 0,
        },
    )
    .expect("an encoder");
    encoder.add_input_block(0, &block0).expect("block 0");
    encoder.add_input_block(1, &block1).expect("block 1");
    let expected = encoder.finish();

    assert_eq!(set.recovery_blocks().len(), 1);
    assert_block_eq(
        set.recovery_blocks()[0].data(),
        expected[0].data(),
        "the recovery block over the packed tail blocks",
    );

    // Blocks holding chunk tails get no External Data entry, so a set of only
    // tail blocks has no block checksums at all.
    assert!(
        set.block_checksums().is_empty(),
        "no block here is a full block"
    );
    assert!(
        verify_set(&set, tree.path())
            .expect("verification runs")
            .is_complete()
    );
}

// ---------------------------------------------------------------------------
// 5. The block size rule
// ---------------------------------------------------------------------------

#[test]
fn the_suggested_block_size_follows_the_reference_rule() {
    // Every file 40 bytes or smaller: the minimum, and nothing else applies.
    assert_eq!(suggest_block_size([40]), 40);
    assert_eq!(suggest_block_size([]), 40);

    // sqrt(5000) * 10 = 707, clamped by nothing, rounded down to 512.
    assert_eq!(suggest_block_size([5000]), 512);

    // The oracle set: sqrt(9010) * 10 = 949, rounded down to 512, which gives
    // 20 blocks — inside neither adjustment band.
    assert_eq!(suggest_block_size([5000, 10, 4000]), 512);

    // 100 MiB: sqrt = 10240, times 10 is 102400, rounded down to 65536, which
    // gives 1600 blocks — above the halving band, so it stands.
    let mib = 1024 * 1024;
    assert_eq!(suggest_block_size([100 * mib]), 65536);

    // 4 MiB: sqrt = 2048, times 10 is 20480, rounded down to 16384, which gives
    // 256 blocks — inside 129..1000, so the size is halved.
    assert_eq!(suggest_block_size([4 * mib]), 8192);

    // 1 TiB in one file: sqrt * 10 rounds down to 8 MiB, which is 131072 blocks,
    // so the size doubles until the count is 32768 — three doublings, to 32 MiB.
    assert_eq!(suggest_block_size([1u64 << 40]), 1 << 25);

    // Two hundred thousand tiny files: no block size gives 32768 blocks or
    // fewer, so the doubling stops once a block is as large as the largest file
    // rather than running away.
    let many: Vec<u64> = std::iter::repeat_n(100u64, 200_000).collect();
    assert_eq!(suggest_block_size(many.iter().copied()), 128);
}

// ---------------------------------------------------------------------------
// 6. The field boundary
// ---------------------------------------------------------------------------

/// Create a set of exactly `blocks` full blocks and report the field it chose.
fn field_for(label: &str, blocks: u64) -> (CreateReport, TempTree) {
    let tree = TempTree::new(label);
    tree.write("f.bin", &filler(9, (blocks * 64) as usize));
    let report = create_in(
        &tree,
        &["f.bin"],
        &[],
        "set.par3",
        &CreateOptions::default()
            .with_block_size(64)
            .with_recovery(RecoveryAmount::Blocks(1)),
    );
    assert_eq!(report.block_count, blocks, "{label}");
    (report, tree)
}

#[test]
fn one_hundred_and_twenty_eight_blocks_stay_in_gf8_and_one_more_moves_to_gf16() {
    let (small, tree) = field_for("gf8-boundary", 128);
    assert_eq!(small.field.size, 1);
    assert_eq!(small.field.generator, 0x1d);
    let set = Par3Set::from_packets_for(packets_written(&small), small.set_id).expect("a set");
    assert_eq!(set.galois_field().size, 1);
    drop(tree);

    let (large, tree) = field_for("gf16-boundary", 129);
    assert_eq!(large.field.size, 2);
    assert_eq!(large.field.generator, 0x100b);
    let set = Par3Set::from_packets_for(packets_written(&large), large.set_id).expect("a set");
    assert_eq!(set.galois_field().size, 2);
    drop(tree);
}

#[test]
fn an_odd_block_size_is_rounded_up_and_the_report_says_so() {
    let tree = TempTree::new("odd-block-size");
    tree.write("f.bin", &filler(11, 20_000));
    let report = create_in(
        &tree,
        &["f.bin"],
        &[],
        "set.par3",
        &CreateOptions::default()
            .with_block_size(101)
            .with_recovery(RecoveryAmount::Blocks(1)),
    );
    assert_eq!(report.block_size, 102, "an odd block size gains one");
    assert_eq!(report.field.size, 2, "198 blocks need GF(2^16)");

    let set = Par3Set::from_packets_for(packets_written(&report), report.set_id).expect("a set");
    assert_eq!(set.block_size(), 102);
    assert!(
        verify_set(&set, tree.path())
            .expect("verification runs")
            .is_complete()
    );
}

// ---------------------------------------------------------------------------
// 7. Refusals
// ---------------------------------------------------------------------------

#[test]
fn unusable_inputs_and_settings_are_refused() {
    let tree = TempTree::new("refusals");
    tree.write("a.bin", &filler(12, 4096));
    let stem = tree.path().join("set.par3");
    let default = CreateOptions::default().with_block_size(1024);

    let attempt = |files: &[&str], options: &CreateOptions| {
        let files: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
        create(&InputSpec::new(tree.path(), &files), &stem, options)
    };

    assert!(attempt(&[], &default).is_err(), "an empty file list");
    assert!(
        attempt(&["/etc/hosts"], &default).is_err(),
        "an absolute path"
    );
    assert!(
        attempt(&["../a.bin"], &default).is_err(),
        "a \"..\" component"
    );
    assert!(
        attempt(&["a.bin", "a.bin"], &default).is_err(),
        "a duplicate name"
    );
    assert!(
        attempt(&["missing.bin"], &default).is_err(),
        "a missing file"
    );
    assert!(
        attempt(&["a.bin"], &CreateOptions::default().with_block_size(0)).is_err(),
        "a block size of zero"
    );
    assert!(
        attempt(
            &["a.bin"],
            &CreateOptions::default()
                .with_block_size(1024)
                .with_recovery(RecoveryAmount::Blocks(70_000))
        )
        .is_err(),
        "recovery blocks past the 65536 ceiling"
    );
    assert!(
        attempt(
            &["a.bin"],
            &CreateOptions::default().with_limits(CreateLimits::default().with_max_files(0))
        )
        .is_err(),
        "more files than the limits allow"
    );

    // The first success writes the set; a second refuses to replace it, and
    // leaves what is there alone.
    let first = attempt(&["a.bin"], &default).expect("the first create succeeds");
    let before = tree.read("set.par3");
    assert!(attempt(&["a.bin"], &default).is_err(), "an existing index");
    assert_eq!(tree.read("set.par3"), before, "the refusal wrote nothing");
    assert!(
        attempt(&["a.bin"], &default.clone().with_overwrite(true)).is_ok(),
        "overwrite replaces it"
    );
    assert_eq!(first.files_written.len(), 1);
}

// ---------------------------------------------------------------------------
// 8. Directory trees
// ---------------------------------------------------------------------------

#[test]
fn a_directory_tree_is_described_by_directory_packets_and_reads_back() {
    let tree = TempTree::new("tree");
    tree.write("a/b/c.bin", &filler(20, 2100));
    tree.write("a/d.bin", &filler(21, 900));
    tree.write("e.bin", &filler(22, 1500));
    tree.mkdir("f");

    let report = create_in(
        &tree,
        &["a/b/c.bin", "a/d.bin", "e.bin"],
        &["f"],
        "tree.par3",
        &CreateOptions::default()
            .with_block_size(1000)
            .with_recovery(RecoveryAmount::Blocks(2)),
    );

    let set = Par3Set::from_packets_for(packets_written(&report), report.set_id).expect("a set");

    let directories: BTreeSet<&str> = set
        .directories()
        .iter()
        .map(par3_rs::Par3Directory::path)
        .collect();
    assert_eq!(directories, ["a", "a/b", "f"].into_iter().collect());

    let files: BTreeSet<&str> = set.files().iter().map(par3_rs::Par3File::path).collect();
    assert_eq!(
        files,
        ["a/b/c.bin", "a/d.bin", "e.bin"].into_iter().collect(),
        "the reader resolves the same paths back"
    );

    // The Root packet names three children: the directories `a` and `f`, and
    // the top-level file `e.bin`.
    assert_eq!(set.root().children.len(), 3);
    let top: BTreeSet<&str> = set
        .directories()
        .iter()
        .filter(|directory| !directory.path().contains('/'))
        .map(par3_rs::Par3Directory::path)
        .chain(
            set.files()
                .iter()
                .filter(|file| !file.path().contains('/'))
                .map(par3_rs::Par3File::path),
        )
        .collect();
    assert_eq!(top, ["a", "e.bin", "f"].into_iter().collect());

    assert_eq!(
        packets_of(&tree.read("tree.par3"))
            .iter()
            .filter(|packet| packet.packet_type() == PacketType::Directory)
            .count(),
        3
    );
    assert!(
        verify_set(&set, tree.path())
            .expect("verification runs")
            .is_complete()
    );
}
