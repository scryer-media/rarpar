//! par3-rs against the eight PAR3 sets in the repository's test corpus.
//!
//! Every byte read here was written by the official `par3cmdline`, and by
//! nothing else. The sets live outside the repository, in the signed,
//! content-addressed test corpus described by `docs/test-corpus.md`; the
//! recipe that produced them — one `par3 create` per case, inputs from a
//! deterministic byte stream — is `par3_sets` in
//! `bench/rarpar-bench/internal/testcorpus/par3_sets.go`, and
//! `tests/fixtures/README.md` says what each case pins. Hydrate them with:
//!
//! ```sh
//! cargo run --locked -p xtask -- test-corpus hydrate --profile par3
//! ```
//!
//! Without that the fixtures are absent and every test here skips, which is
//! what a checkout that has not fetched the corpus sees.
//!
//! The four things asked of each set:
//!
//! 1. **Read** it, and agree with the reference about its shape — block size,
//!    block count, field, files, directories, comment, and how many recovery
//!    blocks the volumes carry.
//! 2. **Verify** the reference's own inputs against it, and find them whole.
//! 3. **Create** it again from those inputs and the options the reference was
//!    given, and match every file it wrote byte for byte.
//! 4. **Repair** damage, using the reference's volumes and no other recovery
//!    data, back to the inputs it protected.
//!
//! No PAR3 packet is assembled or edited here (`AGENTS.md`, PAR3 rules). The
//! damage the repair tests need is made in memory, on copies of the inputs.

mod common;

use std::path::{Path, PathBuf};

use common::{TempTree, assert_block_eq};
use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::repair::{RepairOptions, plan_repair, repair_set};
use par3_rs::{FileVerdict, Packet, Par3Error, Par3Set, scan_packets_from_path, verify_set};

/// The Creator text `par3cmdline` writes, which ours says so that a rebuilt
/// set can be compared byte for byte. The Creator packet is the one packet
/// whose content is the client's own to choose.
const REFERENCE_CREATOR: &str =
    "par3cmdline version 0.0.1\n(https://github.com/Parchive/par3cmdline)";

/// One corpus case: what the reference was told, and what it produced.
struct Case {
    /// The case directory under `tests/fixtures`.
    name: &'static str,
    /// The input paths, in the order the recipe lists them.
    inputs: &'static [&'static str],
    /// The block size the reference was given, or `None` where `-s` was absent
    /// and it chose one — which is then a test of [`suggest_block_size`].
    ///
    /// [`suggest_block_size`]: par3_rs::create::suggest_block_size
    block_size: Option<u64>,
    /// The recovery the reference was asked for, `-r` as a percentage or `-c`
    /// as a count.
    recovery: RecoveryAmount,
    /// The `-C` comment, where the recipe passed one.
    comment: Option<&'static str>,
    /// Bytes per block in the set the reference wrote.
    expected_block_size: u64,
    /// Input blocks it stored, after tail packing.
    block_count: u64,
    /// Recovery blocks across all its volumes.
    recovery_count: u64,
    /// 1 for GF(2^8), 2 for GF(2^16).
    field_size: u8,
    /// Every input file and its length, in the set's own path order.
    files: &'static [(&'static str, u64)],
    /// Every input directory, in the set's own order.
    directories: &'static [&'static str],
    /// Every file the reference wrote, the index first and the volumes after.
    written: &'static [&'static str],
    /// The file the repair tests damage: one whose first block is a full one,
    /// so a flipped byte at offset zero costs exactly one input block.
    damage: &'static str,
}

impl Case {
    /// Where this case's fixtures are.
    fn dir(&self) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(self.name)
    }

    /// The bytes of one of the files the reference wrote.
    fn reference_output(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir().join(name)).expect("a fixture the reference wrote")
    }

    /// The bytes of one of the inputs the reference protected.
    fn input(&self, path: &str) -> Vec<u8> {
        let mut file = self.dir().join("in");
        for component in path.split('/') {
            file.push(component);
        }
        std::fs::read(file).expect("a fixture input")
    }

    /// Read the whole set: the index file and every volume beside it.
    fn load(&self) -> Par3Set {
        let mut packets: Vec<Packet> = Vec::new();
        for name in self.written {
            let scanned = scan_packets_from_path(&self.dir().join(name))
                .unwrap_or_else(|error| panic!("{}/{name} scans: {error}", self.name));
            packets.extend(scanned.into_iter().map(|(_, packet)| packet));
        }
        let mut sets = Par3Set::from_packets(packets)
            .unwrap_or_else(|error| panic!("{} builds a set: {error}", self.name));
        assert_eq!(
            sets.len(),
            1,
            "{}: the reference wrote one input set",
            self.name
        );
        sets.pop().expect("the one set")
    }

    /// Lay the reference's inputs out in a scratch directory, under `in/` the
    /// way the reference read them, and hand back the base directory.
    fn lay_out(&self, tree: &TempTree) -> PathBuf {
        for path in self.inputs {
            tree.write(&format!("in/{path}"), &self.input(path));
        }
        tree.path().join("in")
    }

    /// The create options the reference was given, plus its Creator text.
    fn options(&self) -> CreateOptions {
        let mut options = CreateOptions::default()
            .with_recovery(self.recovery)
            .with_creator(REFERENCE_CREATOR);
        if let Some(block_size) = self.block_size {
            options = options.with_block_size(block_size);
        }
        if let Some(comment) = self.comment {
            options = options.with_comment(comment);
        }
        options
    }
}

/// The corpus cases, in the order `par3_sets.go` writes them.
static CASES: &[Case] = &[
    Case {
        name: "gf8_packed",
        inputs: &["big.bin", "sub/mid.bin", "tiny.bin", "odd.bin"],
        block_size: Some(4096),
        recovery: RecoveryAmount::Percent(20),
        comment: Some("corpus gf8_packed"),
        expected_block_size: 4096,
        block_count: 76,
        recovery_count: 16,
        field_size: 1,
        files: &[
            ("big.bin", 300_000),
            ("odd.bin", 4_131),
            ("sub/mid.bin", 5_000),
            ("tiny.bin", 37),
        ],
        directories: &["sub"],
        written: &[
            "set.par3",
            "set.vol00+1.par3",
            "set.vol01+2.par3",
            "set.vol03+4.par3",
            "set.vol07+8.par3",
            "set.vol15+1.par3",
        ],
        damage: "big.bin",
    },
    Case {
        name: "gf16_blocks",
        inputs: &["long.bin", "a.bin", "b.bin"],
        block_size: Some(1024),
        recovery: RecoveryAmount::Percent(10),
        comment: None,
        expected_block_size: 1024,
        block_count: 687,
        recovery_count: 69,
        field_size: 2,
        files: &[("a.bin", 1_000), ("b.bin", 2_000), ("long.bin", 700_000)],
        directories: &[],
        written: &[
            "set.par3",
            "set.vol00+01.par3",
            "set.vol01+02.par3",
            "set.vol03+04.par3",
            "set.vol07+08.par3",
            "set.vol15+16.par3",
            "set.vol31+32.par3",
            "set.vol63+06.par3",
        ],
        damage: "long.bin",
    },
    Case {
        name: "gf16_by_recovery",
        inputs: &["exact.bin"],
        block_size: Some(4096),
        recovery: RecoveryAmount::Blocks(200),
        comment: None,
        expected_block_size: 4096,
        block_count: 100,
        recovery_count: 200,
        field_size: 2,
        files: &[("exact.bin", 409_600)],
        directories: &[],
        written: &[
            "set.par3",
            "set.vol000+01.par3",
            "set.vol001+02.par3",
            "set.vol003+04.par3",
            "set.vol007+08.par3",
            "set.vol015+16.par3",
            "set.vol031+32.par3",
            "set.vol063+64.par3",
            "set.vol127+73.par3",
        ],
        damage: "exact.bin",
    },
    Case {
        name: "index_only",
        inputs: &["one.bin", "two.bin", "three.bin"],
        block_size: Some(4096),
        recovery: RecoveryAmount::Blocks(0),
        comment: None,
        expected_block_size: 4096,
        block_count: 8,
        recovery_count: 0,
        field_size: 1,
        files: &[("one.bin", 10_000), ("three.bin", 300), ("two.bin", 20_000)],
        directories: &[],
        written: &["set.par3"],
        damage: "one.bin",
    },
    Case {
        name: "tree",
        inputs: &[
            "top.bin",
            "a/b/c/deep.bin",
            "a/twin.bin",
            "a/b/twin.bin",
            "a/empty.bin",
        ],
        block_size: Some(4096),
        recovery: RecoveryAmount::Percent(10),
        comment: None,
        expected_block_size: 4096,
        block_count: 6,
        recovery_count: 1,
        field_size: 1,
        files: &[
            ("a/b/c/deep.bin", 9_000),
            ("a/b/twin.bin", 4_200),
            ("a/empty.bin", 0),
            ("a/twin.bin", 4_200),
            ("top.bin", 5_000),
        ],
        directories: &["a", "a/b", "a/b/c"],
        written: &["set.par3", "set.vol0+1.par3"],
        damage: "top.bin",
    },
    Case {
        name: "tiny_inline",
        inputs: &["t05.bin", "t39.bin", "t40.bin", "t41.bin", "t100.bin"],
        block_size: None,
        recovery: RecoveryAmount::Percent(50),
        comment: None,
        expected_block_size: 64,
        block_count: 3,
        recovery_count: 2,
        field_size: 1,
        files: &[
            ("t05.bin", 5),
            ("t100.bin", 100),
            ("t39.bin", 39),
            ("t40.bin", 40),
            ("t41.bin", 41),
        ],
        directories: &[],
        written: &["set.par3", "set.vol0+1.par3", "set.vol1+1.par3"],
        damage: "t100.bin",
    },
    Case {
        name: "auto_block",
        inputs: &["clip.bin", "meta.bin", "note.bin"],
        block_size: None,
        recovery: RecoveryAmount::Percent(15),
        comment: None,
        expected_block_size: 4096,
        block_count: 42,
        recovery_count: 7,
        field_size: 1,
        files: &[
            ("clip.bin", 150_000),
            ("meta.bin", 20_000),
            ("note.bin", 999),
        ],
        directories: &[],
        written: &[
            "set.par3",
            "set.vol0+1.par3",
            "set.vol1+2.par3",
            "set.vol3+4.par3",
        ],
        damage: "clip.bin",
    },
    Case {
        name: "large_stream",
        inputs: &["stream.bin"],
        block_size: Some(65_536),
        recovery: RecoveryAmount::Percent(5),
        comment: None,
        expected_block_size: 65_536,
        block_count: 257,
        recovery_count: 13,
        field_size: 2,
        files: &[("stream.bin", 16_789_561)],
        directories: &[],
        written: &[
            "set.par3",
            "set.vol0+1.par3",
            "set.vol1+2.par3",
            "set.vol3+4.par3",
            "set.vol7+6.par3",
        ],
        damage: "stream.bin",
    },
];

/// Whether the corpus has been hydrated, saying so once if it has not.
///
/// A checkout that has not fetched the corpus has none of these files, and the
/// tests that read them skip rather than fail.
fn hydrated() -> bool {
    let missing: Vec<&str> = CASES
        .iter()
        .filter(|case| !case.dir().join("set.par3").is_file())
        .map(|case| case.name)
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert_eq!(
        missing.len(),
        CASES.len(),
        "a partly hydrated corpus: {} of {} cases are absent ({}). \
         Re-run `cargo run --locked -p xtask -- test-corpus hydrate --profile par3`",
        missing.len(),
        CASES.len(),
        missing.join(", ")
    );
    eprintln!("skipping test: par3 corpus fixtures not present");
    false
}

/// Every file in a set, checked against the bytes the reference protected.
fn assert_inputs_restored(case: &Case, base: &Path) {
    for path in case.inputs {
        let mut file = PathBuf::from(base);
        for component in path.split('/') {
            file.push(component);
        }
        let actual = std::fs::read(&file)
            .unwrap_or_else(|error| panic!("{}/{path} is readable: {error}", case.name));
        assert_block_eq(&actual, &case.input(path), &format!("{}/{path}", case.name));
    }
}

#[test]
fn every_set_is_read_the_way_the_reference_wrote_it() {
    if !hydrated() {
        return;
    }
    for case in CASES {
        let set = case.load();
        let name = case.name;

        assert_eq!(
            set.block_size(),
            case.expected_block_size,
            "{name}: block size"
        );
        assert_eq!(set.block_count(), case.block_count, "{name}: input blocks");
        assert_eq!(
            set.galois_field().size,
            case.field_size,
            "{name}: Galois field size"
        );

        let files: Vec<(&str, u64)> = set
            .files()
            .iter()
            .map(|file| (file.path(), file.size()))
            .collect();
        assert_eq!(files, case.files, "{name}: input files");

        let directories: Vec<&str> = set
            .directories()
            .iter()
            .map(par3_rs::Par3Directory::path)
            .collect();
        assert_eq!(directories, case.directories, "{name}: input directories");

        assert_eq!(
            set.recovery_blocks().len() as u64,
            case.recovery_count,
            "{name}: recovery blocks across every volume"
        );
        assert_eq!(
            set.conflicting_recovery_packet_count(),
            0,
            "{name}: the reference's volumes agree with each other"
        );

        let comments: Vec<&str> = case.comment.into_iter().collect();
        assert_eq!(set.comments(), comments, "{name}: comment packets");
        assert!(
            set.creator_texts()
                .iter()
                .any(|text| text == REFERENCE_CREATOR),
            "{name}: the reference's Creator text, but found {:?}",
            set.creator_texts()
        );
    }
}

#[test]
fn every_set_verifies_the_inputs_the_reference_protected() {
    if !hydrated() {
        return;
    }
    for case in CASES {
        let set = case.load();
        let tree = TempTree::new(&format!("corpus-verify-{}", case.name));
        let base = case.lay_out(&tree);

        let report = verify_set(&set, &base)
            .unwrap_or_else(|error| panic!("{} verifies: {error}", case.name));
        assert!(
            report.is_complete(),
            "{}: {:?}",
            case.name,
            report
                .files()
                .iter()
                .filter(|file| !file.verdict().is_complete())
                .map(|file| (file.path(), file.verdict()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.complete_count(),
            case.files.len(),
            "{}: files checked",
            case.name
        );
        assert_eq!(
            report.input_set_id(),
            set.input_set_id(),
            "{}: the report names the set it checked",
            case.name
        );
    }
}

#[test]
fn every_set_is_created_again_byte_for_byte() {
    if !hydrated() {
        return;
    }
    for case in CASES {
        let tree = TempTree::new(&format!("corpus-create-{}", case.name));
        let base = case.lay_out(&tree);
        let files: Vec<PathBuf> = case.inputs.iter().map(PathBuf::from).collect();

        let report = create(
            &InputSpec::new(&base, &files),
            &tree.path().join("set.par3"),
            &case.options(),
        )
        .unwrap_or_else(|error| panic!("{} is created: {error}", case.name));

        let written: Vec<String> = report
            .files_written
            .iter()
            .map(|path| {
                path.file_name()
                    .expect("a file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            written, case.written,
            "{}: the file names the reference chose",
            case.name
        );
        assert_eq!(
            report.block_size, case.expected_block_size,
            "{}: block size",
            case.name
        );
        assert_eq!(
            report.block_count, case.block_count,
            "{}: input blocks",
            case.name
        );
        assert_eq!(
            report.recovery_count, case.recovery_count,
            "{}: recovery blocks",
            case.name
        );
        assert_eq!(
            report.field.size, case.field_size,
            "{}: Galois field size",
            case.name
        );
        assert_eq!(
            report.set_id,
            case.load().input_set_id(),
            "{}: our InputSetID derivation reproduces the reference's",
            case.name
        );

        for name in case.written {
            assert_block_eq(
                &tree.read(name),
                &case.reference_output(name),
                &format!("{}/{name}", case.name),
            );
        }
    }
}

#[test]
fn a_damaged_block_is_repaired_from_the_reference_volumes() {
    if !hydrated() {
        return;
    }
    for case in CASES.iter().filter(|case| case.recovery_count > 0) {
        let set = case.load();
        let tree = TempTree::new(&format!("corpus-repair-{}", case.name));
        let base = case.lay_out(&tree);

        // One byte of the first block of a file whose first block is full: the
        // damage is made here, on our copy, never in the fixture.
        let mut damaged = case.input(case.damage);
        damaged[0] ^= 0xff;
        tree.write(&format!("in/{}", case.damage), &damaged);

        let plan = plan_repair(&set, &base, &Default::default())
            .unwrap_or_else(|error| panic!("{} plans a repair: {error}", case.name));
        assert!(plan.needs_repair(), "{}: the damage is seen", case.name);
        assert!(
            plan.is_possible(),
            "{}: {} recovery blocks for {} lost",
            case.name,
            plan.available_recovery(),
            plan.lost_blocks().len()
        );
        assert_eq!(
            plan.available_recovery(),
            case.recovery_count,
            "{}: every volume's recovery blocks are on hand",
            case.name
        );
        assert_eq!(
            plan.files_to_rewrite(),
            [case.damage],
            "{}: only the damaged file is rewritten",
            case.name
        );
        assert_eq!(
            plan.recovery_to_use().len(),
            plan.lost_blocks().len(),
            "{}: one recovery block per lost block",
            case.name
        );

        let report = repair_set(&set, &base, &RepairOptions::default())
            .unwrap_or_else(|error| panic!("{} repairs: {error}", case.name));
        assert!(report.is_complete(), "{}: complete after repair", case.name);
        assert_eq!(report.repaired().len(), 1, "{}: files written", case.name);
        assert!(
            report.repaired()[0].verified(),
            "{}: the rebuilt bytes match the File packet",
            case.name
        );
        assert_inputs_restored(case, &base);
    }
}

#[test]
fn a_missing_file_is_rebuilt_from_the_reference_volumes() {
    if !hydrated() {
        return;
    }
    // Four files with tails of every kind, sixteen recovery blocks: enough to
    // lose a whole file, its own blocks and its share of a packed tail block.
    let case = CASES
        .iter()
        .find(|case| case.name == "gf8_packed")
        .expect("the packed-tail case");

    let set = case.load();
    let tree = TempTree::new("corpus-missing");
    let base = case.lay_out(&tree);
    std::fs::remove_file(base.join("sub").join("mid.bin")).expect("the file is removed");

    let report = verify_set(&set, &base).expect("the set verifies");
    assert_eq!(report.missing_count(), 1, "one file is gone");
    let gone = report
        .files()
        .iter()
        .find(|file| file.verdict().is_missing())
        .expect("a missing file");
    assert_eq!(gone.path(), "sub/mid.bin", "the file that was removed");

    let report = repair_set(&set, &base, &RepairOptions::default()).expect("the set is repaired");
    assert!(report.is_complete(), "complete after repair");
    assert_eq!(
        report
            .repaired()
            .iter()
            .map(|file| file.path())
            .collect::<Vec<_>>(),
        ["sub/mid.bin"]
    );
    assert!(
        report.repaired()[0].backup().is_none(),
        "nothing was there to keep"
    );
    assert_inputs_restored(case, &base);
}

#[test]
fn an_index_only_set_cannot_repair_and_writes_nothing() {
    if !hydrated() {
        return;
    }
    let case = CASES
        .iter()
        .find(|case| case.name == "index_only")
        .expect("the index-only case");

    let set = case.load();
    let tree = TempTree::new("corpus-index-only");
    let base = case.lay_out(&tree);
    assert_eq!(set.recovery_blocks().len(), 0, "an index file alone");
    assert!(set.matrix_packets().is_empty(), "and no Matrix packet");

    let mut damaged = case.input(case.damage);
    damaged[0] ^= 0xff;
    tree.write(&format!("in/{}", case.damage), &damaged);

    let plan = plan_repair(&set, &base, &Default::default()).expect("a repair is planned");
    assert!(plan.needs_repair(), "the damage is seen");
    assert!(
        !plan.is_possible(),
        "but there is nothing to repair it with"
    );
    assert_eq!(plan.available_recovery(), 0);
    assert_eq!(
        plan.missing_recovery_blocks(),
        plan.lost_blocks().len() as u64
    );
    assert!(plan.recovery_to_use().is_empty());

    let error = repair_set(&set, &base, &RepairOptions::default())
        .expect_err("a repair without recovery data is refused");
    assert!(
        matches!(error, Par3Error::InsufficientRecovery { available: 0, .. }),
        "{error:?}"
    );

    // The refusal left the directory as it was: the damaged file still holds
    // the damaged bytes, and nothing was written beside it.
    assert_eq!(tree.read(&format!("in/{}", case.damage)), damaged);
    let report = verify_set(&set, &base).expect("the set verifies");
    assert_eq!(report.damaged_count(), 1);
    assert!(matches!(
        report
            .files()
            .iter()
            .find(|file| file.path() == case.damage)
            .expect("the damaged file")
            .verdict(),
        FileVerdict::Damaged { .. }
    ));
    let mut entries: Vec<String> = std::fs::read_dir(&base)
        .expect("the base is readable")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    entries.sort();
    assert_eq!(entries, ["one.bin", "three.bin", "two.bin"]);
}
