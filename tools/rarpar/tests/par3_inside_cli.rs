//! `rarpar par3 inside` over a RARLAB-made RAR5 volume set: insert, verify,
//! in-place repair of a lost and a damaged volume, and byte-exact removal.
//! The fixtures are not committed; each test skips when they are absent.
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const STEM: &str = "generated_matrix_rar5_store_plain";

fn run(root: &Path, args: &[&str], code: i32) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "args={args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Copy the seven-volume fixture into `root/original`, or `None` when absent.
fn originals(root: &Path) -> Option<Vec<PathBuf>> {
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/unrar-rs/tests/fixtures/rar5");
    let directory = root.join("original");
    std::fs::create_dir_all(&directory).unwrap();
    let mut copies = Vec::new();
    for part in 1..=7 {
        let name = format!("{STEM}.part{part}.rar");
        let source = fixtures.join(&name);
        if !source.is_file() {
            eprintln!("skipping: fixture {} is not present", source.display());
            return None;
        }
        std::fs::copy(&source, directory.join(&name)).unwrap();
        copies.push(directory.join(name));
    }
    Some(copies)
}

/// Every run warns on stderr that the feature is experimental, unless `--quiet`.
fn assert_experimental_notice(root: &Path, archive: &str) {
    let stderr = |quiet: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rarpar"));
        command.current_dir(root);
        if quiet {
            command.arg("--quiet");
        }
        let output = command
            .args(["par3", "inside", "verify", archive])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        String::from_utf8(output.stderr).unwrap()
    };
    assert!(stderr(false).contains("par3 inside is EXPERIMENTAL"));
    assert!(!stderr(true).contains("EXPERIMENTAL"));
}

#[test]
fn inside_help_is_marked_experimental() {
    for args in [
        &["par3", "inside", "--help"][..],
        &["par3", "inside", "insert", "--help"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.starts_with("EXPERIMENTAL:"), "{args:?}: {help}");
    }
}

fn name(part: usize) -> String {
    format!("{STEM}.part{part}.rar")
}

#[test]
fn inside_lifecycle_repairs_lost_and_damaged_volumes_and_removes_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let first = sources[0].to_str().unwrap();

    let inserted = run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "-d",
            "protected",
            "-s",
            "4096",
            "-c",
            "56",
            "--layout",
            "service",
        ],
        0,
    );
    assert_eq!(inserted["outputs"].as_array().unwrap().len(), 7);
    assert_eq!(inserted["experimental"], true);
    let protected = root.join("protected");
    let pristine: Vec<Vec<u8>> = (1..=7)
        .map(|part| std::fs::read(protected.join(name(part))).unwrap())
        .collect();
    let entry = protected.join(name(1));
    let entry = entry.to_str().unwrap();
    run(root, &["par3", "inside", "verify", entry], 0);
    assert_experimental_notice(root, entry);

    std::fs::remove_file(protected.join(name(1))).unwrap();
    let damaged = protected.join(name(4));
    let mut bytes = std::fs::read(&damaged).unwrap();
    let middle = bytes.len() / 2;
    for byte in &mut bytes[middle..middle + 64] {
        *byte ^= 0x5a;
    }
    std::fs::write(&damaged, bytes).unwrap();

    let entry = protected.join(name(2));
    let entry = entry.to_str().unwrap();
    let verified = run(root, &["par3", "inside", "verify", entry], 1);
    assert_eq!(verified["repairable"], true);
    let repaired = run(root, &["par3", "inside", "repair", entry], 0);
    assert_eq!(repaired["status"], "repaired");
    for part in 1..=7 {
        assert_eq!(
            std::fs::read(protected.join(name(part))).unwrap(),
            pristine[part - 1],
            "volume {part} after repair"
        );
    }
    run(root, &["par3", "inside", "verify", entry], 0);

    run(
        root,
        &["par3", "inside", "remove", entry, "-d", "stripped"],
        0,
    );
    for (part, source) in sources.iter().enumerate() {
        assert_eq!(
            std::fs::read(root.join("stripped").join(name(part + 1))).unwrap(),
            std::fs::read(source).unwrap(),
            "volume {} after removal",
            part + 1
        );
    }
}

#[test]
fn inside_reports_a_missing_volume_no_independent_set_covers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let first = sources[0].to_str().unwrap();
    run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "-d",
            "protected",
            "-s",
            "4096",
            "-r",
            "10",
            "--placement",
            "independent",
        ],
        0,
    );
    let protected = root.join("protected");
    std::fs::remove_file(protected.join(name(3))).unwrap();
    let entry = protected.join(name(1));
    let entry = entry.to_str().unwrap();
    let verified = run(root, &["par3", "inside", "verify", entry], 1);
    assert_eq!(verified["repairable"], false);
    assert_eq!(
        verified["unprotected_missing_volumes"],
        serde_json::json!([name(3)])
    );
    let repaired = run(root, &["par3", "inside", "repair", entry], 1);
    assert_eq!(
        repaired["unprotected_missing_volumes"],
        serde_json::json!([name(3)])
    );
}

/// One repair over two sets in two directories: a lost volume comes back
/// beside its own set's survivors, and a dry run reports a plan and writes
/// nothing.
#[test]
fn inside_repairs_each_set_in_its_own_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let single = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/unrar-rs/tests/fixtures/rar5/rar5_store.rar");
    if !single.is_file() {
        eprintln!("skipping: fixture {} is not present", single.display());
        return;
    }
    let lone = root.join("original/lone-host.rar");
    std::fs::copy(&single, &lone).unwrap();
    let insert = |archive: &Path, into: &str| {
        run(
            root,
            &[
                "par3",
                "inside",
                "insert",
                archive.to_str().unwrap(),
                "-d",
                into,
                "-s",
                "4096",
                "-c",
                "56",
            ],
            0,
        );
    };
    insert(&lone, "west");
    insert(&sources[0], "east");
    let east = root.join("east");
    let pristine = std::fs::read(east.join(name(1))).unwrap();
    std::fs::remove_file(east.join(name(1))).unwrap();
    let west_entry = root.join("west/lone-host.rar");
    let east_entry = east.join(name(2));
    let args = |dry: bool| {
        let mut args = Vec::new();
        if dry {
            args.push("--dry-run");
        }
        args.extend(["par3", "inside", "repair"]);
        args.push(west_entry.to_str().unwrap());
        args.push(east_entry.to_str().unwrap());
        args
    };
    let planned = run(root, &args(true), 0);
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["dry_run"], true);
    assert!(!east.join(name(1)).exists());
    let repaired = run(root, &args(false), 0);
    assert_eq!(repaired["status"], "repaired");
    assert_eq!(std::fs::read(east.join(name(1))).unwrap(), pristine);
    assert!(!root.join("west").join(name(1)).exists());
}

/// In place, insertion and removal stage beside each volume and leave
/// nothing behind but the volumes, byte-exact after the round trip.
#[test]
fn inside_in_place_round_trip_leaves_only_the_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let pristine: Vec<Vec<u8>> = sources
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    let first = sources[0].to_str().unwrap();
    run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "--in-place",
            "-s",
            "4096",
            "-c",
            "14",
        ],
        0,
    );
    let listing = || {
        let mut names: Vec<_> = std::fs::read_dir(root.join("original"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    };
    let expected: Vec<String> = (1..=7).map(name).collect();
    assert_eq!(listing(), expected);
    assert_ne!(std::fs::read(&sources[0]).unwrap(), pristine[0]);
    run(root, &["par3", "inside", "verify", first], 0);
    run(root, &["par3", "inside", "remove", first, "--in-place"], 0);
    assert_eq!(listing(), expected);
    for (path, bytes) in sources.iter().zip(&pristine) {
        assert_eq!(&std::fs::read(path).unwrap(), bytes);
    }
}

/// A dry-run removal makes the checks a removal would: a damaged host is
/// refused with the same exit code, and an intact set is reported as a plan
/// with nothing written.
#[test]
fn inside_dry_run_removal_checks_like_a_removal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let first = sources[0].to_str().unwrap();
    run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "-d",
            "protected",
            "-s",
            "4096",
            "-c",
            "14",
        ],
        0,
    );
    let entry = root.join("protected").join(name(1));
    let entry = entry.to_str().unwrap();
    let planned = run(
        root,
        &[
            "--dry-run",
            "par3",
            "inside",
            "remove",
            entry,
            "-d",
            "stripped",
        ],
        0,
    );
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["dry_run"], true);
    assert!(!root.join("stripped").exists());

    let damaged = root.join("protected").join(name(3));
    let mut bytes = std::fs::read(&damaged).unwrap();
    bytes[5000] ^= 0x5a;
    std::fs::write(&damaged, bytes).unwrap();
    let code = |dry: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rarpar"));
        command.current_dir(root).args(["--json", "--quiet"]);
        if dry {
            command.arg("--dry-run");
        }
        command
            .args(["par3", "inside", "remove", entry, "-d", "stripped"])
            .output()
            .unwrap()
            .status
            .code()
    };
    let dry = code(true);
    assert_ne!(dry, Some(0));
    assert_eq!(dry, code(false));
    assert!(!root.join("stripped").join(name(3)).exists());
}

/// A dry-run insertion reports its plan before it creates anything: no
/// output directory, and in place no staging or scratch file beside the host.
#[test]
fn inside_dry_run_insertion_creates_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/unrar-rs/fuzz/corpus/rar_extract/rar5_longname.rar");
    let shelf = root.join("shelf");
    std::fs::create_dir(&shelf).unwrap();
    let host = shelf.join("quill-host.rar");
    std::fs::copy(&source, &host).unwrap();
    let host = host.to_str().unwrap();
    let planned = run(
        root,
        &[
            "--dry-run",
            "par3",
            "inside",
            "insert",
            host,
            "-d",
            "fresh/out",
            "-c",
            "2",
        ],
        0,
    );
    assert_eq!(planned["status"], "planned");
    assert!(!root.join("fresh").exists());
    let planned = run(
        root,
        &[
            "--dry-run",
            "par3",
            "inside",
            "insert",
            host,
            "--in-place",
            "-c",
            "2",
        ],
        0,
    );
    assert_eq!(planned["status"], "planned");
    let left: Vec<_> = std::fs::read_dir(&shelf)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(left, ["quill-host.rar"]);
    assert_eq!(
        std::fs::read(shelf.join("quill-host.rar")).unwrap(),
        std::fs::read(&source).unwrap()
    );
}

/// On a case-insensitive filesystem a volume named in other casing than its
/// directory entry still finds every volume of its set. Skips where the
/// filesystem is case-sensitive.
#[test]
fn inside_finds_the_set_from_a_name_in_other_casing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let shouted = root.join("original").join(name(1).to_uppercase());
    if !shouted.is_file() {
        eprintln!("skipping: the filesystem is case-sensitive");
        return;
    }
    let shouted = shouted.to_str().unwrap();
    let inserted = run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            shouted,
            "-d",
            "protected",
            "-s",
            "4096",
            "-c",
            "14",
        ],
        0,
    );
    assert_eq!(inserted["outputs"].as_array().unwrap().len(), sources.len());
    let protected = root.join("protected").join(name(3).to_uppercase());
    let protected = protected.to_str().unwrap();
    run(root, &["par3", "inside", "verify", protected], 0);
    run(
        root,
        &["par3", "inside", "remove", protected, "-d", "stripped"],
        0,
    );
    for (part, source) in sources.iter().enumerate() {
        assert_eq!(
            std::fs::read(root.join("stripped").join(name(part + 1))).unwrap(),
            std::fs::read(source).unwrap(),
            "volume {} after removal",
            part + 1
        );
    }
}
