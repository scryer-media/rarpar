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

/// A directory at a missing volume's name does not stand in for the volume.
#[test]
fn inside_reports_a_missing_volume_masked_by_a_directory() {
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
    std::fs::create_dir(protected.join(name(3))).unwrap();
    let entry = protected.join(name(1));
    let entry = entry.to_str().unwrap();
    let verified = run(root, &["par3", "inside", "verify", entry], 1);
    assert_eq!(verified["repairable"], false);
    assert_eq!(
        verified["unprotected_missing_volumes"],
        serde_json::json!([name(3)])
    );
}

/// A volume renamed to a huge suffix, whose end header says another follows,
/// is reported against a bound the inputs justify instead of having every
/// number up to its suffix enumerated.
#[test]
fn inside_bounds_a_renamed_volume_suffix() {
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
            "--in-place",
            "-s",
            "4096",
            "-c",
            "14",
        ],
        0,
    );
    let directory = root.join("original");
    std::fs::remove_file(directory.join(name(7))).unwrap();
    std::fs::rename(
        directory.join(name(6)),
        directory.join(format!("{STEM}.part{}.rar", u64::MAX)),
    )
    .unwrap();
    let verified = run(root, &["par3", "inside", "verify", first], 1);
    let missing = verified["unprotected_missing_volumes"].as_array().unwrap();
    assert!(!missing.is_empty());
    assert!(missing.len() <= 6 + 7 + 1, "{missing:?}");
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

/// An ordinary RAR5 archive carries no embedded set, so verifying it fails
/// instead of reporting nothing checked as intact.
#[test]
fn inside_verify_without_an_embedded_set_fails() {
    let single = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/unrar-rs/tests/fixtures/rar5/rar5_store.rar");
    if !single.is_file() {
        eprintln!("skipping: fixture {} is not present", single.display());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let plain = temp.path().join("plain-host.rar");
    std::fs::copy(&single, &plain).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(temp.path())
        .args(["--json", "par3", "inside", "verify"])
        .arg(&plain)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(stderr.contains("no PAR3 packets found"), "{stderr}");
    assert!(output.stdout.is_empty());
}

/// Generated RAR5 volumes, so these tests need no fixture.
#[cfg(feature = "sevenz")]
mod generated {
    use std::path::Path;

    use crc_fast::{CrcAlgorithm, Digest};

    use super::run;

    fn push_vint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    /// One RAR5 header block: CRC32, size, `fields` as vints, then `data`.
    fn block(fields: &[u64], data: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        for &field in fields {
            push_vint(&mut inner, field);
        }
        let mut sized = Vec::new();
        push_vint(&mut sized, inner.len() as u64);
        sized.extend_from_slice(&inner);
        let mut digest = Digest::new(CrcAlgorithm::Crc32IsoHdlc);
        digest.update(&sized);
        let mut out = (digest.finalize() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&sized);
        out.extend_from_slice(data);
        out
    }

    /// Volume `index` of `count`: main header, one opaque data block, end header.
    fn volume(index: u64, count: u64, seed: u8) -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
        let main = if index == 0 {
            vec![1, 0, 0x1]
        } else {
            vec![1, 0, 0x3, index]
        };
        out.extend(block(&main, &[]));
        let data: Vec<u8> = (0..20_000u32)
            .map(|value| (value as u8).wrapping_mul(31).wrapping_add(seed))
            .collect();
        out.extend(block(&[2, 0x2, data.len() as u64], &data));
        out.extend(block(&[5, 0, u64::from(index + 1 < count)], &[]));
        out
    }

    /// Write `set.part1.rar` .. `set.part3.rar` into `directory`.
    fn family(directory: &Path, seed: u8) {
        std::fs::create_dir_all(directory).unwrap();
        for index in 0..3 {
            let name = format!("set.part{}.rar", index + 1);
            std::fs::write(directory.join(name), volume(index, 3, seed + index as u8)).unwrap();
        }
    }

    fn insert(root: &Path, source: &str, output: &str, placement: &str) {
        let first = format!("{source}/set.part1.rar");
        run(
            root,
            &[
                "par3",
                "inside",
                "insert",
                &first,
                "-d",
                output,
                "-s",
                "4096",
                "-r",
                "10",
                "--placement",
                placement,
            ],
            0,
        );
    }

    /// A volume missing from one directory is not covered by a set in another
    /// directory that records a volume of the same name.
    #[test]
    fn a_same_named_volume_elsewhere_does_not_cover_a_missing_one() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        family(&root.join("first-source"), 1);
        family(&root.join("second-source"), 101);
        insert(root, "first-source", "first", "spread");
        insert(root, "second-source", "second", "independent");
        std::fs::remove_file(root.join("second/set.part2.rar")).unwrap();
        let verified = run(
            root,
            &[
                "par3",
                "inside",
                "verify",
                "first/set.part1.rar",
                "second/set.part1.rar",
            ],
            1,
        );
        assert_eq!(
            verified["unprotected_missing_volumes"],
            serde_json::json!(["set.part2.rar"])
        );
    }

    /// A family named in one case while the directory keeps another: on a
    /// volume whose names ignore case (Windows, and macOS by default), every
    /// volume is verified and a missing one is reported in the directory's
    /// spelling. On a case-sensitive volume the other spelling is another
    /// file, and stems match exactly.
    #[test]
    fn a_family_named_in_another_case() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        family(&root.join("source"), 23);
        insert(root, "source", "protected", "independent");
        let protected = root.join("protected");
        for part in 1..=3 {
            std::fs::rename(
                protected.join(format!("set.part{part}.rar")),
                protected.join(format!("SET.part{part}.rar")),
            )
            .unwrap();
        }
        let named = "protected/set.part1.rar";
        if root.join(named).is_file() {
            assert!(
                cfg!(any(windows, target_os = "macos")),
                "a volume that ignores case must be a platform whose stems fold"
            );
            let verified = run(root, &["par3", "inside", "verify", named], 0);
            assert_eq!(verified["sets"].as_array().unwrap().len(), 3, "{verified}");
            std::fs::remove_file(protected.join("SET.part2.rar")).unwrap();
            let verified = run(root, &["par3", "inside", "verify", named], 1);
            assert_eq!(verified["sets"].as_array().unwrap().len(), 2, "{verified}");
            assert_eq!(
                verified["unprotected_missing_volumes"],
                serde_json::json!(["SET.part2.rar"])
            );
        } else {
            // A case-sensitive volume has no such file.
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_rarpar"))
                .current_dir(root)
                .args(["--json", "par3", "inside", "verify", named])
                .output()
                .unwrap();
            assert!(!output.status.success());
            let upper = run(
                root,
                &["par3", "inside", "verify", "protected/SET.part1.rar"],
                0,
            );
            assert_eq!(upper["sets"].as_array().unwrap().len(), 3, "{upper}");
        }
    }

    /// Naming several volumes of one family lists and opens it once.
    #[test]
    fn several_volumes_of_one_family_open_each_set_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        family(&root.join("source"), 7);
        insert(root, "source", "protected", "independent");
        let verified = run(
            root,
            &[
                "par3",
                "inside",
                "verify",
                "protected/set.part1.rar",
                "protected/set.part2.rar",
                "protected/set.part3.rar",
            ],
            0,
        );
        assert_eq!(verified["sets"].as_array().unwrap().len(), 3, "{verified}");
    }
}
