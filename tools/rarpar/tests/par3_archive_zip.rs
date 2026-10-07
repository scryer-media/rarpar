//! `rarpar par3 archive --format zip`: a ZIP archive protected by PAR3 in the
//! same pass.

#![cfg(feature = "sevenz")]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn rarpar(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

/// `rarpar --json [global] par3 archive --format zip --base-path in [args]`.
#[track_caller]
fn archive(root: &Path, global: &[&str], args: &[&str]) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(global);
    full.extend(["par3", "archive", "--format", "zip", "--base-path", "in"]);
    full.extend_from_slice(args);
    let output = rarpar(root, &full);
    assert_eq!(
        output.status.code(),
        Some(0),
        "args={full:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn bytes(size: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761) | 1;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// Invented inputs: noise that does not compress, text that does, an empty
/// file, a nested file, an empty directory and a non-ASCII name.
fn fixture(noise: usize) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in");
    std::fs::create_dir_all(input.join("cellar/vault")).unwrap();
    std::fs::create_dir_all(input.join("attic")).unwrap();
    std::fs::write(input.join("static.bin"), bytes(noise, 3)).unwrap();
    std::fs::write(input.join("ledger.txt"), b"quartz ferry ".repeat(4000)).unwrap();
    std::fs::write(input.join("blank.dat"), b"").unwrap();
    std::fs::write(input.join("cellar/vault/tally.raw"), bytes(4321, 9)).unwrap();
    std::fs::write(input.join("cellar/f\u{f6}rd \u{2603}.txt"), "h\u{e9}llo\n").unwrap();
    dir
}

const MEMBERS: [&str; 5] = ["static.bin", "ledger.txt", "blank.dat", "cellar", "attic"];

fn with_args<'a>(head: &[&'a str], tail: &[&'a str]) -> Vec<&'a str> {
    head.iter().chain(tail).copied().collect()
}

/// Read the archive with the zip crate and compare every member with its
/// source, and every source with its member.
#[track_caller]
fn assert_extracts(root: &Path, archive: &str) {
    let file = std::fs::File::open(root.join(archive)).unwrap();
    let mut reader = zip::ZipArchive::new(file).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..reader.len() {
        let mut entry = reader.by_index(index).unwrap();
        let name = entry.name().to_owned();
        let source = root.join("in").join(name.trim_end_matches('/'));
        if entry.is_dir() {
            assert!(source.is_dir(), "{name}");
        } else {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            assert!(std::fs::read(&source).unwrap() == data, "{name}");
        }
        seen.insert(name.trim_end_matches('/').to_owned());
    }
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let source = root.join("in").join(&relative);
        if !relative.as_os_str().is_empty() {
            let name = relative.to_str().unwrap().replace('\\', "/");
            assert!(seen.contains(&name), "{name} missing");
        }
        if source.is_dir() {
            for entry in std::fs::read_dir(&source).unwrap() {
                pending.push(relative.join(entry.unwrap().file_name()));
            }
        }
    }
}

fn damage(path: &Path, offset: usize, length: usize) {
    let mut data = std::fs::read(path).unwrap();
    for byte in &mut data[offset..offset + length] {
        *byte = !*byte;
    }
    std::fs::write(path, data).unwrap();
}

/// A copy of rarpar named `par3`, so that it takes par3cmdline's arguments.
fn par3_facade(root: &Path) -> PathBuf {
    let par3 = root.join(format!("par3{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(env!("CARGO_BIN_EXE_rarpar"), &par3).unwrap();
    par3
}

#[track_caller]
fn run_ok(command: &mut Command) -> String {
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[test]
fn a_sibling_set_repairs_the_zip_it_was_written_with() {
    let dir = fixture(200_000);
    let root = dir.path();
    let report = archive(
        root,
        &[],
        &with_args(
            &["out/set.zip"],
            &with_args(&MEMBERS, &["-s", "4096", "-c", "8"]),
        ),
    );
    assert_eq!(report["format"], "zip");
    assert_eq!(report["mode"], "sibling");
    assert_eq!(report["members"], 8);
    assert_eq!(report["recovery_blocks"], 8);
    assert_extracts(root, "out/set.zip");
    let archive = root.join("out/set.zip");
    let original = std::fs::read(&archive).unwrap();
    assert_eq!(report["protected_bytes"], original.len() as u64);
    // The first local header, a run in the middle, and the end records.
    damage(&archive, 0, 30);
    damage(&archive, original.len() / 2, 9000);
    damage(&archive, original.len() - 20, 20);
    run_ok(
        Command::new(env!("CARGO_BIN_EXE_rarpar"))
            .current_dir(root.join("out"))
            .args(["--quiet", "par3", "repair", "--no-backup", "set.par3"]),
    );
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}

/// The set inside follows par3cmdline's ZIP layout: the archive, the packets,
/// then a copy of the end records, so the file is still a ZIP.
#[test]
fn an_inside_set_keeps_the_zip_readable_and_repairs_it() {
    let dir = fixture(150_000);
    let root = dir.path();
    let report = archive(
        root,
        &[],
        &with_args(
            &["out/inner.zip"],
            &with_args(&MEMBERS, &["--inside", "-r", "10"]),
        ),
    );
    assert_eq!(report["mode"], "inside");
    assert_eq!(report["outputs"].as_array().unwrap().len(), 1);
    let archive = root.join("out/inner.zip");
    let original = std::fs::read(&archive).unwrap();
    let protected = report["protected_bytes"].as_u64().unwrap() as usize;
    assert!(protected < original.len());
    // The file ends with the archive's own end records again.
    assert_eq!(
        original[original.len() - 22..],
        original[protected - 22..protected]
    );
    assert_extracts(root, "out/inner.zip");

    let par3 = par3_facade(root);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("out"))
            .args(["vs", "inner.zip"]),
    );
    assert!(stdout.contains("protected data is complete"), "{stdout}");
    // A local header, the central directory, and the copy of the end records
    // after the packets: all protected.
    damage(&archive, 10, 3000);
    damage(&archive, protected - 60, 30);
    damage(&archive, original.len() - 12, 12);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("out"))
            .args(["rs", "inner.zip"]),
    );
    assert!(stdout.contains("protected data was repaired"), "{stdout}");
    assert_eq!(std::fs::read(&archive).unwrap(), original);
    assert_extracts(root, "out/inner.zip");
}

/// One large stored file, past the in-memory head: the streaming lanes write
/// the same archive and set as the exact pass, in both layouts.
#[test]
fn the_streaming_lanes_write_the_same_zip_set_as_an_exact_pass() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("in")).unwrap();
    std::fs::write(root.join("in/reel.bin"), bytes(5_000_000, 21)).unwrap();
    for mode in [
        &["-s", "65536", "-r", "4"][..],
        &["--inside"][..],
        &["--inside", "-r", "3"][..],
    ] {
        for level in ["0", "6"] {
            for (stem, memory) in [("exact", "256"), ("lanes", "4")] {
                let name = format!("{stem}/one.zip");
                let report = archive(
                    root,
                    &["--par3-memory-mib", memory],
                    &with_args(&[&name, "reel.bin", "--level", level], mode),
                );
                assert_eq!(report["read_back"], false, "{mode:?} {memory}");
            }
            let names = |stem: &str| {
                let mut names: Vec<_> = std::fs::read_dir(root.join(stem))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect();
                names.sort();
                names
            };
            assert_eq!(names("exact"), names("lanes"), "{mode:?}");
            for name in names("exact") {
                assert!(
                    std::fs::read(root.join("exact").join(&name)).unwrap()
                        == std::fs::read(root.join("lanes").join(&name)).unwrap(),
                    "{mode:?} level {level}: {name:?} differs"
                );
            }
            assert_extracts(root, "lanes/one.zip");
            std::fs::remove_dir_all(root.join("exact")).unwrap();
            std::fs::remove_dir_all(root.join("lanes")).unwrap();
        }
    }
}

/// `in/crowd`: 66 folders of 1000 tiny files, 66,067 members in all.
fn crowd() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let crowd = dir.path().join("in/crowd");
    for group in 0..66 {
        let folder = crowd.join(format!("g{group:02}"));
        std::fs::create_dir_all(&folder).unwrap();
        for item in 0..1000 {
            std::fs::write(
                folder.join(format!("{item:03}.txt")),
                format!("{group}:{item}\n"),
            )
            .unwrap();
        }
    }
    dir
}

/// More entries than a plain end record can count: the zip crate adds the
/// ZIP64 end records, and the set inside copies all 98 bytes of them.
#[test]
fn many_small_files_take_zip64_end_records_and_repair() {
    let dir = crowd();
    let root = dir.path();
    let report = archive(
        root,
        &["--max-files", "70000"],
        &["out/crowd.zip", "crowd", "--inside", "-r", "5"],
    );
    assert_eq!(report["members"], 66_067);
    let archive = root.join("out/crowd.zip");
    let original = std::fs::read(&archive).unwrap();
    let protected = report["protected_bytes"].as_u64().unwrap() as usize;
    // ZIP64 end of central directory record, locator, then the plain record.
    let footer = &original[protected - 98..protected];
    assert_eq!(footer[..4], [0x50, 0x4b, 0x06, 0x06]);
    assert_eq!(original[original.len() - 98..], *footer);
    let reader = zip::ZipArchive::new(std::fs::File::open(&archive).unwrap()).unwrap();
    assert_eq!(reader.len(), 66_067);
    drop(reader);

    damage(&archive, protected / 3, 5000);
    damage(&archive, original.len() - 50, 50);
    let par3 = par3_facade(root);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("out"))
            .args(["rs", "crowd.zip"]),
    );
    assert!(stdout.contains("protected data was repaired"), "{stdout}");
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}

/// A member over 4 GiB gets ZIP64 sizes and the archive ZIP64 end records.
/// Writes and protects 4.1 GiB, so it runs on request only.
#[test]
#[ignore = "writes a 4.1 GiB archive"]
fn a_member_over_four_gib_takes_zip64() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("in")).unwrap();
    let size = (4u64 << 30) + 123_457;
    let source = std::fs::File::create(root.join("in/vast.bin")).unwrap();
    source.set_len(size).unwrap();
    drop(source);
    std::fs::write(root.join("in/after.txt"), b"tail entry\n").unwrap();
    let report = archive(
        root,
        &[],
        &[
            "out/vast.zip",
            "vast.bin",
            "after.txt",
            "--level",
            "0",
            "--inside",
        ],
    );
    let archive = root.join("out/vast.zip");
    let protected = report["protected_bytes"].as_u64().unwrap();
    assert!(protected > size);
    let mut reader = zip::ZipArchive::new(std::fs::File::open(&archive).unwrap()).unwrap();
    assert_eq!(reader.by_name("vast.bin").unwrap().size(), size);
    let mut tail = String::new();
    reader
        .by_name("after.txt")
        .unwrap()
        .read_to_string(&mut tail)
        .unwrap();
    assert_eq!(tail, "tail entry\n");
    drop(reader);
    let par3 = par3_facade(root);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("out"))
            .args(["vs", "vast.zip"]),
    );
    assert!(stdout.contains("protected data is complete"), "{stdout}");
}

#[test]
fn seven_zip_switches_are_refused_for_a_zip() {
    let dir = fixture(1000);
    let root = dir.path();
    for bad in [&["--filter", "x86"][..], &["--no-solid"][..]] {
        let mut args = vec![
            "par3",
            "archive",
            "--format",
            "zip",
            "--base-path",
            "in",
            "x.zip",
        ];
        args.extend(MEMBERS);
        args.extend(bad);
        let output = rarpar(root, &args);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(!root.join("x.zip").exists());
    }
}

/// The sets match par3cmdline's `c` and `i` over the finished ZIP, byte for
/// byte, once both write the same Creator text; and each tool verifies and
/// repairs what the other wrote.
#[test]
#[ignore = "needs a par3cmdline binary in PAR3_REFERENCE_BIN"]
fn zip_sets_match_par3cmdline_both_ways() {
    let reference = PathBuf::from(std::env::var_os("PAR3_REFERENCE_BIN").unwrap());
    let creator = "par3cmdline version 0.0.1\n(https://github.com/Parchive/par3cmdline)";
    let dir = fixture(700_000);
    let root = dir.path();
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["-s", "4096", "-c", "3"],
            &["c", "-s4096", "-c3", "set.par3", "set.zip"],
        ),
        (
            &["-s", "2048", "-r", "50"],
            &["c", "-s2048", "-r50", "set.par3", "set.zip"],
        ),
        (&["--inside"], &["i", "set.zip"]),
        (&["--inside", "-r", "5"], &["i", "-r5", "set.zip"]),
        (&["--inside", "-r", "40"], &["i", "-r40", "set.zip"]),
        (&["--inside", "--level", "0"], &["i", "set.zip"]),
    ];
    for memory in ["256", "4"] {
        for (ours, theirs) in cases {
            let _ = std::fs::remove_dir_all(root.join("ours"));
            let _ = std::fs::remove_dir_all(root.join("theirs"));
            std::fs::create_dir_all(root.join("theirs")).unwrap();
            let mut args = vec!["--json", "--par3-memory-mib", memory, "par3", "archive"];
            args.extend(["--format", "zip", "--base-path", "in", "ours/set.zip"]);
            args.extend(MEMBERS);
            args.extend(*ours);
            let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
                .current_dir(root)
                .env("RARPAR_PAR3_CREATOR_TEXT", creator)
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(0), "{ours:?}");
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let protected = report["protected_bytes"].as_u64().unwrap() as usize;
            let archive = std::fs::read(root.join("ours/set.zip")).unwrap();
            std::fs::write(root.join("theirs/set.zip"), &archive[..protected]).unwrap();
            let status = Command::new(&reference)
                .current_dir(root.join("theirs"))
                .args(*theirs)
                .output()
                .unwrap()
                .status;
            assert!(status.success(), "{theirs:?}");
            let names = |stem: &str| {
                let mut names: Vec<_> = std::fs::read_dir(root.join(stem))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect();
                names.sort();
                names
            };
            assert_eq!(names("theirs"), names("ours"), "{ours:?} {memory}");
            for name in names("theirs") {
                assert!(
                    std::fs::read(root.join("theirs").join(&name)).unwrap()
                        == std::fs::read(root.join("ours").join(&name)).unwrap(),
                    "{ours:?} {memory}: {name:?} differs"
                );
            }
        }
    }

    // Ours, verified and repaired by par3cmdline.
    let _ = std::fs::remove_dir_all(root.join("ours"));
    archive(
        root,
        &[],
        &with_args(
            &["ours/set.zip"],
            &with_args(&MEMBERS, &["--inside", "-r", "10"]),
        ),
    );
    let path = root.join("ours/set.zip");
    let original = std::fs::read(&path).unwrap();
    let stdout = run_ok(
        Command::new(&reference)
            .current_dir(root.join("ours"))
            .args(["vs", "set.zip"]),
    );
    assert!(stdout.contains("protected data is complete"), "{stdout}");
    damage(&path, 500, 4000);
    damage(&path, original.len() - 10, 10);
    run_ok(
        Command::new(&reference)
            .current_dir(root.join("ours"))
            .args(["rs", "set.zip"]),
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);

    // par3cmdline's, verified and repaired by rarpar.
    let _ = std::fs::remove_dir_all(root.join("theirs"));
    std::fs::create_dir_all(root.join("theirs")).unwrap();
    archive(
        root,
        &[],
        &with_args(&["plain/set.zip"], &with_args(&MEMBERS, &["-c", "1"])),
    );
    std::fs::copy(root.join("plain/set.zip"), root.join("theirs/set.zip")).unwrap();
    run_ok(
        Command::new(&reference)
            .current_dir(root.join("theirs"))
            .args(["i", "-r10", "set.zip"]),
    );
    let path = root.join("theirs/set.zip");
    let original = std::fs::read(&path).unwrap();
    let par3 = par3_facade(root);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("theirs"))
            .args(["vs", "set.zip"]),
    );
    assert!(stdout.contains("protected data is complete"), "{stdout}");
    damage(&path, 500, 4000);
    damage(&path, original.len() - 10, 10);
    let stdout = run_ok(
        Command::new(&par3)
            .current_dir(root.join("theirs"))
            .args(["rs", "set.zip"]),
    );
    assert!(stdout.contains("protected data was repaired"), "{stdout}");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_extracts(root, "theirs/set.zip");

    // ZIP64 end records: a 98-byte footer, copied whole.
    let dir = crowd();
    let root = dir.path();
    std::fs::create_dir_all(root.join("theirs")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .env("RARPAR_PAR3_CREATOR_TEXT", creator)
        .args(["--json", "--max-files", "70000", "par3", "archive"])
        .args([
            "--format",
            "zip",
            "--base-path",
            "in",
            "ours/crowd.zip",
            "crowd",
        ])
        .args(["--inside", "-r", "5"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let protected = report["protected_bytes"].as_u64().unwrap() as usize;
    let ours = std::fs::read(root.join("ours/crowd.zip")).unwrap();
    std::fs::write(root.join("theirs/crowd.zip"), &ours[..protected]).unwrap();
    run_ok(
        Command::new(&reference)
            .current_dir(root.join("theirs"))
            .args(["i", "-r5", "crowd.zip"]),
    );
    assert!(std::fs::read(root.join("theirs/crowd.zip")).unwrap() == ours);
}

/// The zip crate keeps only a mode's permission bits; setuid, setgid and
/// sticky still reach the central directory, as Info-ZIP records them.
#[cfg(unix)]
#[test]
fn special_permission_bits_survive_in_the_zip() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let input = root.join("in");
    std::fs::create_dir_all(input.join("shelf")).unwrap();
    std::fs::write(input.join("lever.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::write(input.join("plain.txt"), b"pebble\n").unwrap();
    std::fs::set_permissions(
        input.join("lever.sh"),
        std::fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    std::fs::set_permissions(input.join("shelf"), std::fs::Permissions::from_mode(0o1777)).unwrap();
    archive(
        root,
        &[],
        &["out/bits.zip", "lever.sh", "plain.txt", "shelf"],
    );
    let file = std::fs::File::open(root.join("out/bits.zip")).unwrap();
    let mut reader = zip::ZipArchive::new(file).unwrap();
    let mut modes = std::collections::BTreeMap::new();
    for index in 0..reader.len() {
        let entry = reader.by_index(index).unwrap();
        modes.insert(
            entry.name().trim_end_matches('/').to_owned(),
            entry.unix_mode().unwrap() & 0o7777,
        );
    }
    assert_eq!(modes["lever.sh"], 0o4755, "{modes:?}");
    assert_eq!(modes["shelf"], 0o1777, "{modes:?}");
    assert_eq!(modes["plain.txt"] & 0o7000, 0, "{modes:?}");
}

/// DOS times are local times: each member's hour follows the zone's offset
/// at its own mtime, so a winter and a summer file differ by daylight saving.
#[cfg(unix)]
#[test]
fn zip_times_are_local_to_each_members_date() {
    use std::time::{Duration, UNIX_EPOCH};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let input = root.join("in");
    std::fs::create_dir_all(&input).unwrap();
    // 2025-01-15 and 2025-07-15, both 12:00:00 UTC.
    for (name, secs) in [
        ("winter.txt", 1_736_942_400u64),
        ("summer.txt", 1_752_580_800),
    ] {
        std::fs::write(input.join(name), name).unwrap();
        let file = std::fs::File::options()
            .write(true)
            .open(input.join(name))
            .unwrap();
        file.set_modified(UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .env("TZ", "EST5EDT,M3.2.0,M11.1.0")
        .args([
            "--json",
            "par3",
            "archive",
            "--format",
            "zip",
            "--base-path",
            "in",
        ])
        .args(["out/times.zip", "winter.txt", "summer.txt"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = std::fs::File::open(root.join("out/times.zip")).unwrap();
    let mut reader = zip::ZipArchive::new(file).unwrap();
    let hour = |reader: &mut zip::ZipArchive<std::fs::File>, name: &str| {
        reader
            .by_name(name)
            .unwrap()
            .last_modified()
            .unwrap()
            .hour()
    };
    assert_eq!(hour(&mut reader, "winter.txt"), 7);
    assert_eq!(hour(&mut reader, "summer.txt"), 8);
}
