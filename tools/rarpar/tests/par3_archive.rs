//! `rarpar par3 archive`: a 7z archive protected by PAR3 in the same pass.

#![cfg(feature = "sevenz")]

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

#[track_caller]
fn archive(root: &Path, args: &[&str]) -> Value {
    let mut full = vec!["--json", "par3", "archive", "--base-path", "in"];
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

/// Extract with sevenz-turbo and compare every member with its source.
#[track_caller]
fn assert_extracts(root: &Path, archive: &str) {
    let out = root.join(format!("{archive}.out"));
    let mut reader =
        sevenz_turbo::ArchiveReader::open(root.join(archive), sevenz_turbo::Password::empty())
            .unwrap();
    reader
        .for_each_entries(|entry, data| {
            let path = out.join(entry.name());
            if entry.is_directory() {
                std::fs::create_dir_all(&path).unwrap();
            } else {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let mut bytes = Vec::new();
                data.read_to_end(&mut bytes).unwrap();
                std::fs::write(&path, bytes).unwrap();
            }
            Ok(true)
        })
        .unwrap();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let source = root.join("in").join(&relative);
        let copy = out.join(&relative);
        if source.is_dir() {
            assert!(copy.is_dir(), "{} missing", relative.display());
            for entry in std::fs::read_dir(&source).unwrap() {
                pending.push(relative.join(entry.unwrap().file_name()));
            }
        } else {
            assert_eq!(
                std::fs::read(&source).unwrap(),
                std::fs::read(&copy).unwrap(),
                "{}",
                relative.display()
            );
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

fn with_args<'a>(head: &[&'a str], tail: &[&'a str]) -> Vec<&'a str> {
    head.iter().chain(tail).copied().collect()
}

#[test]
fn a_sibling_set_repairs_the_archive_it_was_written_with() {
    let dir = fixture(200_000);
    let root = dir.path();
    let report = archive(
        root,
        &with_args(
            &["out/set.7z"],
            &with_args(&MEMBERS, &["-s", "4096", "-c", "8"]),
        ),
    );
    assert_eq!(report["mode"], "sibling");
    assert_eq!(report["read_back"], false);
    assert_eq!(report["recovery_blocks"], 8);
    assert_extracts(root, "out/set.7z");
    let archive = root.join("out/set.7z");
    let original = std::fs::read(&archive).unwrap();
    // The start header, a run in the middle, and the end header.
    damage(&archive, 0, 32);
    damage(&archive, original.len() / 2, 9000);
    damage(&archive, original.len() - 40, 30);
    let output = rarpar(
        &root.join("out"),
        &["--quiet", "par3", "repair", "--no-backup", "set.par3"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}

#[test]
fn a_relative_archive_path_lands_under_the_global_output_directory() {
    let dir = fixture(20_000);
    let root = dir.path();
    let tail = with_args(&MEMBERS, &["-s", "4096", "-c", "2"]);
    // The members are still found under --base-path; only the archive moves.
    let report = archive(root, &with_args(&["-o", "placed", "sub/set.7z"], &tail));
    assert_eq!(report["mode"], "sibling");
    assert!(root.join("placed/sub/set.par3").is_file());
    assert!(!root.join("sub").exists());
    assert_extracts(root, "placed/sub/set.7z");

    // An absolute archive path wins over -o.
    let absolute = root.join("abs/set.7z");
    archive(
        root,
        &with_args(&["-o", "placed", absolute.to_str().unwrap()], &tail),
    );
    assert!(absolute.is_file());
    assert!(root.join("abs/set.par3").is_file());
    assert!(!root.join("placed/abs").exists());
}

#[test]
fn an_inside_set_repairs_the_archive_that_carries_it() {
    let dir = fixture(150_000);
    let root = dir.path();
    let report = archive(
        root,
        &with_args(
            &["out/inner.7z"],
            &with_args(&MEMBERS, &["--inside", "-r", "10"]),
        ),
    );
    assert_eq!(report["mode"], "inside");
    assert_eq!(report["outputs"].as_array().unwrap().len(), 1);
    let archive = root.join("out/inner.7z");
    let original = std::fs::read(&archive).unwrap();
    assert!(report["protected_bytes"].as_u64().unwrap() < original.len() as u64);
    // 7z readers stop at the end header and ignore the packets after it.
    assert_extracts(root, "out/inner.7z");

    // par3cmdline's `rs`, through the facade, finds the set inside the file.
    let par3 = root.join(format!("par3{}", std::env::consts::EXE_SUFFIX));
    // A link on Unix: a copy's write descriptor, inherited by a child another
    // test forked but has not yet exec'd, fails the copy's own exec with
    // `ETXTBSY`. Windows has neither that window nor unprivileged links.
    #[cfg(unix)]
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_rarpar"), &par3).unwrap();
    #[cfg(windows)]
    std::fs::copy(env!("CARGO_BIN_EXE_rarpar"), &par3).unwrap();
    damage(&archive, 100, 3000);
    let output = Command::new(&par3)
        .current_dir(root.join("out"))
        .args(["rs", "inner.7z"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("protected data was repaired"), "{stdout}");
    assert_eq!(std::fs::read(&archive).unwrap(), original);

    // A second repair replaces the first one's `.1` backup, as par3cmdline
    // does, on every platform.
    let backup = root.join("out/inner.7z.1");
    assert!(backup.exists());
    damage(&archive, 200, 2000);
    let damaged = std::fs::read(&archive).unwrap();
    let output = Command::new(&par3)
        .current_dir(root.join("out"))
        .args(["rs", "inner.7z"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(std::fs::read(&archive).unwrap(), original);
    assert_eq!(std::fs::read(&backup).unwrap(), damaged);
}

/// Archives larger than the in-memory head take the multi-lane path; the set
/// must come out exactly as the exact path writes it.
#[test]
fn the_streaming_lanes_write_the_same_set_as_an_exact_pass() {
    let dir = fixture(3_000_000);
    let root = dir.path();
    for mode in [
        &["-s", "65536", "-r", "4"][..],
        &["--inside"][..],
        &["--inside", "-r", "2"][..],
    ] {
        for (stem, memory) in [("exact", "256"), ("lanes", "4")] {
            let name = format!("{stem}/set.7z");
            let mut args = vec!["--par3-memory-mib", memory, "--par3-workers", "2"];
            args.extend([
                "par3",
                "archive",
                "--base-path",
                "in",
                &name,
                "--level",
                "0",
            ]);
            args.extend(MEMBERS);
            args.extend(mode);
            let output = rarpar(root, &with_args(&["--json"], &args));
            assert_eq!(
                output.status.code(),
                Some(0),
                "{mode:?} {memory}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
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
                "{mode:?}: {name:?} differs"
            );
        }
        std::fs::remove_dir_all(root.join("exact")).unwrap();
        std::fs::remove_dir_all(root.join("lanes")).unwrap();
    }
}

#[test]
fn filters_and_non_solid_archives_extract() {
    let dir = fixture(20_000);
    let root = dir.path();
    for (index, extra) in [
        &["--filter", "x86"][..],
        &["--filter", "arm64", "--no-solid"][..],
        &["--level", "0", "--no-solid"][..],
        &["--filter", "riscv", "--level", "9"][..],
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("out/f{index}.7z");
        archive(root, &with_args(&[&name], &with_args(&MEMBERS, extra)));
        assert_extracts(root, &name);
    }
}

#[test]
fn the_text_report_names_the_archive_and_its_set() {
    let dir = fixture(30_000);
    let root = dir.path();
    let output = rarpar(
        root,
        &with_args(
            &["par3", "archive", "--base-path", "in", "set.7z"],
            &MEMBERS,
        ),
    );
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    let size = std::fs::metadata(root.join("set.7z")).unwrap().len();
    assert_eq!(
        text,
        format!(
            "par3_archive: created\n  set.7z: 8 member(s), {size} bytes, {size} protected\n  \
             1 block(s) of 1048576 bytes, 1 recovery block(s), PAR3 set sibling\n  \
             set.7z\n  set.par3\n  set.vol0+1.par3\n"
        )
    );
}

#[test]
fn existing_outputs_and_bad_switches_are_refused() {
    let dir = fixture(1000);
    let root = dir.path();
    archive(root, &with_args(&["set.7z"], &MEMBERS));
    let again = rarpar(
        root,
        &with_args(
            &["par3", "archive", "--base-path", "in", "set.7z"],
            &MEMBERS,
        ),
    );
    assert_eq!(again.status.code(), Some(3));
    archive(root, &with_args(&["--overwrite", "set.7z"], &MEMBERS));
    for bad in [
        &["--inside", "-c", "2"][..],
        &["--inside", "-s", "4096"][..],
        &["-c", "1", "-r", "5"][..],
        &["--level", "10"][..],
        &["-mx=9"][..],
        &["--inside", "-r", "251"][..],
        // The largest odd block size has no even size to round up to.
        &["-s", "18446744073709551615"][..],
    ] {
        let mut args = vec!["par3", "archive", "--base-path", "in", "other.7z"];
        args.extend(MEMBERS);
        args.extend(bad);
        let output = rarpar(root, &args);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(!root.join("other.7z").exists());
    }
}

/// With `--overwrite`, a previous archive and index under an input directory
/// are not packed into their replacement.
#[test]
fn an_overwritten_archive_under_an_input_is_not_its_own_member() {
    let dir = fixture(1000);
    let root = dir.path();
    let names = |archive: &str| {
        let mut names = Vec::new();
        let mut reader =
            sevenz_turbo::ArchiveReader::open(root.join(archive), sevenz_turbo::Password::empty())
                .unwrap();
        reader
            .for_each_entries(|entry, _| {
                names.push(entry.name().to_owned());
                Ok(true)
            })
            .unwrap();
        names.sort();
        names
    };
    archive(root, &["in/cellar/set.7z", "cellar", "-c", "1"]);
    let first = names("in/cellar/set.7z");
    assert!(root.join("in/cellar/set.par3").is_file());
    archive(
        root,
        &["--overwrite", "in/cellar/set.7z", "cellar", "-c", "1"],
    );
    assert_eq!(names("in/cellar/set.7z"), first);
}

/// With `--overwrite`, an archive rebuilt under another case of its previous
/// name: on a volume that ignores case (Windows, and macOS by default) the
/// previous archive, index and recovery volume are the outputs being replaced
/// and are not packed; on a case-sensitive volume they are other files, and
/// are packed like any other input.
#[test]
fn an_overwritten_archive_in_another_case_is_not_its_own_member() {
    let dir = fixture(1000);
    let root = dir.path();
    let names = |archive: &str| {
        let mut names = Vec::new();
        let mut reader =
            sevenz_turbo::ArchiveReader::open(root.join(archive), sevenz_turbo::Password::empty())
                .unwrap();
        reader
            .for_each_entries(|entry, _| {
                names.push(entry.name().to_owned());
                Ok(true)
            })
            .unwrap();
        names.sort();
        names
    };
    archive(root, &["in/cellar/set.7z", "cellar", "-c", "1"]);
    let first = names("in/cellar/set.7z");
    assert!(root.join("in/cellar/set.vol0+1.par3").is_file());
    let folds = root.join("in/cellar/SET.7z").is_file();
    archive(
        root,
        &["--overwrite", "in/cellar/SET.7z", "cellar", "-c", "1"],
    );
    let second = names("in/cellar/SET.7z");
    if folds {
        assert_eq!(second, first);
    } else {
        for previous in ["set.7z", "set.par3", "set.vol0+1.par3"] {
            let member = format!("cellar/{previous}");
            assert!(second.contains(&member), "{member} in {second:?}");
        }
    }
}

/// An archive named like its own PAR3 index is refused before anything is
/// written, with or without `--overwrite`, in either case of the extension.
#[test]
fn an_archive_named_as_its_own_index_is_refused_first() {
    let dir = fixture(1000);
    let root = dir.path();
    for name in ["set.par3", "SET.PAR3", "set.vol0+1.par3"] {
        for overwrite in [false, true] {
            let mut args = vec!["par3", "archive", "--base-path", "in"];
            if overwrite {
                args.push("--overwrite");
            }
            args.push(name);
            args.extend(MEMBERS);
            let output = rarpar(root, &args);
            assert_eq!(output.status.code(), Some(2), "{name} {overwrite}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("would both be written"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let left: Vec<_> = std::fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name != "in")
                .collect();
            assert!(left.is_empty(), "{name} {overwrite}: {left:?}");
        }
    }
}

/// A recovery volume name that is taken is found before the archive is
/// installed, and a symlink at one is never written through, even with
/// `--overwrite`.
#[test]
fn taken_or_linked_volume_names_stop_the_archive_first() {
    let dir = fixture(1000);
    let root = dir.path();
    std::fs::write(root.join("set.vol0+1.par3"), b"someone else's").unwrap();
    let output = rarpar(
        root,
        &with_args(
            &["par3", "archive", "--base-path", "in", "set.7z"],
            &MEMBERS,
        ),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(!root.join("set.7z").exists());
    assert!(!root.join("set.par3").exists());
    assert_eq!(
        std::fs::read(root.join("set.vol0+1.par3")).unwrap(),
        b"someone else's"
    );

    #[cfg(unix)]
    {
        std::fs::remove_file(root.join("set.vol0+1.par3")).unwrap();
        std::fs::write(root.join("victim.bin"), b"keep me").unwrap();
        std::os::unix::fs::symlink("victim.bin", root.join("set.vol0+1.par3")).unwrap();
        let output = rarpar(
            root,
            &with_args(
                &[
                    "par3",
                    "archive",
                    "--overwrite",
                    "--base-path",
                    "in",
                    "set.7z",
                ],
                &MEMBERS,
            ),
        );
        assert_ne!(output.status.code(), Some(0));
        assert!(!root.join("set.7z").exists());
        assert_eq!(std::fs::read(root.join("victim.bin")).unwrap(), b"keep me");
    }
}

/// The sets match par3cmdline's `c` and `i` over the finished archive, byte
/// for byte, once both write the same Creator text.
#[test]
#[ignore = "needs a par3cmdline binary in PAR3_REFERENCE_BIN"]
fn sets_match_par3cmdline_over_the_finished_archive() {
    let reference = PathBuf::from(std::env::var_os("PAR3_REFERENCE_BIN").unwrap());
    let creator = "par3cmdline version 0.0.1\n(https://github.com/Parchive/par3cmdline)";
    let dir = fixture(700_000);
    let root = dir.path();
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["-s", "4096", "-c", "3"],
            &["c", "-s4096", "-c3", "set.par3", "set.7z"],
        ),
        (
            &["-s", "1000", "-r", "7"],
            &["c", "-s1000", "-r7", "set.par3", "set.7z"],
        ),
        (
            &["-s", "65537", "-c", "1"],
            &["c", "-s65537", "-c1", "set.par3", "set.7z"],
        ),
        (
            &["-s", "2048", "-r", "50"],
            &["c", "-s2048", "-r50", "set.par3", "set.7z"],
        ),
        (&["--inside"], &["i", "set.7z"]),
        (&["--inside", "-r", "5"], &["i", "-r5", "set.7z"]),
        (&["--inside", "-r", "40"], &["i", "-r40", "set.7z"]),
    ];
    for memory in ["256", "4"] {
        for (ours, theirs) in cases {
            let _ = std::fs::remove_dir_all(root.join("ours"));
            let _ = std::fs::remove_dir_all(root.join("theirs"));
            std::fs::create_dir_all(root.join("theirs")).unwrap();
            let mut args = vec!["--json", "--par3-memory-mib", memory, "par3", "archive"];
            args.extend(["--base-path", "in", "ours/set.7z"]);
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
            let archive = std::fs::read(root.join("ours/set.7z")).unwrap();
            std::fs::write(root.join("theirs/set.7z"), &archive[..protected]).unwrap();
            let status = Command::new(&reference)
                .current_dir(root.join("theirs"))
                .args(*theirs)
                .output()
                .unwrap()
                .status;
            assert!(status.success(), "{theirs:?}");
            let mut names: Vec<_> = std::fs::read_dir(root.join("theirs"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            let mut ours_names: Vec<_> = std::fs::read_dir(root.join("ours"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            ours_names.sort();
            assert_eq!(names, ours_names, "{ours:?} {memory}");
            for name in names {
                assert!(
                    std::fs::read(root.join("theirs").join(&name)).unwrap()
                        == std::fs::read(root.join("ours").join(&name)).unwrap(),
                    "{ours:?} {memory}: {name:?} differs"
                );
            }
        }
    }
}
