//! rarpar as par3cmdline: the binary started under the name `par3`, and the
//! `rarpar` name sniffing a par3cmdline command line by its `.par3` argument.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A copy of the rarpar binary named `par3`, so it starts as par3cmdline.
struct Par3 {
    _dir: tempfile::TempDir,
    binary: PathBuf,
}

impl Par3 {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir
            .path()
            .join(format!("par3{}", std::env::consts::EXE_SUFFIX));
        let source = Path::new(env!("CARGO_BIN_EXE_rarpar"));
        // A copy, not a link: macOS kills a process whose binary's inode is
        // rewritten under it, and cargo may relink the original meanwhile.
        std::fs::copy(source, &binary).unwrap();
        Self { _dir: dir, binary }
    }

    fn run(&self, root: &Path, args: &[&str]) -> Run {
        Run::from(
            Command::new(&self.binary)
                .current_dir(root)
                .args(args)
                .output()
                .unwrap(),
            args,
        )
    }
}

fn rarpar(root: &Path, args: &[&str]) -> Run {
    Run::from(
        Command::new(env!("CARGO_BIN_EXE_rarpar"))
            .current_dir(root)
            .args(args)
            .output()
            .unwrap(),
        args,
    )
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    args: String,
}

impl Run {
    fn from(output: Output, args: &[&str]) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            args: format!("{args:?}"),
        }
    }

    #[track_caller]
    fn code(self, code: i32) -> Self {
        assert_eq!(
            self.code, code,
            "args={}\nstdout={}\nstderr={}",
            self.args, self.stdout, self.stderr
        );
        self
    }

    #[track_caller]
    fn says(self, text: &str) -> Self {
        assert!(
            self.stdout.contains(text),
            "args={} expected {text:?} in\n{}\nstderr={}",
            self.args,
            self.stdout,
            self.stderr
        );
        self
    }

    #[track_caller]
    fn lacks(self, text: &str) -> Self {
        assert!(
            !self.stdout.contains(text),
            "args={} did not expect {text:?} in\n{}",
            self.args,
            self.stdout
        );
        self
    }
}

/// Invented inputs: deterministic bytes of awkward sizes, a nested file and an
/// empty directory.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join("nested")).unwrap();
    std::fs::create_dir(root.join("hollow")).unwrap();
    for (name, size, seed) in [
        ("lantern.bin", 5000usize, 3u32),
        ("orchard.bin", 3333, 5),
        ("pebble.txt", 90, 7),
        ("nested/quill.bin", 1200, 11),
    ] {
        let bytes: Vec<u8> = (0..size as u32)
            .map(|index| (index.wrapping_mul(seed * 2 + 1) ^ (index >> 5) ^ seed) as u8)
            .collect();
        std::fs::write(root.join(name), bytes).unwrap();
    }
    dir
}

fn par3_names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".par3"))
        .collect();
    names.sort();
    names
}

fn damage(path: &Path, offset: usize, length: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    for byte in &mut bytes[offset..offset + length] {
        *byte = !*byte;
    }
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn help_version_and_short_command_lines() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(root, &["-h"]).code(0).says("Usage:");
    par3.run(root, &["-V"])
        .code(0)
        .says("par3cmdline version 0.0.1");
    par3.run(root, &["-VV"]).code(0).says("par3cmdline version");
    for args in [&[][..], &["c"], &["-v"]] {
        par3.run(root, args)
            .code(3)
            .says("Not enough command line arguments.")
            .says("To show help, type: par3 -h");
    }
    // Two arguments whose first is no command: the help, and code 3.
    par3.run(root, &["x", "set"]).code(3).says("Usage:");
    par3.run(root, &["-VV", "x"]).code(3).says("Usage:");
}

#[test]
fn malformed_and_conflicting_options_fail_with_code_3() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    for (args, message) in [
        (&["c", "-Z", "set"][..], "Invalid option specified: -Z"),
        (
            &["c", "-b5", "-s5", "set"],
            "Cannot specify both block count and block size.",
        ),
        (
            &["v", "-s100", "set"],
            "Cannot specify block size unless creating.",
        ),
        (
            &["c", "-r5", "-c5", "set"],
            "Cannot specify both recovery block count and redundancy.",
        ),
        (
            &["c", "-u", "-l", "set"],
            "Cannot specify two recovery file size schemes.",
        ),
        (
            &["c", "-S5", "set"],
            "Cannot specify searching time limit unless reparing or verifying.",
        ),
        (
            &["l", "-Bnested", "set"],
            "Cannot specify base-path for listing.",
        ),
        (
            &["c", "-d1", "-d2", "set"],
            "Cannot specify deduplication twice.",
        ),
        (&["v", "-q"], "PAR filename is not specified"),
        (&["l", "set*"], "Found wildcard in PAR filename, set*"),
    ] {
        par3.run(root, args).code(3).says(message);
    }
    // Soft errors are printed and the run carries on.
    par3.run(root, &["c", "-r300", "-s1000", "soft.par3", "pebble.txt"])
        .code(0)
        .says("Invalid redundancy option: 300")
        .says("Done");
    par3.run(
        root,
        &["c", "-e9", "-c1", "-s1000", "multi.par3", "pebble.txt"],
    )
    .code(0)
    .says("Cannot specify multiple Error Correction Codes.");
}

#[test]
fn exit_code_matrix() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    // 0: success.
    par3.run(
        root,
        &["c", "-q", "-s1000", "-c2", "set.par3", "lantern.bin"],
    )
    .code(0);
    // 3: invalid command line, or nothing to protect.
    par3.run(root, &["c", "-q", "empty.par3", "absent*"])
        .code(3)
        .says("You must specify a list of files when creating.");
    // 4: a PAR file that holds no set.
    std::fs::write(root.join("junk.par3"), [0x5au8; 300]).unwrap();
    par3.run(root, &["v", "junk.par3"])
        .code(4)
        .says("Failed to find PAR3 Start Packet")
        .says("Failed to verify with PAR file");
    // 6: file I/O: no PAR file, a self target that is no ZIP, a bad base path.
    par3.run(root, &["v", "missing.par3"])
        .code(6)
        .says("PAR file is not found")
        .says("Failed to search PAR files");
    par3.run(root, &["vs", "set.par3"])
        .code(6)
        .says("File extension is different from ZIP.");
    par3.run(root, &["c", "-Bnowhere", "set.par3", "lantern.bin"])
        .code(6);
    par3.run(root, &["c", "set.par3", "../outside.bin"])
        .code(6)
        .says("Ignoring out of base-path input file: ../outside.bin");
    // 7: an error correction code par3cmdline has not implemented.
    par3.run(
        root,
        &["c", "-e2", "-c1", "-s1000", "e2.par3", "pebble.txt"],
    )
    .code(7)
    .says("The specified Error Correction Codes (2) isn't implemented yet.")
    .says("Failed to create PAR file");
    // 8: a memory limit too small for the work.
    par3.run(
        root,
        &["c", "-q", "-m1k", "-s1000", "-c1", "m.par3", "lantern.bin"],
    )
    .code(8)
    .says("Failed to create PAR file");
}

#[test]
fn create_list_verify_repair_round_trip() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &[
            "c",
            "-s500",
            "-c6",
            "set.par3",
            "lantern.bin",
            "orchard.bin",
            "pebble.txt",
            "nested/quill.bin",
        ],
    )
    .code(0)
    .says("Number of input file = 4, directory = 1")
    .says("Total file size = 9623")
    .says("Cauchy Reed-Solomon Codes")
    .says("Recovery block count = 6")
    .says("Wrote index file, set.par3")
    .says("Wrote recovery file, set.vol0+1.par3")
    .says("Done");
    assert_eq!(
        par3_names(root),
        [
            "set.par3",
            "set.vol0+1.par3",
            "set.vol1+2.par3",
            "set.vol3+3.par3"
        ]
    );

    par3.run(root, &["l", "set.par3"])
        .code(0)
        .says("Block size = 500")
        .says(" Size (Bytes)  File (4)")
        .says("         5000 \"lantern.bin\"")
        .says(" Directory (1)")
        .says("\"nested\"")
        .says("Listed");
    par3.run(root, &["l", "-q", "set.par3"])
        .code(0)
        .says("\"orchard.bin\"")
        .lacks("Size (Bytes)");

    par3.run(root, &["v", "set.par3"])
        .code(0)
        .says("Loading \"set.vol0+1.par3\".")
        .says("Target: \"lantern.bin\" - complete.")
        .says("All files are correct, repair is not required.");

    let original = std::fs::read(root.join("lantern.bin")).unwrap();
    damage(&root.join("lantern.bin"), 10, 600);
    std::fs::remove_file(root.join("nested/quill.bin")).unwrap();
    par3.run(root, &["v", "set.par3"])
        .code(0)
        .says("Target: \"lantern.bin\" - damaged.")
        .says("Target: \"nested/quill.bin\" - missing.")
        .says("Repair is required.")
        .says("1 files are missing.")
        .says("1 files exist but are damaged.")
        .says("You have 6 recovery blocks available for Cauchy Reed-Solomon Codes.")
        .says("Repair is possible.");
    // Verifying changes nothing.
    assert!(!root.join("nested/quill.bin").exists());

    par3.run(root, &["r", "set.par3"])
        .code(0)
        .says("Verifying repaired files:")
        .says("Target: \"lantern.bin\" - repaired.")
        .says("Repair complete.");
    assert_eq!(std::fs::read(root.join("lantern.bin")).unwrap(), original);
    assert!(
        root.join("lantern.bin.1").exists(),
        "damaged file kept as a backup"
    );
    par3.run(root, &["v", "-q", "set.par3"])
        .code(0)
        .says("All files are correct, repair is not required.");
    par3.run(root, &["v", "-qq", "set.par3"])
        .code(0)
        .lacks("All files");
}

#[test]
fn repair_that_is_not_possible_changes_nothing_and_exits_0() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &[
            "c",
            "-q",
            "-s500",
            "-c1",
            "set.par3",
            "lantern.bin",
            "orchard.bin",
        ],
    )
    .code(0);
    std::fs::remove_file(root.join("lantern.bin")).unwrap();
    par3.run(root, &["r", "set.par3"])
        .code(0)
        .says("Repair is not possible.")
        .says("You need 9 more recovery blocks to be able to repair.");
    assert!(!root.join("lantern.bin").exists());
}

#[test]
fn trial_create_writes_nothing() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &[
            "tc",
            "-s1000",
            "-c3",
            "set.par3",
            "lantern.bin",
            "pebble.txt",
        ],
    )
    .code(0)
    .says("Size of index file = ")
    .says("Size of recovery file = ")
    .says("Total size of PAR files = ")
    .says("Efficiency of PAR files    = ")
    .says("Done");
    assert!(par3_names(root).is_empty());
}

#[test]
fn creation_options_round_trip() {
    let par3 = Par3::new();
    for (stem, options) in [
        ("fft", &["-e8", "-i1", "-c4"][..]),
        ("uniform", &["-c4", "-u"]),
        ("split", &["-c4", "-u", "-n2"]),
        ("percent", &["-r20"]),
        ("count", &["-b20", "-c3"]),
        ("first", &["-c3", "-cf2"]),
        ("aligned", &["-c3", "-d1"]),
        ("sliding", &["-c3", "-d2"]),
        ("stored", &["-c3", "-D"]),
        ("wide", &["-c10"]),
    ] {
        let dir = fixture();
        let root = dir.path();
        let par = format!("{stem}.par3");
        let mut args = vec!["c", "-q"];
        if stem != "count" {
            args.push(if stem == "wide" { "-s64" } else { "-s500" });
        }
        args.extend_from_slice(options);
        args.extend_from_slice(&[par.as_str(), "lantern.bin", "orchard.bin", "pebble.txt"]);
        par3.run(root, &args).code(0).says("Done");
        // Within one block, so every case's recovery covers it.
        damage(&root.join("orchard.bin"), 1100, 60);
        par3.run(root, &["r", "-q", &par])
            .code(0)
            .says("Repair complete.");
        par3.run(root, &["v", "-q", &par])
            .code(0)
            .says("All files are correct, repair is not required.");
    }
}

#[test]
fn recursion_empty_directories_and_comments() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &[
            "c",
            "-s500",
            "-c3",
            "-R",
            "-Cfirst line",
            "-C\"second\"",
            "set.par3",
            "*",
        ],
    )
    .code(0)
    .says("Number of input file = 4, directory = 2");
    par3.run(root, &["l", "set.par3"])
        .code(0)
        .says("Comment text:\nfirst line\nsecond")
        .says(" Directory (2)")
        .says("\"hollow\"");
    std::fs::remove_dir(root.join("hollow")).unwrap();
    par3.run(root, &["r", "set.par3"])
        .code(0)
        .says("Target: \"hollow\" - missing.")
        .says("Repair complete.");
    assert!(root.join("hollow").is_dir());
}

#[test]
fn moved_input_data_is_found_among_extra_files() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &[
            "c",
            "-q",
            "-s500",
            "-c1",
            "set.par3",
            "lantern.bin",
            "orchard.bin",
        ],
    )
    .code(0);
    let original = std::fs::read(root.join("orchard.bin")).unwrap();
    std::fs::rename(root.join("orchard.bin"), root.join("renamed.dat")).unwrap();
    // One recovery block cannot cover the file; the extra file does.
    par3.run(root, &["r", "set.par3", "renamed.dat"])
        .code(0)
        .says("Repair complete.");
    assert_eq!(std::fs::read(root.join("orchard.bin")).unwrap(), original);
}

#[test]
fn unsupported_commands_and_options_are_refused() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    par3.run(
        root,
        &["c", "-q", "-s1000", "-c1", "set.par3", "pebble.txt"],
    )
    .code(0);
    std::fs::write(root.join("bundle.zip"), b"PK\x05\x06").unwrap();
    for (args, message) in [
        (
            &["e", "set.par3", "pebble.txt"][..],
            "rarpar cannot extend a PAR3 set (e is not supported).",
        ),
        (
            &["te", "set.par3", "pebble.txt"],
            "rarpar cannot extend a PAR3 set (te is not supported).",
        ),
        (&["i", "bundle.zip"], "(i, ti and d are not supported)"),
        (&["ti", "bundle.zip"], "(i, ti and d are not supported)"),
        (&["d", "bundle.zip"], "(i, ti and d are not supported)"),
        (&["vs", "bundle.zip"], "(vs and rs are not supported)"),
        (&["rs", "bundle.zip"], "(vs and rs are not supported)"),
        (&["c", "-fu", "x.par3", "pebble.txt"], "(-fu, -ff)"),
        (&["c", "-ff", "x.par3", "pebble.txt"], "(-fu, -ff)"),
        (&["v", "-fu7", "set.par3"], "(-fu, -ff)"),
        (&["c", "-lp2", "x.par3", "pebble.txt"], "(-lp)"),
        (&["c", "-abs", "x.par3", "pebble.txt"], "(-abs)"),
        (&["c", "-l", "x.par3", "pebble.txt"], "(-l)"),
        (&["c", "-l4096", "x.par3", "pebble.txt"], "(-l)"),
        (&["c", "-n2", "x.par3", "pebble.txt"], "without -u (-n)"),
        (&["c", "-c2", "-cm4", "x.par3", "pebble.txt"], "(-cm, -rm)"),
        (
            &["c", "-s1000", "-c3", "-u", "-n2", "x.par3", "lantern.bin"],
            "unevenly over 2 uniform files",
        ),
        (
            &["c", "-c2", "-e8", "-Chello", "x.par3", "pebble.txt"],
            "comment (-C) only for a plain Cauchy set",
        ),
        (
            &["c", "-c2", "-e2", "-Chello", "x.par3", "pebble.txt"],
            "isn't implemented yet",
        ),
        (
            &["c", "-e4", "x.par3", "pebble.txt"],
            "rarpar cannot write a set for Error Correction Codes (4)",
        ),
    ] {
        let run = par3.run(root, args);
        assert!(
            run.code == 3 || run.code == 7,
            "args={args:?} code={} stdout={}",
            run.code,
            run.stdout
        );
        run.says(message);
    }
    assert!(!root.join("x.par3").exists());
}

#[test]
fn rarpar_name_claims_par3_command_lines() {
    let dir = fixture();
    let root = dir.path();
    rarpar(
        root,
        &["c", "-q", "-s500", "-c2", "set.par3", "lantern.bin"],
    )
    .code(0)
    .says("Wrote index file, set.par3");
    rarpar(root, &["l", "-q", "set.par3"])
        .code(0)
        .says("\"lantern.bin\"");
    damage(&root.join("lantern.bin"), 0, 100);
    rarpar(root, &["r", "set.par3"])
        .code(0)
        .says("Repair complete.");
    rarpar(root, &["v", "-q", "set.par3"])
        .code(0)
        .says("All files are correct, repair is not required.");
    // Without a `.par3` argument the command line is not par3cmdline's.
    rarpar(root, &["v", "set"]).lacks("PAR filename");
}

/// Compare the facade with a real par3cmdline binary, named by
/// `PAR3_REFERENCE_BIN`: exit codes for every case, and every packet of the
/// PAR files apart from the Creator packet, byte for byte, where the two are
/// documented to agree.
#[test]
#[ignore = "needs a par3cmdline binary in PAR3_REFERENCE_BIN"]
fn compare_with_par3cmdline() {
    let Some(reference) = std::env::var_os("PAR3_REFERENCE_BIN") else {
        eprintln!("PAR3_REFERENCE_BIN is not set; nothing to compare");
        return;
    };
    let reference = PathBuf::from(reference);
    let par3 = Par3::new();
    let inputs = ["lantern.bin", "orchard.bin", "pebble.txt"];
    let create_cases: &[&[&str]] = &[
        &["-s1000", "-c3"],
        &["-s500", "-c6"],
        &["-r10"],
        &["-b20", "-c5"],
        &["-s1000", "-e8", "-i1", "-c4"],
        &["-s1000", "-c4", "-u"],
        &["-s1000", "-c4", "-u", "-n2"],
        &["-s1000", "-c3", "-cf2"],
        &["-s1000", "-c3", "-d1"],
        &["-s1000", "-c3", "-d2"],
        &["-s64", "-c10"],
        &["-s1000", "-c2", "-Ca comment"],
        &["-s1000"],
    ];
    for options in create_cases {
        let ours = fixture();
        let theirs = fixture();
        let mut args = vec!["c", "-q"];
        args.extend_from_slice(options);
        args.push("set.par3");
        args.extend_from_slice(&inputs);
        let a = par3.run(ours.path(), &args);
        let b = Run::from(
            Command::new(&reference)
                .current_dir(theirs.path())
                .args(&args)
                .output()
                .unwrap(),
            &args,
        );
        assert_eq!(a.code, b.code, "{args:?}");
        assert_eq!(
            par3_names(ours.path()),
            par3_names(theirs.path()),
            "{args:?}"
        );
        for name in par3_names(ours.path()) {
            assert_eq!(
                packets_without_creator(&ours.path().join(&name)),
                packets_without_creator(&theirs.path().join(&name)),
                "{args:?} {name}"
            );
        }
        // Each verifies and repairs the other's set alike.
        for (root, run) in [(ours.path(), &reference), (theirs.path(), &par3.binary)] {
            std::fs::remove_file(root.join("orchard.bin")).unwrap();
            let verify = Command::new(run)
                .current_dir(root)
                .args(["v", "set.par3"])
                .output()
                .unwrap();
            let repair = Command::new(run)
                .current_dir(root)
                .args(["r", "set.par3"])
                .output()
                .unwrap();
            assert_eq!(verify.status.code(), Some(0), "{args:?}");
            assert_eq!(repair.status.code(), Some(0), "{args:?}");
        }
    }
    let error_cases: &[&[&str]] = &[
        &["x", "set"],
        &["c"],
        &["c", "-Z", "set"],
        &["c", "-b5", "-s5", "set"],
        &["v", "-q"],
        &["vs", "set.par3"],
        &["v", "missing.par3"],
        &["c", "-e2", "-c1", "-s1000", "e2.par3", "pebble.txt"],
        &["c", "-q", "empty.par3", "absent*"],
    ];
    for args in error_cases {
        let ours = fixture();
        let theirs = fixture();
        let a = par3.run(ours.path(), args);
        let b = Command::new(&reference)
            .current_dir(theirs.path())
            .args(*args)
            .output()
            .unwrap();
        assert_eq!(Some(a.code), b.status.code(), "{args:?}");
    }
}

/// Every packet of a PAR3 file except Creator packets, in file order.
fn packets_without_creator(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    let mut packets = Vec::new();
    let mut at = 0;
    while at + 48 <= bytes.len() {
        if &bytes[at..at + 8] != b"PAR3\0PKT" {
            at += 1;
            continue;
        }
        let length = u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap()) as usize;
        let packet = &bytes[at..at + length];
        if &packet[40..47] != b"PAR CRE" {
            packets.push(packet.to_vec());
        }
        at += length;
    }
    packets
}
