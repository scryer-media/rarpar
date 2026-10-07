//! rarpar as par3cmdline: the binary started under the name `par3`, and the
//! `rarpar` name sniffing a par3cmdline command line by its `.par3` argument.
//! The facade verifies, repairs and lists; sets are made with rarpar's own
//! `par3 create`.

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

/// A PAR3 set over `files`, written by rarpar's first-party `par3 create`.
fn create(root: &Path, block_size: &str, recovery: &str, files: &[&str]) {
    let mut args = vec![
        "par3", "create", "--quiet", "-s", block_size, "-c", recovery, "set.par3",
    ];
    args.extend_from_slice(files);
    rarpar(root, &args).code(0);
}

const ALL: [&str; 4] = [
    "lantern.bin",
    "orchard.bin",
    "pebble.txt",
    "nested/quill.bin",
];

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
    // par3cmdline's own argument checks run first, for every command.
    for (args, message) in [
        (&["c", "-Z", "set"][..], "Invalid option specified: -Z"),
        (
            &["c", "-b5", "-s5", "set"],
            "Cannot specify both block count and block size.",
        ),
        (
            &["c", "-r5", "-c5", "set"],
            "Cannot specify both recovery block count and redundancy.",
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
            &["v", "-m1k", "-m2k", "set"],
            "Cannot specify memory limit twice.",
        ),
        (&["v", "-q"], "PAR filename is not specified"),
        (&["l", "set*"], "Found wildcard in PAR filename, set*"),
    ] {
        par3.run(root, args).code(3).says(message);
    }
}

#[test]
fn create_only_switches_are_rejected_on_verify_repair_and_list() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "1000", "1", &["pebble.txt"]);
    for command in ["v", "r", "l"] {
        for (option, message) in [
            ("-b5", "Cannot specify block count unless creating."),
            ("-s100", "Cannot specify block size unless creating."),
            ("-r10", "Cannot specify redundancy unless creating."),
            ("-rm10", "Cannot specify max redundancy unless creating."),
            (
                "-c2",
                "Cannot specify recovery block count unless creating.",
            ),
            ("-cf2", "Cannot specify first block number unless creating."),
            (
                "-cm4",
                "Cannot specify max recovery block count unless creating.",
            ),
            ("-u", "Cannot specify uniform files unless creating."),
            ("-l", "Cannot specify limit files unless creating."),
            ("-n2", "Cannot specify recovery file count unless creating."),
            ("-R", "Cannot specify Recursive unless creating."),
            ("-D", "Cannot specify Data packet unless creating."),
            ("-d1", "Cannot specify deduplication unless creating."),
            (
                "-e8",
                "Cannot specify Error Correction Codes unless creating.",
            ),
            ("-i2", "Cannot specify interleaving unless creating."),
            ("-lp2", "Cannot specify max repetition unless creating."),
            ("-Chello", "Cannot specify comment unless creating."),
            (
                "-fu",
                "rarpar does not create PAR3 files through the par3cmdline facade, so -fu and -ff are not supported.",
            ),
            ("-fu7", "so -fu and -ff are not supported."),
            ("-fu0", "so -fu and -ff are not supported."),
            ("-fu8", "so -fu and -ff are not supported."),
            ("-ff", "so -fu and -ff are not supported."),
            (
                "-abs",
                "rarpar does not create PAR3 files through the par3cmdline facade, so -abs is not supported.",
            ),
        ] {
            par3.run(root, &[command, option, "set.par3"])
                .code(3)
                .says(message)
                .lacks("Loading");
        }
    }
}

#[test]
fn create_side_commands_are_refused_after_the_argument_checks() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "1000", "1", &["pebble.txt"]);
    let before = par3_names(root);
    std::fs::write(root.join("bundle.zip"), b"PK\x05\x06").unwrap();
    for (args, message) in [
        (
            &["c", "-s1000", "-c1", "new.par3", "pebble.txt"][..],
            "rarpar does not create PAR3 files through the par3cmdline facade (c is not supported); use `rarpar par3 create`.",
        ),
        (
            &["create", "new.par3", "pebble.txt"],
            "(c is not supported); use `rarpar par3 create`.",
        ),
        (
            &["tc", "new.par3", "pebble.txt"],
            "(tc is not supported); use `rarpar par3 create`.",
        ),
        (
            &["e", "set.par3", "lantern.bin"],
            "rarpar does not extend PAR3 files through the par3cmdline facade (e is not supported); use `rarpar par3 create`.",
        ),
        (&["te", "set.par3", "lantern.bin"], "(te is not supported)"),
        (&["i", "bundle.zip"], "(i, ti and d are not supported)"),
        (&["ti", "bundle.zip"], "(i, ti and d are not supported)"),
        (&["d", "bundle.zip"], "(i, ti and d are not supported)"),
        // Refused before the missing base path is looked at.
        (
            &["c", "-Bnowhere", "new.par3", "pebble.txt"],
            "(c is not supported)",
        ),
        (&["e", "-Bnowhere", "set.par3"], "(e is not supported)"),
    ] {
        par3.run(root, args).code(3).says(message);
    }
    // par3cmdline's soft notices still print before the refusal.
    par3.run(root, &["c", "-r300", "-s1000", "soft.par3", "pebble.txt"])
        .code(3)
        .says("Invalid redundancy option: 300")
        .says("(c is not supported)");
    assert_eq!(par3_names(root), before, "nothing was written");
}

#[test]
fn exit_code_matrix() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "2", &["lantern.bin"]);
    // 0: success.
    par3.run(root, &["v", "-q", "set.par3"]).code(0);
    // 3: invalid command line, or a create-side command.
    par3.run(root, &["v", "-Z", "set.par3"]).code(3);
    par3.run(root, &["c", "x.par3", "lantern.bin"]).code(3);
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
    par3.run(root, &["v", "-Bnowhere", "set.par3"]).code(6);
    // 8: a memory limit too small to read the set.
    par3.run(root, &["v", "-m1k", "set.par3"])
        .code(8)
        .says("resource limit")
        .says("Failed to verify with PAR file");
    par3.run(root, &["r", "-m1k", "set.par3"])
        .code(8)
        .says("Failed to repair with PAR file");
}

#[test]
fn list_verify_repair_round_trip() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "6", &ALL);
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
    create(root, "500", "1", &["lantern.bin", "orchard.bin"]);
    std::fs::remove_file(root.join("lantern.bin")).unwrap();
    par3.run(root, &["r", "set.par3"])
        .code(0)
        .says("Repair is not possible.")
        .says("You need 9 more recovery blocks to be able to repair.");
    assert!(!root.join("lantern.bin").exists());
}

#[test]
fn moved_input_data_is_found_among_extra_files() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "1", &["lantern.bin", "orchard.bin"]);
    let original = std::fs::read(root.join("orchard.bin")).unwrap();
    std::fs::rename(root.join("orchard.bin"), root.join("renamed.dat")).unwrap();
    // One recovery block cannot cover the file; the extra file does.
    par3.run(root, &["r", "set.par3", "renamed.dat"])
        .code(0)
        .says("Repair complete.");
    assert_eq!(std::fs::read(root.join("orchard.bin")).unwrap(), original);
}

/// A hidden set loads its hidden recovery volumes, and a dangling link
/// beside them hides none of them.
#[test]
fn hidden_sets_and_broken_entries_still_load_every_volume() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    rarpar(
        root,
        &[
            "par3",
            "create",
            "--quiet",
            "-s",
            "500",
            "-c",
            "2",
            ".set.par3",
            "lantern.bin",
        ],
    )
    .code(0);
    #[cfg(unix)]
    std::os::unix::fs::symlink("nowhere", root.join("dangling")).unwrap();
    let original = std::fs::read(root.join("lantern.bin")).unwrap();
    damage(&root.join("lantern.bin"), 10, 400);
    par3.run(root, &["r", ".set.par3"])
        .code(0)
        .says("Loading \".set.vol")
        .says("Repair complete.");
    assert_eq!(std::fs::read(root.join("lantern.bin")).unwrap(), original);
}

/// On a case-insensitive filesystem a PAR filename spelled in another case
/// still finds its recovery volumes by the on-disk spelling.
#[test]
fn a_differently_cased_par_name_finds_its_volumes() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "2", &["lantern.bin"]);
    if !root.join("SET.PAR3").is_file() {
        eprintln!("skipping: the filesystem is case-sensitive");
        return;
    }
    let original = std::fs::read(root.join("lantern.bin")).unwrap();
    damage(&root.join("lantern.bin"), 10, 400);
    par3.run(root, &["r", "SET.PAR3"])
        .code(0)
        .says("Loading \"set.vol")
        .says("Repair complete.");
    assert_eq!(std::fs::read(root.join("lantern.bin")).unwrap(), original);
}

/// A protected name that is now a directory is reported, not an I/O abort.
#[test]
fn a_directory_at_a_protected_name_is_not_file() {
    let par3 = Par3::new();
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "2", &["lantern.bin", "pebble.txt"]);
    std::fs::remove_file(root.join("pebble.txt")).unwrap();
    std::fs::create_dir(root.join("pebble.txt")).unwrap();
    par3.run(root, &["v", "set.par3"])
        .code(0)
        .says("Target: \"pebble.txt\" - not file.")
        .says("Repair is possible.");
}

#[test]
fn rarpar_name_claims_par3_command_lines() {
    let dir = fixture();
    let root = dir.path();
    create(root, "500", "2", &["lantern.bin"]);
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
    rarpar(root, &["c", "-q", "-c2", "new.par3", "lantern.bin"])
        .code(3)
        .says("use `rarpar par3 create`.");
    assert!(!root.join("new.par3").exists());
    // Without a `.par3` argument the command line is not par3cmdline's.
    rarpar(root, &["v", "set"]).lacks("PAR filename");
}

fn copy_par3(from: &Path, to: &Path) {
    for name in par3_names(from) {
        std::fs::copy(from.join(&name), to.join(&name)).unwrap();
    }
}

fn reference_run(reference: &Path, root: &Path, args: &[&str]) -> Run {
    Run::from(
        Command::new(reference)
            .current_dir(root)
            .args(args)
            .output()
            .unwrap(),
        args,
    )
}

/// The lines both tools print alike: each target's verdict, in sorted order,
/// and the summary lines.
fn verdicts(stdout: &str) -> Vec<String> {
    let mut lines: Vec<String> = stdout
        .lines()
        .filter(|line| {
            line.starts_with("Target: ")
                || line.ends_with(" files are missing.")
                || line.ends_with(" files exist but are damaged.")
                || line.starts_with("You have ")
                || line.starts_with("You need ")
                || line.starts_with("Repair is ")
                || line.starts_with("All files are correct")
                || line.starts_with("Repair complete.")
                || line.starts_with("Verifying repaired files")
        })
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}

/// Compare the facade with a real par3cmdline binary, named by
/// `PAR3_REFERENCE_BIN`. Over sets written by par3cmdline and by rarpar's own
/// `par3 create`, both tools list, verify and repair the same damage: the same
/// exit codes, the same verdict lines and the same repaired bytes. Then the
/// exit codes of the command-line errors both tools reject.
#[test]
#[ignore = "needs a par3cmdline binary in PAR3_REFERENCE_BIN"]
fn compare_with_par3cmdline() {
    let Some(reference) = std::env::var_os("PAR3_REFERENCE_BIN") else {
        eprintln!("PAR3_REFERENCE_BIN is not set; nothing to compare");
        return;
    };
    let reference = PathBuf::from(reference);
    let par3 = Par3::new();
    type Damage = fn(&Path);
    let damages: &[(&str, Damage)] = &[
        ("intact", |_| {}),
        ("damaged", |root| damage(&root.join("lantern.bin"), 10, 600)),
        ("missing", |root| {
            std::fs::remove_file(root.join("nested/quill.bin")).unwrap()
        }),
        ("both", |root| {
            damage(&root.join("orchard.bin"), 1100, 60);
            std::fs::remove_file(root.join("pebble.txt")).unwrap();
        }),
        ("truncated", |root| {
            let path = root.join("lantern.bin");
            let bytes = std::fs::read(&path).unwrap();
            std::fs::write(&path, &bytes[..4200]).unwrap();
        }),
        ("irreparable", |root| {
            std::fs::remove_file(root.join("lantern.bin")).unwrap();
            std::fs::remove_file(root.join("orchard.bin")).unwrap();
        }),
    ];
    for (author, options) in [
        ("par3cmdline", &["-s500", "-c6"][..]),
        ("par3cmdline", &["-s1000", "-c3", "-u"]),
        ("rarpar", &["500", "6"]),
        ("rarpar", &["1000", "3"]),
    ] {
        let source = fixture();
        if author == "rarpar" {
            create(source.path(), options[0], options[1], &ALL);
        } else {
            let mut args = vec!["c", "-q"];
            args.extend_from_slice(options);
            args.push("set.par3");
            args.extend_from_slice(&ALL);
            reference_run(&reference, source.path(), &args).code(0);
        }
        for (name, apply) in damages {
            let label = format!("{author} {options:?} {name}");
            let ours = fixture();
            let theirs = fixture();
            copy_par3(source.path(), ours.path());
            copy_par3(source.path(), theirs.path());
            for root in [ours.path(), theirs.path()] {
                apply(root);
            }
            for args in [
                &["l", "set.par3"][..],
                &["v", "set.par3"],
                &["r", "set.par3"],
            ] {
                let a = par3.run(ours.path(), args);
                let b = reference_run(&reference, theirs.path(), args);
                assert_eq!(
                    a.code, b.code,
                    "{label} {args:?}\n{}\n{}",
                    a.stdout, b.stdout
                );
                if args[0] != "l" {
                    assert!(!verdicts(&a.stdout).is_empty(), "{label} {args:?}");
                }
                assert_eq!(
                    verdicts(&a.stdout),
                    verdicts(&b.stdout),
                    "{label} {args:?}\nours:\n{}\ntheirs:\n{}",
                    a.stdout,
                    b.stdout
                );
            }
            for file in ALL {
                assert_eq!(
                    std::fs::read(ours.path().join(file)).ok(),
                    std::fs::read(theirs.path().join(file)).ok(),
                    "{label} {file}"
                );
            }
        }
    }
    let error_cases: &[&[&str]] = &[
        &["x", "set"],
        &["c"],
        &["c", "-Z", "set"],
        &["c", "-b5", "-s5", "set"],
        &["v", "-q"],
        &["v", "-s100", "set.par3"],
        &["r", "-c2", "set.par3"],
        &["l", "-Bnested", "set.par3"],
        &["l", "set*"],
        &["vs", "set.par3"],
        &["v", "missing.par3"],
    ];
    for args in error_cases {
        let ours = fixture();
        let theirs = fixture();
        let a = par3.run(ours.path(), args);
        let b = reference_run(&reference, theirs.path(), args);
        assert_eq!(a.code, b.code, "{args:?}");
    }
}

/// A ZIP of stored entries holding `size` bytes of invented data.
fn stored_zip(size: usize, seed: u32) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }
    // Xorshift bytes: no two blocks alike, as in compressed archive data.
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(seed);
    let data: Vec<u8> = (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let name = b"meadow.bin";
    let crc = crc32(&data);
    let mut zip = Vec::new();
    let fields = |out: &mut Vec<u8>, central: bool| {
        out.extend_from_slice(&[20, 0]);
        if central {
            out.extend_from_slice(&[20, 0]);
        }
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x21]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
    };
    zip.extend_from_slice(b"PK\x03\x04");
    fields(&mut zip, false);
    zip.extend_from_slice(name);
    zip.extend_from_slice(&data);
    let central = zip.len() as u32;
    zip.extend_from_slice(b"PK\x01\x02");
    fields(&mut zip, true);
    zip.extend_from_slice(&[0; 14]);
    zip.extend_from_slice(name);
    let central_len = zip.len() as u32 - central;
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    zip.extend_from_slice(&central_len.to_le_bytes());
    zip.extend_from_slice(&central.to_le_bytes());
    zip.extend_from_slice(&[0, 0]);
    zip
}

/// `vs` and `rs` against a real par3cmdline: PAR data inserted by par3cmdline
/// `i` into ZIP files (and 7z files when `SEVENZ_REFERENCE_BIN` names 7-Zip),
/// damaged in the archive bytes, the packets, both, by truncation and by
/// growth. Both tools must print the same lines (timings aside), exit alike,
/// and leave the same files with the same bytes.
#[test]
#[ignore = "needs a par3cmdline binary in PAR3_REFERENCE_BIN"]
fn self_verify_and_repair_match_par3cmdline() {
    let Some(reference) = std::env::var_os("PAR3_REFERENCE_BIN") else {
        eprintln!("PAR3_REFERENCE_BIN is not set; nothing to compare");
        return;
    };
    let reference = PathBuf::from(reference);
    let par3 = Par3::new();
    let sources = tempfile::tempdir().unwrap();
    let mut archives = Vec::new();
    for (size, seed) in [
        (0usize, 1u32),
        (39, 2),
        (900, 3),
        (5000, 4),
        (70_000, 5),
        (400_000, 6),
    ] {
        let path = sources.path().join(format!("meadow{size}.zip"));
        std::fs::write(&path, stored_zip(size, seed)).unwrap();
        archives.push(path);
        if let Some(sevenz) = std::env::var_os("SEVENZ_REFERENCE_BIN") {
            let input = sources.path().join(format!("meadow{size}.bin"));
            std::fs::write(&input, stored_zip(size, seed + 7)).unwrap();
            let path = sources.path().join(format!("meadow{size}.7z"));
            let status = Command::new(sevenz)
                .current_dir(sources.path())
                .args(["a", "-bd", "-y"])
                .arg(&path)
                .arg(&input)
                .output()
                .unwrap()
                .status;
            assert!(status.success());
            archives.push(path);
        }
    }
    let packets = |bytes: &[u8]| -> Vec<usize> {
        (0..bytes.len().saturating_sub(8))
            .filter(|&at| &bytes[at..at + 8] == b"PAR3\0PKT")
            .collect()
    };
    type Damage = fn(&mut Vec<u8>, &[usize]);
    let damages: &[(&str, Damage)] = &[
        ("intact", |_, _| {}),
        ("head", |bytes, _| bytes[40..60].fill(0)),
        ("middle", |bytes, _| {
            let at = bytes.len() / 3;
            let end = (at + 700).min(bytes.len());
            bytes[at..end].fill(0xAA);
        }),
        ("packet", |bytes, at| {
            if let Some(&at) = at.get(2) {
                bytes[at + 60] ^= 1;
            }
        }),
        ("head and packet", |bytes, at| {
            if let Some(&at) = at.get(2) {
                bytes[at + 60] ^= 1;
            }
            bytes[40..60].fill(0);
        }),
        ("truncated", |bytes, _| {
            let keep = bytes.len() - 100;
            bytes.truncate(keep);
        }),
        ("grown", |bytes, _| bytes.extend_from_slice(&[0x5A; 200])),
    ];
    let timing = |text: &str| -> String {
        text.lines()
            .map(|line| {
                if line.starts_with("done in ") {
                    "done"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    for archive in &archives {
        let name = archive.file_name().unwrap().to_str().unwrap();
        for redundancy in ["-r0", "-r10", "-r40"] {
            let protected = tempfile::tempdir().unwrap();
            std::fs::copy(archive, protected.path().join(name)).unwrap();
            let inserted = reference_run(&reference, protected.path(), &["i", redundancy, name]);
            assert_eq!(inserted.code, 0, "{name} {redundancy}: {}", inserted.stdout);
            let original = std::fs::read(protected.path().join(name)).unwrap();
            let at = packets(&original);
            for (label, damage) in damages {
                let mut damaged = original.clone();
                damage(&mut damaged, &at);
                for args in [&["vs", name][..], &["rs", name], &["rs", "-q", name]] {
                    let ours = tempfile::tempdir().unwrap();
                    let theirs = tempfile::tempdir().unwrap();
                    std::fs::write(ours.path().join(name), &damaged).unwrap();
                    std::fs::write(theirs.path().join(name), &damaged).unwrap();
                    let a = par3.run(ours.path(), args);
                    let b = reference_run(&reference, theirs.path(), args);
                    let context = format!("{name} {redundancy} {label} {args:?}");
                    assert_eq!(a.code, b.code, "{context}");
                    assert_eq!(timing(&a.stdout), timing(&b.stdout), "{context}");
                    let listing = |root: &Path| {
                        let mut names: Vec<(String, Vec<u8>)> = std::fs::read_dir(root)
                            .unwrap()
                            .map(|entry| {
                                let entry = entry.unwrap();
                                let bytes = std::fs::read(entry.path()).unwrap();
                                (entry.file_name().to_string_lossy().into_owned(), bytes)
                            })
                            .collect();
                        names.sort();
                        names
                    };
                    assert!(listing(ours.path()) == listing(theirs.path()), "{context}");
                }
            }
        }
    }
}
