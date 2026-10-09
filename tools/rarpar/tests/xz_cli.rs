//! `rarpar xz`: compression, decompression, testing and listing of .xz files.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const BLOCK: &str = "65536";

fn rarpar(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

/// Runs `program` with `input` on standard input, written from a thread of its
/// own so that a full output pipe cannot stall the write.
fn piped(program: &Path, root: &Path, args: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(program)
        .current_dir(root)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        // The child may legitimately stop reading early, closing the pipe.
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    output
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarpar"))
}

#[track_caller]
fn ok(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs `rarpar --json <args>` and returns its report.
#[track_caller]
fn report(root: &Path, args: &[&str]) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let output = rarpar(root, &full);
    ok(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Deterministic, compressible bytes: words from a small vocabulary chosen by
/// a xorshift generator, so every level has something to find.
fn sample(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 12] = [
        b"alpha ",
        b"bravo ",
        b"charlie ",
        b"delta ",
        b"echo ",
        b"foxtrot ",
        b"golf ",
        b"hotel ",
        b"india ",
        b"juliet ",
        b"kilo\n",
        b"lima ",
    ];
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if state.is_multiple_of(7) {
            // A little noise keeps the ratio away from trivial.
            out.push((state >> 24) as u8);
        } else {
            out.extend_from_slice(WORDS[(state >> 32) as usize % WORDS.len()]);
        }
    }
    out.truncate(len);
    out
}

#[test]
fn round_trips_across_levels_threads_and_block_sizes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(200_000, 7);
    std::fs::write(root.join("plain.bin"), &original).unwrap();

    for (level, extreme) in [
        ("0", false),
        ("1", false),
        ("3", true),
        ("6", false),
        ("9", false),
        ("9", true),
    ] {
        let mut previous: Option<Vec<u8>> = None;
        for threads in ["1", "4"] {
            let name = format!("l{level}{}-t{threads}.xz", if extreme { "e" } else { "" });
            let mut args = vec!["xz", "compress", "plain.bin", &name, "--level", level];
            args.extend(["--threads", threads, "--block-size", BLOCK]);
            if extreme {
                args.push("--extreme");
            }
            let compressed = report(root, &args);
            assert_eq!(compressed["operation"], "xz_compress");
            assert_eq!(compressed["input_bytes"], 200_000);
            let bytes = std::fs::read(root.join(&name)).unwrap();
            assert_eq!(compressed["output_bytes"], bytes.len() as u64);
            assert!(bytes.len() < original.len() / 2, "level {level} {name}");
            // Blocks are independent, so the thread count never changes the bytes.
            if let Some(previous) = &previous {
                assert_eq!(
                    previous, &bytes,
                    "level {level}: threads changed the output"
                );
            }
            previous = Some(bytes);

            let listed = report(root, &["xz", "list", &name]);
            assert_eq!(listed["stream_count"], 1);
            assert_eq!(listed["block_count"], 4);
            assert_eq!(listed["uncompressed_bytes"], 200_000);

            for decode_threads in ["1", "4"] {
                let out = format!("{name}.t{decode_threads}.out");
                let decoded = report(
                    root,
                    &["xz", "decompress", &name, &out, "--threads", decode_threads],
                );
                assert_eq!(decoded["output_bytes"], 200_000);
                let expected = if decode_threads == "1" {
                    "sequential"
                } else {
                    "parallel"
                };
                assert_eq!(decoded["decoder"], expected, "{name}");
                assert_eq!(std::fs::read(root.join(&out)).unwrap(), original, "{out}");
            }
        }
    }
}

#[test]
fn every_check_type_round_trips_and_is_listed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(150_000, 11);
    std::fs::write(root.join("plain.bin"), &original).unwrap();
    for check in ["none", "crc32", "crc64", "sha256"] {
        let name = format!("{check}.xz");
        let args = ["xz", "compress", "plain.bin", &name, "--check", check];
        let compressed = report(root, &args);
        assert_eq!(compressed["check"], check);
        let listed = report(root, &["xz", "list", &name]);
        assert_eq!(listed["checks"], serde_json::json!([check]));
        assert_eq!(listed["streams"][0]["check"], check);
        let tested = report(root, &["xz", "test", &name]);
        assert_eq!(tested["output_bytes"], 150_000);
        let out = format!("{check}.out");
        ok(&rarpar(root, &["xz", "decompress", &name, &out]));
        assert_eq!(std::fs::read(root.join(&out)).unwrap(), original);
    }
}

#[test]
fn default_names_keep_the_input_and_follow_the_global_output_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(10_000, 3);
    std::fs::write(root.join("data.tar"), &original).unwrap();

    let compressed = report(root, &["xz", "compress", "data.tar"]);
    assert_eq!(compressed["output"], "data.tar.xz");
    assert!(root.join("data.tar").is_file(), "the input is kept");
    std::fs::rename(root.join("data.tar.xz"), root.join("data.txz")).unwrap();

    std::fs::create_dir(root.join("out")).unwrap();
    let decoded = report(root, &["--output", "out", "xz", "decompress", "data.txz"]);
    assert_eq!(decoded["output"], "out/data.tar");
    assert_eq!(std::fs::read(root.join("out/data.tar")).unwrap(), original);
    assert!(root.join("data.txz").is_file(), "the input is kept");

    // An existing directory as OUTPUT takes the default name inside it.
    std::fs::create_dir(root.join("dir")).unwrap();
    ok(&rarpar(root, &["xz", "compress", "data.tar", "dir"]));
    assert!(root.join("dir/data.tar.xz").is_file());

    // Neither direction guesses a name it cannot derive.
    let output = rarpar(root, &["xz", "compress", "data.txz"]);
    assert_eq!(output.status.code(), Some(2));
    let output = rarpar(root, &["xz", "decompress", "data.tar"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn a_named_output_lands_in_the_global_output_directory_unless_absolute() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(20_000, 11);
    std::fs::write(root.join("data.tar"), &original).unwrap();
    std::fs::create_dir_all(root.join("out/sub")).unwrap();
    std::fs::create_dir(root.join("elsewhere")).unwrap();

    // A relative OUTPUT is placed under -o, keeping its own subdirectories.
    let named = report(
        root,
        &["-o", "out", "xz", "compress", "data.tar", "named.xz"],
    );
    assert_eq!(named["output"], "out/named.xz");
    assert!(!root.join("named.xz").exists());
    let nested = report(
        root,
        &["-o", "out", "xz", "compress", "data.tar", "sub/n.xz"],
    );
    assert_eq!(nested["output"], "out/sub/n.xz");
    let decoded = report(
        root,
        &["-o", "out", "xz", "decompress", "out/named.xz", "back.tar"],
    );
    assert_eq!(decoded["output"], "out/back.tar");
    assert_eq!(std::fs::read(root.join("out/back.tar")).unwrap(), original);

    // An absolute OUTPUT wins over -o.
    let absolute = root.join("elsewhere/abs.xz");
    let absolute_arg = absolute.to_str().unwrap();
    ok(&rarpar(
        root,
        &["-o", "out", "xz", "compress", "data.tar", absolute_arg],
    ));
    assert!(absolute.is_file());
    assert!(!root.join("out/elsewhere").exists());

    // `-` stays standard output.
    let streamed = rarpar(root, &["-o", "out", "xz", "compress", "data.tar", "-"]);
    ok(&streamed);
    let back = piped(
        &bin(),
        root,
        &["xz", "decompress", "-", "-"],
        streamed.stdout,
    );
    ok(&back);
    assert_eq!(back.stdout, original);
}

#[test]
fn an_existing_output_needs_overwrite_and_the_input_is_never_the_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(20_000, 5)).unwrap();
    std::fs::write(root.join("data.bin.xz"), b"keep me").unwrap();

    let output = rarpar(root, &["xz", "compress", "data.bin"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read(root.join("data.bin.xz")).unwrap(), b"keep me");
    let leftovers: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".rarpar-xz-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    ok(&rarpar(
        root,
        &["--overwrite", "xz", "compress", "data.bin"],
    ));
    assert_ne!(std::fs::read(root.join("data.bin.xz")).unwrap(), b"keep me");

    let output = rarpar(
        root,
        &["--overwrite", "xz", "compress", "data.bin", "data.bin"],
    );
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn dry_run_reports_without_writing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(5_000, 9)).unwrap();
    let planned = report(root, &["--dry-run", "xz", "compress", "data.bin"]);
    assert_eq!(planned["dry_run"], true);
    assert_eq!(planned["output"], "data.bin.xz");
    assert!(!root.join("data.bin.xz").exists());
}

#[test]
fn standard_input_and_output_stream_both_ways() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(300_000, 13);

    let compressed = piped(
        &bin(),
        root,
        &["xz", "compress", "-", "--level", "2"],
        original.clone(),
    );
    ok(&compressed);
    assert_eq!(&compressed.stdout[..6], b"\xFD7zXZ\x00");

    // Reports move to standard error while the data holds standard output.
    let decoded = piped(
        &bin(),
        root,
        &["--json", "xz", "decompress", "-"],
        compressed.stdout.clone(),
    );
    ok(&decoded);
    assert_eq!(decoded.stdout, original);
    let report: Value = serde_json::from_slice(&decoded.stderr).unwrap();
    assert_eq!(report["output"], "-");
    assert_eq!(report["input_bytes"], compressed.stdout.len() as u64);
    assert_eq!(report["output_bytes"], original.len() as u64);

    std::fs::write(root.join("piped.xz"), &compressed.stdout).unwrap();
    let to_stdout = rarpar(root, &["--quiet", "xz", "decompress", "piped.xz", "-"]);
    ok(&to_stdout);
    assert_eq!(to_stdout.stdout, original);

    let tested = piped(
        &bin(),
        root,
        &["--json", "xz", "test", "-"],
        compressed.stdout,
    );
    ok(&tested);
    let report: Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(report["output_bytes"], original.len() as u64);

    // An empty pipe is not an .xz stream.
    let listed = piped(&bin(), root, &["xz", "list", "-"], Vec::new());
    assert_eq!(listed.status.code(), Some(1));
}

#[test]
fn concatenated_streams_with_padding_decode_as_one_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let first = sample(70_000, 17);
    let second = sample(90_000, 19);
    std::fs::write(root.join("first.bin"), &first).unwrap();
    std::fs::write(root.join("second.bin"), &second).unwrap();
    ok(&rarpar(root, &["xz", "compress", "first.bin", "-s", BLOCK]));
    ok(&rarpar(
        root,
        &["xz", "compress", "second.bin", "--check", "crc32"],
    ));
    let mut joined = std::fs::read(root.join("first.bin.xz")).unwrap();
    let first_len = joined.len() as u64;
    joined.extend_from_slice(&[0; 4]);
    joined.extend(std::fs::read(root.join("second.bin.xz")).unwrap());
    std::fs::write(root.join("joined.xz"), &joined).unwrap();

    let listed = report(root, &["xz", "list", "joined.xz"]);
    assert_eq!(listed["stream_count"], 2);
    assert_eq!(listed["block_count"], 3);
    assert_eq!(listed["checks"], serde_json::json!(["crc64", "crc32"]));
    assert_eq!(listed["streams"][0]["padding_bytes"], 4);
    assert_eq!(listed["streams"][1]["offset"], first_len + 4);
    assert_eq!(listed["uncompressed_bytes"], 160_000);

    let mut expected = first;
    expected.extend(second);
    for threads in ["1", "4"] {
        let out = format!("joined.t{threads}");
        ok(&rarpar(
            root,
            &["xz", "decompress", "joined.xz", &out, "--threads", threads],
        ));
        assert_eq!(std::fs::read(root.join(&out)).unwrap(), expected);
    }
    let piped = piped(&bin(), root, &["xz", "decompress", "-"], joined);
    ok(&piped);
    assert_eq!(piped.stdout, expected);
}

#[test]
fn damage_fails_the_test_and_leaves_no_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(200_000, 23)).unwrap();
    ok(&rarpar(root, &["xz", "compress", "data.bin", "-s", BLOCK]));
    let mut bytes = std::fs::read(root.join("data.bin.xz")).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x55;
    std::fs::write(root.join("bad.xz"), &bytes).unwrap();

    for threads in ["1", "4"] {
        let output = rarpar(root, &["xz", "test", "bad.xz", "--threads", threads]);
        assert_eq!(output.status.code(), Some(1), "threads {threads}");
        let output = rarpar(root, &["xz", "decompress", "bad.xz", "--threads", threads]);
        assert_eq!(output.status.code(), Some(1), "threads {threads}");
        assert!(!root.join("bad").exists());
    }
    let leftovers: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".rarpar-xz-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let output = rarpar(root, &["--json", "xz", "test", "bad.xz"]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert_eq!(report["exit_code"], 1);
}

#[test]
fn a_dictionary_above_the_memory_limit_is_a_resource_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(2 << 20, 29)).unwrap();
    // One 2 MiB block: the dictionary is the block, 2 MiB.
    ok(&rarpar(
        root,
        &[
            "xz", "compress", "data.bin", "--level", "6", "-s", "2097152",
        ],
    ));
    for threads in ["1", "4"] {
        let output = rarpar(
            root,
            &[
                "xz",
                "test",
                "data.bin.xz",
                "--memory-mib",
                "1",
                "--threads",
                threads,
            ],
        );
        assert_eq!(output.status.code(), Some(4), "threads {threads}");
    }
    ok(&rarpar(
        root,
        &["xz", "test", "data.bin.xz", "--memory-mib", "8"],
    ));

    // Compression degrades its threads to the budget, and refuses below one.
    let planned = report(
        root,
        &[
            "--dry-run",
            "xz",
            "compress",
            "data.bin",
            "x.xz",
            "-s",
            BLOCK,
            "--threads",
            "8",
            "--memory-mib",
            "12",
        ],
    );
    let threads = planned["threads"].as_u64().unwrap();
    assert!((1..8).contains(&threads), "{planned}");
    assert!(planned["memory_estimate_bytes"].as_u64().unwrap() <= 12 << 20);
    let output = rarpar(
        root,
        &[
            "xz",
            "compress",
            "data.bin",
            "y.xz",
            "--level",
            "9",
            "--memory-mib",
            "1",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(!root.join("y.xz").exists());
}

#[cfg(unix)]
#[test]
fn outputs_keep_the_input_permissions_and_modification_time() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(30_000, 31)).unwrap();
    std::fs::set_permissions(
        root.join("data.bin"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let stamp = filetime::FileTime::from_unix_time(1_500_000_000, 0);
    filetime::set_file_mtime(root.join("data.bin"), stamp).unwrap();

    ok(&rarpar(root, &["xz", "compress", "data.bin"]));
    let meta = std::fs::metadata(root.join("data.bin.xz")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        filetime::FileTime::from_last_modification_time(&meta),
        stamp
    );

    std::fs::remove_file(root.join("data.bin")).unwrap();
    ok(&rarpar(root, &["xz", "decompress", "data.bin.xz"]));
    let meta = std::fs::metadata(root.join("data.bin")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        filetime::FileTime::from_last_modification_time(&meta),
        stamp
    );
}

#[test]
fn delete_sources_is_refused_rather_than_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("data.bin"), sample(1_000, 37)).unwrap();
    let output = rarpar(root, &["--delete-sources", "xz", "compress", "data.bin"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(root.join("data.bin").is_file());
    assert!(!root.join("data.bin.xz").exists());
}

/// The system `xz`, when there is one on PATH.
fn system_xz() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let name: OsString = format!("xz{}", std::env::consts::EXE_SUFFIX).into();
    std::env::split_paths(&path)
        .map(|directory| directory.join(&name))
        .find(|candidate| candidate.is_file())
}

/// Differential against XZ Utils: each side decodes what the other wrote, at
/// presets 1, 6 and 9, single-threaded (one block) and on four threads
/// (several blocks), and the block layouts both report agree.
#[test]
fn interoperates_with_the_system_xz() {
    let Some(xz) = system_xz() else {
        eprintln!("skipping: xz is not on PATH");
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(400_000, 41);
    std::fs::write(root.join("plain.bin"), &original).unwrap();

    for preset in ["1", "6", "9"] {
        for threads in ["1", "4"] {
            let tag = format!("p{preset}-t{threads}");

            // xz writes, rarpar reads.
            let mut args = vec![format!("-{preset}"), format!("-T{threads}"), "-c".into()];
            if threads != "1" {
                args.push(format!("--block-size={BLOCK}"));
            }
            args.push("plain.bin".into());
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let theirs = Command::new(&xz)
                .current_dir(root)
                .args(&args)
                .output()
                .unwrap();
            ok(&theirs);
            let theirs_name = format!("theirs-{tag}.xz");
            std::fs::write(root.join(&theirs_name), &theirs.stdout).unwrap();
            let out = format!("theirs-{tag}.out");
            let decoded = report(
                root,
                &["xz", "decompress", &theirs_name, &out, "--threads", threads],
            );
            assert_eq!(std::fs::read(root.join(&out)).unwrap(), original, "{tag}");
            let blocks = if threads == "1" { 1 } else { 7 };
            let listed = report(root, &["xz", "list", &theirs_name]);
            assert_eq!(listed["block_count"], blocks, "{tag}");
            assert_eq!(listed["compressed_bytes"], theirs.stdout.len() as u64);
            if threads != "1" {
                assert_eq!(decoded["decoder"], "parallel", "{tag}");
            }

            // rarpar writes, xz reads.
            let ours_name = format!("ours-{tag}.xz");
            let mut args = vec!["xz", "compress", "plain.bin", &ours_name];
            args.extend(["--level", preset, "--threads", threads]);
            if threads != "1" {
                args.extend(["--block-size", BLOCK]);
            }
            ok(&rarpar(root, &args));
            let decoded = Command::new(&xz)
                .current_dir(root)
                .args(["-d", "-c", &ours_name])
                .output()
                .unwrap();
            ok(&decoded);
            assert_eq!(decoded.stdout, original, "{tag}");
            let robot = Command::new(&xz)
                .current_dir(root)
                .args(["--robot", "-l", &ours_name])
                .output()
                .unwrap();
            ok(&robot);
            let robot = String::from_utf8(robot.stdout).unwrap();
            let totals: Vec<&str> = robot
                .lines()
                .find(|line| line.starts_with("totals\t"))
                .unwrap()
                .split('\t')
                .collect();
            let listed = report(root, &["xz", "list", &ours_name]);
            assert_eq!(totals[1], listed["stream_count"].to_string(), "{tag}");
            assert_eq!(totals[2], listed["block_count"].to_string(), "{tag}");
            assert_eq!(totals[3], listed["compressed_bytes"].to_string(), "{tag}");
            assert_eq!(totals[4], listed["uncompressed_bytes"].to_string(), "{tag}");
            assert_eq!(totals[6], "CRC64", "{tag}");
        }
    }
}

// ---------------------------------------------------------------------------
// Real pipes: the binary reads a pipe fed in chunks while its output is read
// concurrently, so neither side can hold the whole stream.

const PIPE_CHUNK: usize = 64 << 10;

/// Runs rarpar with `input` fed to its standard input in chunks from one
/// thread while another drains standard error and this one drains standard
/// output, so the child sees true pipes in both directions.
fn through_pipes(root: &Path, args: &[&str], input: Vec<u8>) -> Output {
    use std::io::Read;
    let mut child = Command::new(bin())
        .current_dir(root)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        for chunk in input.chunks(PIPE_CHUNK) {
            if stdin.write_all(chunk).is_err() {
                // The child stopped reading; its exit status tells why.
                return;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    feeder.join().unwrap();
    Output {
        status,
        stdout,
        stderr: errors.join().unwrap(),
    }
}

#[track_caller]
fn stderr_report(output: &Output) -> Value {
    ok(output);
    serde_json::from_slice(&output.stderr).unwrap()
}

#[test]
fn pipes_stream_through_compress_and_decompress_on_one_and_four_threads() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(6 << 20, 23);

    let mut reference: Option<Vec<u8>> = None;
    for threads in ["1", "4"] {
        // No INPUT: standard input is a pipe, so it is the input.
        let compressed = through_pipes(
            root,
            &[
                "--json",
                "xz",
                "compress",
                "--level",
                "1",
                "-s",
                "524288",
                "--threads",
                threads,
            ],
            original.clone(),
        );
        let report = stderr_report(&compressed);
        assert_eq!(
            report["input_bytes"],
            original.len() as u64,
            "threads {threads}"
        );
        assert_eq!(report["output_bytes"], compressed.stdout.len() as u64);
        // Blocks are cut by size, so the bytes do not depend on the threads.
        match &reference {
            Some(bytes) => assert_eq!(&compressed.stdout, bytes, "threads {threads}"),
            None => reference = Some(compressed.stdout.clone()),
        }

        for decode_threads in ["1", "4"] {
            let decoded = through_pipes(
                root,
                &[
                    "--json",
                    "xz",
                    "decompress",
                    "-",
                    "-",
                    "--threads",
                    decode_threads,
                ],
                compressed.stdout.clone(),
            );
            let report = stderr_report(&decoded);
            assert!(
                decoded.stdout == original,
                "threads {threads}/{decode_threads}"
            );
            assert_eq!(report["input_bytes"], compressed.stdout.len() as u64);
            let expected = if decode_threads == "1" {
                "sequential"
            } else {
                "stream-parallel"
            };
            assert_eq!(report["decoder"], expected);
        }
    }
}

#[test]
fn a_concatenated_stream_pipe_decodes_tests_and_lists() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let first = sample(3 << 20, 29);
    let second = sample(2 << 20, 31);
    std::fs::write(root.join("first.bin"), &first).unwrap();
    std::fs::write(root.join("second.bin"), &second).unwrap();
    ok(&rarpar(
        root,
        &[
            "xz",
            "compress",
            "first.bin",
            "--level",
            "1",
            "-s",
            "524288",
        ],
    ));
    ok(&rarpar(
        root,
        &[
            "xz",
            "compress",
            "second.bin",
            "--level",
            "1",
            "-s",
            "1048576",
            "--check",
            "sha256",
        ],
    ));
    let mut joined = std::fs::read(root.join("first.bin.xz")).unwrap();
    joined.extend_from_slice(&[0; 8]);
    joined.extend(std::fs::read(root.join("second.bin.xz")).unwrap());
    let mut original = first.clone();
    original.extend_from_slice(&second);

    for threads in ["1", "4"] {
        let decoded = through_pipes(
            root,
            &["--json", "xz", "decompress", "--threads", threads],
            joined.clone(),
        );
        let report = stderr_report(&decoded);
        assert!(decoded.stdout == original, "threads {threads}");
        assert_eq!(report["input_bytes"], joined.len() as u64);

        let tested = through_pipes(
            root,
            &["--json", "xz", "test", "-", "--threads", threads],
            joined.clone(),
        );
        ok(&tested);
        let report: Value = serde_json::from_slice(&tested.stdout).unwrap();
        assert_eq!(report["output_bytes"], original.len() as u64);
    }

    let listed = through_pipes(root, &["--json", "xz", "list", "-"], joined.clone());
    ok(&listed);
    let piped_list: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(piped_list["seekable"], false);
    assert_eq!(piped_list["stream_count"], 2);
    assert_eq!(piped_list["block_count"], 6 + 2);
    assert_eq!(piped_list["compressed_bytes"], joined.len() as u64);
    assert_eq!(piped_list["uncompressed_bytes"], original.len() as u64);
    assert_eq!(piped_list["checks"], serde_json::json!(["crc64"]));
    assert_eq!(
        piped_list["blocks"][6]["uncompressed_offset"],
        first.len() as u64
    );
    assert!(!piped_list["unknown"].as_array().unwrap().is_empty());

    // The same file listed from disk agrees on everything a pipe can know.
    std::fs::write(root.join("joined.xz"), &joined).unwrap();
    let seekable = report(root, &["xz", "list", "joined.xz"]);
    for key in [
        "stream_count",
        "block_count",
        "uncompressed_bytes",
        "compressed_bytes",
    ] {
        assert_eq!(seekable[key], piped_list[key], "{key}");
    }
}

/// Damage in a pipe fails the decode with a data error and writes no report
/// of success, on one thread or four.
#[test]
fn damage_in_a_pipe_is_a_data_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = sample(2 << 20, 37);
    let compressed = through_pipes(
        root,
        &["xz", "compress", "--level", "1", "-s", "262144"],
        original,
    );
    ok(&compressed);
    let mut damaged = compressed.stdout;
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x55;
    for threads in ["1", "4"] {
        let tested = through_pipes(
            root,
            &["xz", "test", "-", "--threads", threads],
            damaged.clone(),
        );
        assert_eq!(tested.status.code(), Some(1), "threads {threads}");
    }
}
