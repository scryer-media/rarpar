//! Standard input through the PAR commands: `par3 create -` builds a set from
//! a pipe, and `par verify --name` checks one protected file from a pipe.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const PIPE_CHUNK: usize = 64 << 10;

fn rarpar(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Runs rarpar with `input` fed to its standard input in chunks from one
/// thread while another drains standard error and this one drains standard
/// output, so the child sees true pipes in both directions.
fn through_pipes(root: &Path, args: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rarpar"))
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
fn ok(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[track_caller]
fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Deterministic bytes that do not repeat at block boundaries.
fn sample(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

#[track_caller]
fn usage_error(output: &Output, mentions: &[&str]) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in mentions {
        assert!(stderr.contains(text), "{text:?} not in {stderr}");
    }
}

// ---------------------------------------------------------------------------
// par3 create from standard input

/// The verdicts `par3 verify` gives for the set at `index`.
fn par3_verdicts(root: &Path, index: &str) -> (Option<i32>, Value) {
    let output = rarpar(root, &["--json", "par3", "verify", index]);
    let report = json(&output);
    let files: Vec<Value> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            let name = Path::new(file["path"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            serde_json::json!({"name":name,"complete":file["complete"],
                "verified_prefix":file["verified_prefix"]})
        })
        .collect();
    (output.status.code(), serde_json::json!(files))
}

#[test]
fn par3_create_from_a_pipe_verifies_and_repairs_like_a_set_made_from_the_file() {
    // Few blocks code in GF(2^8); past 128 the set moves to GF(2^16) and the
    // stream drops its GF(2^8) rows on the way.
    for (len, block, rows, field) in [
        (300_017usize, "65536", "3", 1u64),
        (3 << 20, "16384", "8", 2),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let piped = temp.path().join("piped");
        let from_file = temp.path().join("from_file");
        std::fs::create_dir_all(&piped).unwrap();
        std::fs::create_dir_all(&from_file).unwrap();
        let data = sample(len, len as u64);

        // No INPUT: standard input is a pipe, so it is the input.
        let created = through_pipes(
            &piped,
            &[
                "--json", "par3", "create", "set.par3", "--name", "data.bin", "-s", block, "-c",
                rows,
            ],
            data.clone(),
        );
        ok(&created);
        let report = json(&created);
        assert_eq!(report["source_bytes"], len as u64);
        assert_eq!(report["field_bytes"], field, "{len} bytes");
        assert_eq!(report["recovery_blocks"], rows.parse::<u64>().unwrap());
        assert!(!piped.join("data.bin").exists());

        std::fs::write(piped.join("data.bin"), &data).unwrap();
        std::fs::write(from_file.join("data.bin"), &data).unwrap();
        ok(&rarpar(
            &from_file,
            &[
                "par3", "create", "set.par3", "data.bin", "-s", block, "-c", rows,
            ],
        ));

        let ours = par3_verdicts(&piped, "set.par3");
        assert_eq!(ours.0, Some(0));
        assert_eq!(ours, par3_verdicts(&from_file, "set.par3"));

        // Damage the file on disk: both sets see it and repair it.
        for root in [&piped, &from_file] {
            let mut damaged = data.clone();
            for at in [len / 3, len / 2] {
                damaged[at] ^= 0xA5;
            }
            std::fs::write(root.join("data.bin"), &damaged).unwrap();
        }
        let ours = par3_verdicts(&piped, "set.par3");
        assert_eq!(ours.0, Some(1));
        assert_eq!(ours, par3_verdicts(&from_file, "set.par3"));
        ok(&rarpar(
            &piped,
            &["par3", "repair", "set.par3", "--no-backup"],
        ));
        assert!(std::fs::read(piped.join("data.bin")).unwrap() == data);
    }
}

#[test]
fn par3_create_from_a_pipe_honours_dash_and_the_output_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("sets")).unwrap();
    let data = sample(200_000, 3);
    let args = [
        "par3",
        "create",
        "sets",
        "-",
        "--name",
        "piece.bin",
        "-s",
        "4096",
        "-c",
        "2",
    ];
    ok(&through_pipes(root, &args, data.clone()));
    assert!(root.join("sets/piece.bin.par3").is_file());
    // An existing set is not replaced without --overwrite.
    let again = through_pipes(root, &args, data.clone());
    assert_eq!(again.status.code(), Some(3));
    let mut overwrite = vec!["--overwrite"];
    overwrite.extend_from_slice(&args);
    ok(&through_pipes(root, &overwrite, data.clone()));

    std::fs::write(root.join("sets/piece.bin"), &data).unwrap();
    let (code, _) = par3_verdicts(&root.join("sets"), "piece.bin.par3");
    assert_eq!(code, Some(0));

    // The global -o directory takes a relative OUTPUT, and a directory OUTPUT
    // inside it still takes --name.
    std::fs::create_dir_all(root.join("global/inner")).unwrap();
    ok(&through_pipes(
        root,
        &[
            "-o",
            "global",
            "par3",
            "create",
            "inner",
            "-",
            "--name",
            "piece.bin",
            "-s",
            "4096",
            "-c",
            "2",
        ],
        data.clone(),
    ));
    assert!(root.join("global/inner/piece.bin.par3").is_file());
    assert!(!root.join("inner").exists());
    std::fs::write(root.join("global/inner/piece.bin"), &data).unwrap();
    let (code, _) = par3_verdicts(&root.join("global/inner"), "piece.bin.par3");
    assert_eq!(code, Some(0));
}

#[track_caller]
fn code_of(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn par3_create_from_a_pipe_honours_buffered() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data = sample(100_000, 7);
    for (buffered, flag) in [(false, None), (true, Some("--buffered"))] {
        let mut args = vec![
            "--json",
            "par3",
            "create",
            "set.par3",
            "-",
            "--name",
            "piece.bin",
            "-s",
            "4096",
            "-c",
            "2",
        ];
        if buffered {
            args.insert(0, "--overwrite");
        }
        args.extend(flag);
        let created = through_pipes(root, &args, data.clone());
        ok(&created);
        // As `par3 create` over a file reports it: --buffered skips the
        // storage barriers.
        assert_eq!(json(&created)["buffered"], buffered);
    }
    std::fs::write(root.join("piece.bin"), &data).unwrap();
    let (code, _) = par3_verdicts(root, "set.par3");
    assert_eq!(code, Some(0));
}

/// The names in `directory`, sorted.
fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn par3_create_from_a_pipe_refuses_to_leave_obsolete_volumes_behind() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("sets")).unwrap();
    let data = sample(200_000, 3);
    let create = |count: &'static str, overwrite: bool| {
        let mut args = Vec::new();
        if overwrite {
            args.push("--overwrite");
        }
        args.extend_from_slice(&[
            "par3",
            "create",
            "sets/set.par3",
            "-",
            "--name",
            "piece.bin",
            "-s",
            "4096",
            "-c",
            count,
        ]);
        through_pipes(root, &args, data.clone())
    };
    ok(&create("8", false));
    let before = listing(&root.join("sets"));
    assert_eq!(before.len(), 5, "{before:?}");
    let contents: Vec<Vec<u8>> = before
        .iter()
        .map(|name| std::fs::read(root.join("sets").join(name)).unwrap())
        .collect();

    // Fewer recovery blocks would leave the old set's later volumes behind,
    // authenticated and beside a set they no longer belong to, as `par3
    // create` over a file refuses; the old set stays whole.
    let fewer = create("1", true);
    assert_eq!(
        fewer.status.code(),
        Some(3),
        "stderr={}",
        String::from_utf8_lossy(&fewer.stderr)
    );
    assert!(String::from_utf8_lossy(&fewer.stderr).contains("obsolete"));
    assert_eq!(listing(&root.join("sets")), before);
    for (name, content) in before.iter().zip(&contents) {
        assert_eq!(
            &std::fs::read(root.join("sets").join(name)).unwrap(),
            content
        );
    }

    // A larger count renames the volumes (`vol00+01` for 16 blocks), so the
    // old `vol0+1` would be left too; the same layout replaces every carrier.
    code_of(&create("16", true), 3);
    assert_eq!(listing(&root.join("sets")), before);
    ok(&create("8", true));
    std::fs::write(root.join("sets/piece.bin"), &data).unwrap();
    let (code, _) = par3_verdicts(&root.join("sets"), "set.par3");
    assert_eq!(code, Some(0));
}

#[test]
fn par3_create_from_a_pipe_needs_what_the_length_would_choose() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data = sample(10_000, 5);
    let missing = through_pipes(root, &["par3", "create", "set.par3", "-"], data.clone());
    usage_error(
        &missing,
        &["--name", "-s/--block-size", "-c/--recovery-count"],
    );
    let only_count = through_pipes(
        root,
        &["par3", "create", "set.par3", "-", "--name", "a", "-c", "1"],
        data.clone(),
    );
    usage_error(&only_count, &["-s/--block-size"]);
    let percent = through_pipes(
        root,
        &[
            "par3", "create", "set.par3", "-", "--name", "a", "-s", "4096", "-r", "10",
        ],
        data.clone(),
    );
    usage_error(&percent, &["-c/--recovery-count", "-r/--recovery-percent"]);
    let path_name = through_pipes(
        root,
        &[
            "par3", "create", "set.par3", "-", "--name", "dir/a", "-s", "4096", "-c", "1",
        ],
        data.clone(),
    );
    usage_error(&path_name, &["--name"]);
    std::fs::write(root.join("a.bin"), &data).unwrap();
    let mixed = through_pipes(
        root,
        &["par3", "create", "set.par3", "a.bin", "-"],
        data.clone(),
    );
    usage_error(&mixed, &["cannot be mixed"]);
    let name_without_stream = rarpar(
        root,
        &["par3", "create", "set.par3", "a.bin", "--name", "a"],
    );
    usage_error(&name_without_stream, &["--name"]);
    assert!(!root.join("set.par3").exists());
}

// ---------------------------------------------------------------------------
// par verify of one protected file from standard input

/// A PAR2 set over two files, with the data files left beside it.
fn par2_set(root: &Path) -> (Vec<u8>, Vec<u8>) {
    let first = sample(1_500_000, 11);
    let second = sample(400_000, 13);
    std::fs::write(root.join("first.bin"), &first).unwrap();
    std::fs::write(root.join("second.bin"), &second).unwrap();
    ok(&rarpar(
        root,
        &[
            "par",
            "create",
            "set.par2",
            "first.bin",
            "second.bin",
            "-s",
            "65536",
            "--recovery-count",
            "4",
        ],
    ));
    (first, second)
}

#[test]
fn par_verify_reads_one_protected_file_from_a_pipe() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (first, second) = par2_set(root);
    // The files on disk play no part: the stream is the file.
    std::fs::remove_file(root.join("first.bin")).unwrap();

    for (name, data) in [("first.bin", &first), ("second.bin", &second)] {
        let verified = through_pipes(
            root,
            &["--json", "par", "verify", "set.par2", "--name", name],
            data.clone(),
        );
        ok(&verified);
        let report = json(&verified);
        assert_eq!(report["success"], true);
        assert_eq!(report["stream"]["bytes"], data.len() as u64);
        assert_eq!(report["stream"]["damaged_slices"], serde_json::json!([]));
        assert_eq!(report["stream"]["missing_slices"], 0);
    }

    // Two damaged slices are named; the file is still repairable.
    let mut damaged = first.clone();
    damaged[70_000] ^= 1;
    damaged[5 * 65_536 + 3] ^= 0x80;
    let verified = through_pipes(
        root,
        &["--json", "par", "verify", "set.par2", "--name", "first.bin"],
        damaged,
    );
    assert_eq!(verified.status.code(), Some(1));
    let report = json(&verified);
    assert_eq!(report["success"], false);
    assert_eq!(
        report["stream"]["damaged_slices"],
        serde_json::json!([1, 5])
    );
    assert_eq!(report["stream"]["repairable"], true);

    // A short stream leaves its last slices missing; a long one is refused.
    let short = through_pipes(
        root,
        &["--json", "par", "verify", "set.par2", "--name", "first.bin"],
        first[..1_000_000].to_vec(),
    );
    assert_eq!(short.status.code(), Some(1));
    let report = json(&short);
    assert_eq!(report["stream"]["missing_slices"], 23 - 15);
    let mut long = first.clone();
    long.extend_from_slice(b"extra");
    let long = through_pipes(
        root,
        &["--json", "par", "verify", "set.par2", "--name", "first.bin"],
        long,
    );
    assert_eq!(long.status.code(), Some(1));
    assert_eq!(json(&long)["stream"]["trailing_bytes"], 5);
}

/// Rewrites a PAR2 set's packets as an untrusted writer could: the Main
/// packet declares `slice_size`, and every packet is re-signed with the set
/// ID and packet MD5 that follow from it, so the set still parses.
fn forge_slice_size(par2: &[u8], slice_size: u64) -> Vec<u8> {
    const MAGIC: &[u8; 8] = b"PAR2\0PKT";
    const MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
    let mut packets = Vec::new();
    let mut at = 0;
    while at + 64 <= par2.len() {
        assert_eq!(&par2[at..at + 8], MAGIC);
        let len = u64::from_le_bytes(par2[at + 8..at + 16].try_into().unwrap()) as usize;
        packets.push(par2[at..at + len].to_vec());
        at += len;
    }
    let main = packets
        .iter_mut()
        .find(|packet| &packet[48..64] == MAIN)
        .unwrap();
    main[64..72].copy_from_slice(&slice_size.to_le_bytes());
    let set_id = par2_rs::checksum::md5(&main[64..]);
    let mut out = Vec::new();
    for mut packet in packets {
        packet[32..48].copy_from_slice(&set_id);
        let digest = par2_rs::checksum::md5(&packet[32..]);
        packet[16..32].copy_from_slice(&digest);
        out.extend_from_slice(&packet);
    }
    out
}

#[test]
fn par_verify_from_a_pipe_refuses_a_slice_size_it_cannot_hold() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (first, _) = par2_set(root);
    let index = std::fs::read(root.join("set.par2")).unwrap();
    std::fs::create_dir(root.join("forged")).unwrap();
    // A slice of 2^62 bytes: the allocation for one slice would abort.
    std::fs::write(
        root.join("forged/set.par2"),
        forge_slice_size(&index, 1 << 62),
    )
    .unwrap();
    let forged = through_pipes(
        root,
        &["par", "verify", "forged/set.par2", "--name", "first.bin"],
        first.clone(),
    );
    assert_eq!(
        forged.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&forged.stderr)
    );
    let message = String::from_utf8_lossy(&forged.stderr);
    assert!(message.contains("slice"), "{message}");
    assert!(message.contains("--par3-memory-mib"), "{message}");

    // A slice the budget can hold still verifies; one just past it does not.
    let budget = through_pipes(
        root,
        &[
            "--par3-memory-mib",
            "1",
            "par",
            "verify",
            "set.par2",
            "--name",
            "first.bin",
        ],
        first.clone(),
    );
    ok(&budget);
    std::fs::write(
        root.join("forged/set.par2"),
        forge_slice_size(&index, (1 << 20) + 4),
    )
    .unwrap();
    let over = through_pipes(
        root,
        &[
            "--par3-memory-mib",
            "1",
            "par",
            "verify",
            "forged/set.par2",
            "--name",
            "first.bin",
        ],
        first,
    );
    assert_eq!(over.status.code(), Some(1));
}

#[test]
fn par_verify_from_a_pipe_refuses_what_it_cannot_do() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (first, _) = par2_set(root);
    let wrong = through_pipes(
        root,
        &["par", "verify", "set.par2", "--name", "third.bin"],
        first.clone(),
    );
    usage_error(&wrong, &["third.bin", "first.bin", "second.bin"]);
    let repair = through_pipes(
        root,
        &["par", "repair", "set.par2", "--name", "first.bin"],
        first.clone(),
    );
    usage_error(&repair, &["par repair"]);
    let repair_dash = through_pipes(root, &["par", "repair", "-"], first.clone());
    usage_error(&repair_dash, &["par repair"]);
    let set_on_stdin = through_pipes(root, &["par", "verify", "-"], first.clone());
    usage_error(&set_on_stdin, &["must be a path"]);
}
