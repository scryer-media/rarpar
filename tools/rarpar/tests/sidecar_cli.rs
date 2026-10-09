//! Conventional recovery sets written in the same pass as the archive they
//! protect: `xz compress --sidecar` and `par3 archive --sidecar`.
//!
//! Each set is checked by the verifier of its own format against the written
//! archive, then repairs the archive after damage. A set over standard output
//! proves the single pass: the archive only ever existed in the pipe.

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

/// Runs rarpar with `input` fed to standard input in chunks from one thread
/// while another drains standard error and this one drains standard output.
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
fn code(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[track_caller]
fn report(root: &Path, args: &[&str]) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let output = rarpar(root, &full);
    ok(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Invented bytes that do not compress, so damage hits recoverable blocks.
fn noise(size: usize, seed: u32) -> Vec<u8> {
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

fn damage(path: &Path, offset: usize, length: usize) {
    let mut data = std::fs::read(path).unwrap();
    for byte in &mut data[offset..offset + length] {
        *byte = !*byte;
    }
    std::fs::write(path, data).unwrap();
}

/// The verifier of `format` passes `set` in `directory`, `archive` (a path
/// under `directory`) is then damaged, verification fails, and a repair
/// gives back the archive's exact bytes.
#[track_caller]
fn verify_damage_repair(directory: &Path, format: &str, set: &str, archive: &str) {
    let (verify, repair): (&[&str], &[&str]) = match format {
        "par2" => (&["--quiet", "par", "verify"], &["--quiet", "par", "repair"]),
        _ => (
            &["--quiet", "par3", "verify"],
            &["--quiet", "par3", "repair", "--no-backup"],
        ),
    };
    let with = |head: &[&str]| -> Vec<String> {
        head.iter()
            .map(|arg| arg.to_string())
            .chain([set.to_string()])
            .collect()
    };
    let run = |args: Vec<String>| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        rarpar(directory, &args)
    };
    ok(&run(with(verify)));
    let path = directory.join(archive);
    let original = std::fs::read(&path).unwrap();
    damage(&path, 10, 30);
    damage(&path, original.len() / 2, 5000);
    damage(&path, original.len() - 20, 16);
    code(&run(with(verify)), 1);
    ok(&run(with(repair)));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    ok(&run(with(verify)));
}

#[test]
fn xz_sidecars_over_standard_output_verify_and_repair() {
    for format in ["par2", "par3"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let input = noise(700_000, 5);
        let output = through_pipes(
            root,
            &[
                "--json",
                "xz",
                "compress",
                "--sidecar",
                format,
                "--sidecar-block-size",
                "16384",
                "--sidecar-recovery-count",
                "8",
                "--sidecar-name",
                "sets/stream.xz",
                "-",
            ],
            input,
        );
        ok(&output);
        // The report shares standard error with nothing: the archive holds
        // standard output.
        let report: Value = serde_json::from_slice(&output.stderr).unwrap();
        let sidecar = &report["sidecar"];
        assert_eq!(sidecar["format"], format);
        assert_eq!(sidecar["name"], "stream.xz");
        assert_eq!(sidecar["recovery_blocks"], 8);
        assert_eq!(
            sidecar["source_bytes"].as_u64(),
            Some(output.stdout.len() as u64)
        );
        // The set was finished before the archive reached a file: the bytes
        // it covers were seen once, in the pipe.
        let sets = root.join("sets");
        assert!(sets.join(format!("stream.xz.{format}")).is_file());
        std::fs::write(sets.join("stream.xz"), &output.stdout).unwrap();
        verify_damage_repair(&sets, format, &format!("stream.xz.{format}"), "stream.xz");
    }
}

#[test]
fn an_xz_file_output_names_its_set_after_the_archive_under_the_global_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data.tar"), noise(300_000, 11)).unwrap();
    for format in ["par2", "par3"] {
        let report = report(
            root,
            &[
                "-o",
                format,
                "xz",
                "compress",
                "--sidecar",
                format,
                "--sidecar-block-size",
                "8192",
                "--sidecar-recovery-count",
                "5",
                "data.tar",
            ],
        );
        let placed = root.join(format);
        assert_eq!(report["sidecar"]["name"], "data.tar.xz");
        assert!(placed.join("data.tar.xz").is_file());
        assert!(placed.join(format!("data.tar.xz.{format}")).is_file());
        assert_eq!(
            report["sidecar"]["source_bytes"].as_u64(),
            Some(std::fs::metadata(placed.join("data.tar.xz")).unwrap().len())
        );
        verify_damage_repair(
            &placed,
            format,
            &format!("data.tar.xz.{format}"),
            "data.tar.xz",
        );
    }
}

#[test]
fn a_streamed_par2_sidecar_is_the_set_par_create_makes_from_the_finished_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("blob"), noise(900_000, 23)).unwrap();
    report(
        root,
        &[
            "xz",
            "compress",
            "--sidecar",
            "par2",
            "--sidecar-block-size",
            "32768",
            "--sidecar-recovery-count",
            "13",
            "blob",
            "streamed/blob.xz",
        ],
    );
    std::fs::create_dir(root.join("finished")).unwrap();
    report(
        root,
        &[
            "par",
            "create",
            "-s",
            "32768",
            "--recovery-count",
            "13",
            "--base-path",
            "streamed",
            "finished/blob.xz.par2",
            "blob.xz",
        ],
    );
    let mut names: Vec<String> = std::fs::read_dir(root.join("finished"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 5, "{names:?}");
    for name in &names {
        assert_eq!(
            std::fs::read(root.join("streamed").join(name)).unwrap(),
            std::fs::read(root.join("finished").join(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn xz_sidecar_options_are_checked_before_any_byte_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(10_000, 2)).unwrap();
    let sized = [
        "--sidecar-block-size",
        "4096",
        "--sidecar-recovery-count",
        "2",
    ];
    let args = |head: &[&'static str], tail: &[&'static str]| -> Vec<&'static str> {
        ["xz", "compress"]
            .iter()
            .chain(head)
            .chain(tail)
            .copied()
            .collect()
    };

    // Standard output has no name for the set to record.
    let output = through_pipes(
        root,
        &args(&["--sidecar", "par2"], &[&sized[..], &["-"]].concat()),
        noise(1000, 1),
    );
    code(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--sidecar-name"));
    // Both numbers are needed up front.
    let output = rarpar(root, &args(&["--sidecar", "par3"], &["data"]));
    code(&output, 2);
    let message = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(message.contains("--sidecar-block-size"), "{message}");
    assert!(message.contains("--sidecar-recovery-count"), "{message}");
    // A file output names its own set.
    let output = rarpar(
        root,
        &args(
            &["--sidecar", "par2", "--sidecar-name", "other.xz"],
            &[&sized[..], &["data"]].concat(),
        ),
    );
    code(&output, 2);
    // The sidecar flags need --sidecar.
    code(
        &rarpar(root, &args(&["--sidecar-block-size", "4096"], &["data"])),
        2,
    );
    assert!(!root.join("data.xz").exists());

    // A taken volume name stops the run before the archive is written.
    std::fs::write(root.join("data.xz.vol1+1.par2"), b"taken").unwrap();
    let output = rarpar(
        root,
        &args(&["--sidecar", "par2"], &[&sized[..], &["data"]].concat()),
    );
    code(&output, 3);
    assert!(!root.join("data.xz").exists());
    assert!(!root.join("data.xz.par2").exists());
    // --overwrite replaces it.
    let mut overwrite = vec!["--overwrite"];
    overwrite.extend(args(
        &["--sidecar", "par2"],
        &[&sized[..], &["data"]].concat(),
    ));
    ok(&rarpar(root, &overwrite));
    ok(&rarpar(root, &["--quiet", "par", "verify", "data.xz.par2"]));

    // A dry run lists the set's files and writes nothing.
    let report = report(
        root,
        &[
            "--dry-run",
            "xz",
            "compress",
            "--sidecar",
            "par3",
            "--sidecar-block-size",
            "4096",
            "--sidecar-recovery-count",
            "3",
            "data",
            "dry.xz",
        ],
    );
    assert_eq!(report["sidecar"]["outputs"].as_array().unwrap().len(), 3);
    assert!(!root.join("dry.xz").exists());
    assert!(!root.join("dry.xz.par3").exists());
}

#[test]
fn an_xz_par2_overwrite_refuses_to_leave_obsolete_volumes_behind() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(200_000, 7)).unwrap();
    let compress = |count: &str| {
        rarpar(
            root,
            &[
                "--overwrite",
                "xz",
                "compress",
                "--sidecar",
                "par2",
                "--sidecar-block-size",
                "4096",
                "--sidecar-recovery-count",
                count,
                "data",
            ],
        )
    };
    let snapshot = || {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        files.sort();
        files
    };
    ok(&compress("8"));
    // A file that only looks like a volume is not part of any set.
    std::fs::write(root.join("data.xz.vol90+9.par2"), b"not a volume").unwrap();
    let before = snapshot();

    // Fewer volumes would leave authenticated volumes of the old set.
    let output = compress("1");
    code(&output, 3);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("obsolete"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(snapshot(), before);
    // More volumes rename them, which would orphan the old names too.
    code(&compress("16"), 3);
    assert_eq!(snapshot(), before);

    // The same layout replaces every volume of the old set.
    ok(&compress("8"));
    ok(&rarpar(root, &["--quiet", "par", "verify", "data.xz.par2"]));
}

#[test]
fn an_xz_output_named_like_its_set_index_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(20_000, 4)).unwrap();
    for format in ["par2", "par3"] {
        let alias = format!("archive.{format}");
        let sized = [
            "--sidecar",
            format,
            "--sidecar-block-size",
            "4096",
            "--sidecar-recovery-count",
            "2",
        ];
        // A file OUTPUT, directly and under the global -o directory.
        for head in [&["--overwrite"][..], &["--overwrite", "-o", "placed"][..]] {
            let mut args: Vec<&str> = head.to_vec();
            args.extend(["xz", "compress"]);
            args.extend(sized);
            args.extend(["data", &alias]);
            let output = rarpar(root, &args);
            code(&output, 2);
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("both be written"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // Standard output saved under a name the set's index would take.
        let mut args = vec!["--overwrite", "xz", "compress"];
        args.extend(sized);
        args.extend(["--sidecar-name", &alias, "-"]);
        let output = through_pipes(root, &args, noise(1000, 1));
        code(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(!root.join(&alias).exists());
        assert!(!root.join("placed").exists());
    }
}

#[test]
fn an_xz_sidecar_that_would_replace_the_input_is_refused_before_anything_is_written() {
    for format in ["par2", "par3"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // The input is named like the index of the set `--sidecar-name`
        // asks for, so installing that set would replace it.
        let input = format!("source.{format}");
        let before = noise(20_000, 4);
        std::fs::write(root.join(&input), &before).unwrap();
        let output = rarpar(
            root,
            &[
                "--overwrite",
                "xz",
                "compress",
                "--sidecar",
                format,
                "--sidecar-block-size",
                "4096",
                "--sidecar-recovery-count",
                "2",
                "--sidecar-name",
                "source",
                &input,
                "-",
            ],
        );
        code(&output, 3);
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains("over the input"), "{message}");
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(root.join(&input)).unwrap(), before);
        let names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, [input.as_str()], "{names:?}");
    }
}

#[test]
fn a_par2_sidecar_of_many_tiny_rows_counts_each_row_against_the_memory_limit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(1000, 6)).unwrap();
    // 65,535 four-byte rows are 256 KiB of bytes, but each is its own
    // allocation in a list of vectors: well past 1 MiB in all.
    let output = rarpar(
        root,
        &[
            "--dry-run",
            "--par3-memory-mib",
            "1",
            "xz",
            "compress",
            "--sidecar",
            "par2",
            "--sidecar-block-size",
            "1",
            "--sidecar-recovery-count",
            "65535",
            "data",
        ],
    );
    code(&output, 4);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--par3-memory-mib"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_sidecar_block_size_that_cannot_be_rounded_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(1000, 8)).unwrap();
    let largest = u64::MAX.to_string();
    let even = (u64::MAX - 1).to_string();
    // PAR3 rounds an odd size up to even, PAR2 up to a multiple of four.
    for (format, size) in [("par3", &largest), ("par2", &largest), ("par2", &even)] {
        let output = rarpar(
            root,
            &[
                "--dry-run",
                "xz",
                "compress",
                "--sidecar",
                format,
                "--sidecar-block-size",
                size,
                "--sidecar-recovery-count",
                "1",
                "data",
            ],
        );
        code(&output, 2);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be rounded"),
            "{format} {size}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // A set over standard input takes the same plan.
    let output = through_pipes(
        root,
        &[
            "--dry-run",
            "par3",
            "create",
            "set.par3",
            "-",
            "--name",
            "piece",
            "-s",
            &largest,
            "-c",
            "1",
        ],
        noise(100, 2),
    );
    code(&output, 2);
}

#[cfg(unix)]
#[test]
fn a_sidecar_for_a_name_that_is_not_utf8_is_refused() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("data"), noise(5000, 10)).unwrap();
    let bad = OsStr::from_bytes(b"bad\xff.xz");
    let listing = || {
        let mut names: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let before = listing();
    for format in ["par2", "par3"] {
        // An xz OUTPUT the set would be named after.
        let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
            .current_dir(root)
            .args([
                "xz",
                "compress",
                "--sidecar",
                format,
                "--sidecar-block-size",
                "4096",
                "--sidecar-recovery-count",
                "2",
                "data",
            ])
            .arg(bad)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        code(&output, 2);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("UTF-8"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(listing(), before);
    }
    // A set over standard input placed at an OUTPUT that is not UTF-8.
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .args(["par3", "create"])
        .arg(OsStr::from_bytes(b"set\xff.par3"))
        .args(["-", "--name", "piece", "-s", "4096", "-c", "2"])
        .stdin(std::fs::File::open(root.join("data")).unwrap())
        .output()
        .unwrap();
    code(&output, 2);
    assert_eq!(listing(), before);
}

#[test]
fn an_xz_overwrite_whose_sidecar_cannot_be_finished_keeps_the_previous_archive() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // A PAR2 set holds at most 32,768 slices. An archive four bytes past
    // 32,768 eight-byte slices (an .xz is a multiple of four bytes) feeds
    // every whole slice as it is written, and only finishing the set meets
    // the 32,769th: the set fails after the archive is complete.
    let target = 32_768 * 8 + 4;
    let level0 = ["xz", "compress", "--level", "0", "--threads", "1"];
    let compressed = |input: &[u8], name: &str| {
        std::fs::write(root.join("probe"), input).unwrap();
        let mut args = vec!["--overwrite"];
        args.extend(level0);
        args.extend(["probe", name]);
        ok(&rarpar(root, &args));
        std::fs::metadata(root.join(name)).unwrap().len() as usize
    };
    // Incompressible input grows by a fixed overhead, give or take a chunk
    // header, so the input of the right length is found near the estimate.
    let estimate = 262_000 + target - compressed(&noise(262_000, 12), "probe.xz");
    let data = (estimate - 16..=estimate + 16)
        .map(|len| noise(len, 12))
        .find(|data| compressed(data, "probe.xz") == target)
        .expect("an input that compresses to the target length");
    std::fs::write(root.join("data"), &data).unwrap();

    std::fs::write(root.join("old"), noise(50_000, 13)).unwrap();
    let mut args = vec!["xz", "compress"];
    args.extend([
        "--sidecar",
        "par2",
        "--sidecar-block-size",
        "4096",
        "--sidecar-recovery-count",
        "1",
        "old",
        "out.xz",
    ]);
    ok(&rarpar(root, &args));
    let archive = std::fs::read(root.join("out.xz")).unwrap();
    let set = std::fs::read(root.join("out.xz.par2")).unwrap();

    let mut args = vec!["--overwrite"];
    args.extend(level0);
    args.extend([
        "--sidecar",
        "par2",
        "--sidecar-block-size",
        "8",
        "--sidecar-recovery-count",
        "1",
        "data",
        "out.xz",
    ]);
    let output = rarpar(root, &args);
    code(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("32768 slices"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        std::fs::read(root.join("out.xz")).unwrap() == archive,
        "the previous archive was replaced"
    );
    assert!(
        std::fs::read(root.join("out.xz.par2")).unwrap() == set,
        "the previous set was replaced"
    );
    ok(&rarpar(root, &["--quiet", "par", "verify", "out.xz.par2"]));
}

#[test]
fn an_overwrite_spelled_in_another_case_refuses_to_leave_obsolete_volumes_behind() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Only a filesystem that folds case holds `SET.xz` and `set.xz` as one
    // file; on one that does not, the two are separate sets.
    std::fs::write(root.join("Probe"), b"").unwrap();
    if !root.join("PROBE").exists() {
        eprintln!("skipped: the temporary directory is case-sensitive");
        return;
    }
    std::fs::remove_file(root.join("Probe")).unwrap();
    std::fs::write(root.join("data"), noise(200_000, 14)).unwrap();
    for format in ["par2", "par3"] {
        let compress = |output: &str, count: &str| {
            rarpar(
                root,
                &[
                    "--overwrite",
                    "xz",
                    "compress",
                    "--sidecar",
                    format,
                    "--sidecar-block-size",
                    "4096",
                    "--sidecar-recovery-count",
                    count,
                    "data",
                    output,
                ],
            )
        };
        let snapshot = || {
            let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(root)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().into_string().unwrap(),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect();
            files.sort();
            files
        };
        ok(&compress("SET.xz", "8"));
        let before = snapshot();
        let output = compress("set.xz", "1");
        code(&output, 3);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("obsolete"),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(snapshot() == before, "{format}: the previous set changed");
        // The same layout, in either spelling, replaces every volume.
        ok(&compress("set.xz", "8"));
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == format) {
                std::fs::remove_file(path).unwrap();
            }
        }
        std::fs::remove_file(root.join("SET.xz")).unwrap();
    }
}

#[cfg(feature = "sevenz")]
mod archives {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(input.join("nested")).unwrap();
        std::fs::write(input.join("static.bin"), noise(400_000, 3)).unwrap();
        std::fs::write(input.join("ledger.txt"), b"quartz ferry ".repeat(3000)).unwrap();
        std::fs::write(input.join("nested/tally.raw"), noise(4321, 9)).unwrap();
        dir
    }

    fn archive(root: &Path, args: &[&str]) -> Value {
        let mut full = vec!["par3", "archive", "--base-path", "in"];
        full.extend_from_slice(args);
        report(root, &full)
    }

    #[test]
    fn a_zip_takes_a_par2_sidecar_in_the_same_pass() {
        let dir = fixture();
        let root = dir.path();
        let report = archive(
            root,
            &[
                "--format",
                "zip",
                "--sidecar",
                "par2",
                "--sidecar-block-size",
                "8192",
                "--sidecar-recovery-count",
                "9",
                "out/set.zip",
                "static.bin",
                "ledger.txt",
                "nested",
            ],
        );
        assert_eq!(report["mode"], "sibling");
        assert_eq!(report["set_format"], "par2");
        assert_eq!(report["read_back"], false);
        assert_eq!(report["recovery_blocks"], 9);
        assert_eq!(
            report["protected_bytes"].as_u64(),
            Some(std::fs::metadata(root.join("out/set.zip")).unwrap().len())
        );
        // Named by the archive's stem, as the PAR3 sibling set is, and the
        // set `par create` makes from the finished archive.
        assert!(root.join("out/set.par2").is_file());
        std::fs::create_dir(root.join("finished")).unwrap();
        super::report(
            root,
            &[
                "par",
                "create",
                "-s",
                "8192",
                "--recovery-count",
                "9",
                "--base-path",
                "out",
                "finished/set.par2",
                "set.zip",
            ],
        );
        for entry in std::fs::read_dir(root.join("finished")).unwrap() {
            let name = entry.unwrap().file_name();
            assert_eq!(
                std::fs::read(root.join("out").join(&name)).unwrap(),
                std::fs::read(root.join("finished").join(&name)).unwrap(),
                "{name:?}"
            );
        }
        verify_damage_repair(&root.join("out"), "par2", "set.par2", "set.zip");
    }

    #[test]
    fn a_zip_par2_overwrite_refuses_to_leave_obsolete_volumes_behind() {
        let dir = fixture();
        let root = dir.path();
        let create = |count: &str| {
            rarpar(
                root,
                &[
                    "--overwrite",
                    "par3",
                    "archive",
                    "--base-path",
                    "in",
                    "--format",
                    "zip",
                    "--sidecar",
                    "par2",
                    "--sidecar-block-size",
                    "8192",
                    "--sidecar-recovery-count",
                    count,
                    "out/set.zip",
                    "static.bin",
                    "ledger.txt",
                    "nested",
                ],
            )
        };
        let snapshot = || {
            let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(root.join("out"))
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().into_string().unwrap(),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect();
            files.sort();
            files
        };
        ok(&create("8"));
        let before = snapshot();

        // Fewer volumes would leave authenticated volumes of the old set,
        // and the refusal comes before the archive is rebuilt.
        let output = create("1");
        code(&output, 3);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("obsolete"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(snapshot(), before);
        // More volumes rename them, which would orphan the old names too.
        code(&create("16"), 3);
        assert_eq!(snapshot(), before);

        // The same layout replaces every volume of the old set.
        ok(&create("8"));
        ok(&rarpar(
            &root.join("out"),
            &["--quiet", "par", "verify", "set.par2"],
        ));
    }

    #[test]
    fn par3_sidecars_of_7z_and_zip_verify_and_repair() {
        for (format, name) in [("7z", "set.7z"), ("zip", "set.zip")] {
            let dir = fixture();
            let root = dir.path();
            let target = format!("out/{name}");
            let report = archive(
                root,
                &[
                    "--format",
                    format,
                    "--sidecar",
                    "par3",
                    "-s",
                    "8192",
                    "-c",
                    "7",
                    &target,
                    "static.bin",
                    "ledger.txt",
                    "nested",
                ],
            );
            assert_eq!(report["set_format"], "par3");
            assert_eq!(report["read_back"], false);
            verify_damage_repair(&root.join("out"), "par3", "set.par3", name);
        }
    }

    #[test]
    fn an_archive_named_like_its_sidecar_index_is_refused() {
        let dir = fixture();
        let root = dir.path();
        for (format, set, sized) in [
            ("zip", "par2", &["-s", "8192", "-c", "2"][..]),
            ("zip", "par3", &["-s", "8192", "-c", "2"][..]),
            ("7z", "par3", &["-s", "8192", "-c", "2"][..]),
        ] {
            let target = format!("out/set.{set}");
            let mut args = vec![
                "--overwrite",
                "par3",
                "archive",
                "--base-path",
                "in",
                "--format",
                format,
                "--sidecar",
                set,
            ];
            args.extend_from_slice(sized);
            args.extend_from_slice(&[&target, "static.bin"]);
            code(&rarpar(root, &args), 2);
            assert!(!root.join(&target).exists());
        }
    }

    #[test]
    fn a_7z_par2_sidecar_is_refused_before_anything_is_written() {
        let dir = fixture();
        let root = dir.path();
        for extra in [
            &["--format", "7z"][..],
            &["--format", "zip", "-r", "10"][..],
        ] {
            let mut args = vec!["par3", "archive", "--base-path", "in", "--sidecar", "par2"];
            args.extend_from_slice(extra);
            args.extend_from_slice(&["out/set.7z", "static.bin"]);
            let output = rarpar(root, &args);
            code(&output, 2);
        }
        let output = rarpar(
            root,
            &[
                "par3",
                "archive",
                "--base-path",
                "in",
                "--sidecar",
                "par2",
                "out/set.7z",
                "static.bin",
            ],
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("start header"));
        assert!(!root.join("out").exists());
    }
}
