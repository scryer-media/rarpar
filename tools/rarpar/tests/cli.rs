use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarpar"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn fixture(parts: &[&str]) -> PathBuf {
    let mut path = repo_root();
    for part in parts {
        path.push(part);
    }
    path
}

fn copy_dir_recursive(source: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &dest_path);
        } else if file_type.is_file() {
            std::fs::copy(&source_path, &dest_path).unwrap();
        }
    }
}

fn run(args: &[&OsStr]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn run_in_dir(dir: &Path, args: &[&OsStr]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn run_with_input(args: &[&OsStr], input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn root_version_reports_rarpar_version() {
    let output = run(&[OsStr::new("--version")]);
    assert!(
        output.status.success(),
        "--version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("rarpar {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(!stdout.contains("UNRAR"));
}

#[test]
fn root_help_leads_with_natural_workflow() {
    let output = run(&[OsStr::new("--help")]);
    assert!(
        output.status.success(),
        "--help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rarpar <path>"));
    assert!(stdout.contains("rarpar inspect --json <path>"));
    assert!(stdout.contains("rarpar cleanup --dry-run <path>"));
    assert!(!stdout.contains("UNRAR"));
}

#[test]
fn command_help_documents_mutation_safety() {
    let auto = run(&[OsStr::new("auto"), OsStr::new("--help")]);
    assert!(
        auto.status.success(),
        "auto --help failed: {}",
        String::from_utf8_lossy(&auto.stderr)
    );
    let auto_stdout = String::from_utf8_lossy(&auto.stdout);
    assert!(auto_stdout.contains("verification enabled"));
    assert!(auto_stdout.contains("verified successful extraction"));

    let cleanup = run(&[OsStr::new("cleanup"), OsStr::new("--help")]);
    assert!(
        cleanup.status.success(),
        "cleanup --help failed: {}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    let cleanup_stdout = String::from_utf8_lossy(&cleanup.stdout);
    assert!(cleanup_stdout.contains("Validate expected extracted outputs"));
    assert!(cleanup_stdout.contains("dry-run"));
}

#[test]
fn par_help_documents_canonical_placement_mode() {
    let output = run(&[
        OsStr::new("par"),
        OsStr::new("verify"),
        OsStr::new("--help"),
    ]);
    assert!(
        output.status.success(),
        "par verify --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--par-placement"));
    assert!(stdout.contains("canonical"));
    assert!(stdout.contains("renamed or moved"));
}

#[test]
fn par_create_help_documents_output_and_file_contract() {
    let output = run(&[
        OsStr::new("par"),
        OsStr::new("create"),
        OsStr::new("--help"),
    ]);
    assert!(
        output.status.success(),
        "par create --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<OUTPUT>"));
    assert!(stdout.contains("<FILE>..."));
    assert!(stdout.contains("--block-size"));
    assert!(stdout.contains("--block-count"));
    assert!(stdout.contains("--recovery-percent"));
    assert!(stdout.contains("--recovery-count"));
    assert!(stdout.contains("--memory-mib"));
    assert!(stdout.contains("variable"));
    assert!(stdout.contains("uniform"));
    assert!(stdout.contains("limited"));
}

#[test]
fn par_create_rejects_missing_files_and_fractional_recovery_percent() {
    let missing_file = run(&[OsStr::new("par"), OsStr::new("create"), OsStr::new("set")]);
    assert_eq!(missing_file.status.code(), Some(2));

    let fractional_percent = run(&[
        OsStr::new("par"),
        OsStr::new("create"),
        OsStr::new("set"),
        OsStr::new("input.bin"),
        OsStr::new("--recovery-percent"),
        OsStr::new("5.5"),
    ]);
    assert_eq!(fractional_percent.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&fractional_percent.stderr).contains("invalid value"));
}

#[test]
fn par_create_rejects_volume_count_above_public_limit() {
    let output = run(&[
        OsStr::new("par"),
        OsStr::new("create"),
        OsStr::new("set"),
        OsStr::new("input.bin"),
        OsStr::new("--volume-count"),
        OsStr::new("32"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value"));
}

#[test]
fn par_create_dry_run_reports_real_plan_without_outputs() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("input.bin"), b"123456789").unwrap();
    let output_path = temp.path().join("set");

    let output = run_in_dir(
        temp.path(),
        &[
            OsStr::new("--dry-run"),
            OsStr::new("--json"),
            OsStr::new("par"),
            OsStr::new("create"),
            output_path.as_os_str(),
            OsStr::new("--block-size"),
            OsStr::new("4"),
            OsStr::new("--recovery-count"),
            OsStr::new("1"),
            OsStr::new("input.bin"),
        ],
    );
    assert!(
        output.status.success(),
        "dry-run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"], "create");
    assert_eq!(report["status"], "planned");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["plan"]["slice_size"], 4);
    assert_eq!(report["plan"]["file_count"], 1);
    assert_eq!(report["plan"]["volume_count"], 1);
    assert_eq!(report["plan"]["volume_scheme"], "variable");
    assert_eq!(report["plan"]["source_slice_count"], 3);
    assert_eq!(report["plan"]["recovery_count"], 1);
    assert_eq!(report["plan"]["sources"][0]["par2_name"], "input.bin");
    assert_eq!(
        report["plan"]["recovery_set_id"].as_str().unwrap().len(),
        32
    );
    assert!(report["plan"]["memory"]["controller_overhead_blocks"].is_number());
    assert!(report["plan"]["memory"]["critical_packet_bytes"].is_number());
    assert!(report["plan"]["memory"]["main_file_id_workspace_bytes"].is_number());
    assert!(report["plan"]["memory"]["packet_build_workspace_bytes"].is_number());
    assert!(report["plan"]["memory"]["validation_workspace_bytes"].is_number());
    assert!(report["plan"]["memory"]["total_creation_peak_bytes"].is_number());
    assert_eq!(report["plan"]["backend_selected"], "cpu");
    assert_eq!(report["outcome"]["backend_selected"], "cpu");
    assert_eq!(report["outcome"]["dry_run"], true);
    for path in report["plan"]["output_paths"].as_array().unwrap() {
        assert!(!Path::new(path.as_str().unwrap()).exists());
    }
}

#[test]
fn par_create_json_reports_real_outcome_and_writes_outputs() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("input.bin"), b"123456789").unwrap();
    let output_path = temp.path().join("set");

    let output = run_in_dir(
        temp.path(),
        &[
            OsStr::new("--json"),
            OsStr::new("par"),
            OsStr::new("create"),
            output_path.as_os_str(),
            OsStr::new("--block-size"),
            OsStr::new("4"),
            OsStr::new("--recovery-count"),
            OsStr::new("1"),
            OsStr::new("--volume-count"),
            OsStr::new("1"),
            OsStr::new("--volume-scheme"),
            OsStr::new("uniform"),
            OsStr::new("input.bin"),
        ],
    );
    assert!(
        output.status.success(),
        "create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "created");
    assert_eq!(report["dry_run"], false);
    assert_eq!(report["outcome"]["backend_requested"], "cpu");
    assert_eq!(report["outcome"]["backend_selected"], "cpu");
    assert_eq!(report["outcome"]["dry_run"], false);
    assert_eq!(report["outcome"]["recovery_count"], 1);
    assert!(report["outcome"]["bytes_written"].as_u64().unwrap() > 0);
    assert_eq!(
        report["outcome"]["output_paths"].as_array().unwrap().len(),
        2
    );
    for path in report["outcome"]["output_paths"].as_array().unwrap() {
        assert!(Path::new(path.as_str().unwrap()).is_file());
    }
}

#[test]
fn par_create_places_the_set_under_the_global_output_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("input.bin"), b"0123456789abcdef").unwrap();
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::write(root.join("data/other.bin"), b"fedcba9876543210").unwrap();
    std::fs::create_dir_all(root.join("sets")).unwrap();
    let create = |extra: &[&str]| {
        let mut args: Vec<&OsStr> = ["-o", "sets", "par", "create"]
            .iter()
            .chain(extra)
            .map(OsStr::new)
            .collect();
        args.extend(
            ["--block-size", "4", "--recovery-count", "1"]
                .iter()
                .map(OsStr::new),
        );
        run_in_dir(root, &args)
    };
    let succeeded = |output: &Output| {
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    // The set lands under -o; the input is still found beside OUTPUT as typed.
    succeeded(&create(&["set.par2", "input.bin"]));
    assert!(root.join("sets/set.par2").is_file());
    assert!(!root.join("set.par2").exists());
    let verify = run_in_dir(
        root,
        &[
            OsStr::new("par"),
            OsStr::new("verify"),
            OsStr::new("sets/set.par2"),
            OsStr::new("."),
        ],
    );
    succeeded(&verify);

    // An explicit --base-path is used as given, not moved under -o.
    succeeded(&create(&["--base-path", "data", "named.par2", "other.bin"]));
    assert!(root.join("sets/named.par2").is_file());
    assert!(!root.join("sets/data").exists());
    let verify = run_in_dir(
        root,
        &[
            OsStr::new("par"),
            OsStr::new("verify"),
            OsStr::new("sets/named.par2"),
            OsStr::new("data"),
        ],
    );
    succeeded(&verify);
}

#[test]
fn par_create_progress_reports_true_scan_totals_without_flooding() {
    let temp = tempfile::tempdir().unwrap();
    let sizes = [100_000usize, 50_000, 25_000];
    for (index, size) in sizes.iter().enumerate() {
        std::fs::write(
            temp.path().join(format!("input{index}.bin")),
            vec![index as u8 + 1; *size],
        )
        .unwrap();
    }
    let total_bytes: usize = sizes.iter().sum();
    let output_path = temp.path().join("set");

    // No --json/--quiet: progress goes to stderr. The source scan hashes
    // files concurrently; the callback must still end the scan phase on the
    // true cumulative byte count (a flush line, not a racy sample), and the
    // 250 ms throttle must hold (three progress-callback regressions in a
    // row shipped because nothing asserted on this output).
    let output = run_in_dir(
        temp.path(),
        &[
            OsStr::new("par"),
            OsStr::new("create"),
            output_path.as_os_str(),
            OsStr::new("--block-size"),
            OsStr::new("4096"),
            OsStr::new("--recovery-count"),
            OsStr::new("1"),
            OsStr::new("--volume-count"),
            OsStr::new("1"),
            OsStr::new("--volume-scheme"),
            OsStr::new("uniform"),
            OsStr::new("input0.bin"),
            OsStr::new("input1.bin"),
            OsStr::new("input2.bin"),
        ],
    );
    assert!(
        output.status.success(),
        "create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let progress_lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("create "))
        .collect();
    assert!(
        progress_lines
            .iter()
            .any(|line| line.contains(&format!("({total_bytes} bytes)"))),
        "no progress line reports the true scan total of {total_bytes} bytes: {progress_lines:?}"
    );
    assert!(
        progress_lines.len() <= 40,
        "progress flooded: {} lines",
        progress_lines.len()
    );
}

#[test]
fn par_create_rejects_existing_outputs_without_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("input.bin"), b"123456789").unwrap();
    let output_path = temp.path().join("set");
    let args = [
        OsStr::new("par"),
        OsStr::new("create"),
        output_path.as_os_str(),
        OsStr::new("--block-size"),
        OsStr::new("4"),
        OsStr::new("--recovery-count"),
        OsStr::new("1"),
        OsStr::new("--volume-count"),
        OsStr::new("1"),
        OsStr::new("input.bin"),
    ];

    let first = run_in_dir(temp.path(), &args);
    assert!(first.status.success());
    let main_path = temp.path().join("set.par2");
    let original = std::fs::read(&main_path).unwrap();

    let second = run_in_dir(temp.path(), &args);
    assert_eq!(second.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&second.stderr).contains("already exists"));
    assert_eq!(std::fs::read(&main_path).unwrap(), original);

    let overwritten = run_in_dir(
        temp.path(),
        &[
            OsStr::new("--overwrite"),
            OsStr::new("--quiet"),
            OsStr::new("par"),
            OsStr::new("create"),
            output_path.as_os_str(),
            OsStr::new("--block-size"),
            OsStr::new("4"),
            OsStr::new("--recovery-count"),
            OsStr::new("1"),
            OsStr::new("--volume-count"),
            OsStr::new("1"),
            OsStr::new("input.bin"),
        ],
    );
    assert!(overwritten.status.success());
    assert!(overwritten.stdout.is_empty());
    assert!(overwritten.stderr.is_empty());
    assert!(main_path.is_file());
}

#[test]
fn par_canonical_placement_does_not_scan_for_renamed_files() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    std::fs::rename(
        work_dir.join("fixture_rar5_lz_plain.part2.rar"),
        work_dir.join("relocated-volume"),
    )
    .unwrap();

    let canonical = run(&[
        OsStr::new("par"),
        OsStr::new("verify"),
        OsStr::new("--par-placement"),
        OsStr::new("canonical"),
        work_dir.as_os_str(),
    ]);
    assert!(
        !canonical.status.success(),
        "canonical placement must not hash-scan renamed files: stdout={} stderr={}",
        String::from_utf8_lossy(&canonical.stdout),
        String::from_utf8_lossy(&canonical.stderr)
    );

    let smart = run(&[
        OsStr::new("par"),
        OsStr::new("verify"),
        OsStr::new("--par-placement"),
        OsStr::new("smart"),
        work_dir.as_os_str(),
    ]);
    assert!(
        smart.status.success(),
        "smart placement should locate the renamed volume: stdout={} stderr={}",
        String::from_utf8_lossy(&smart.stdout),
        String::from_utf8_lossy(&smart.stderr)
    );
}

#[test]
fn inspect_detects_obfuscated_rar_by_magic_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let obfuscated = temp.path().join("download-piece-001");
    std::fs::copy(source, &obfuscated).unwrap();

    let output = run(&[
        std::ffi::OsStr::new("inspect"),
        std::ffi::OsStr::new("--json"),
        obfuscated.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["rar_sets"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["files"][0]["kind"]["rar_volume"]["files"][0],
        "small.txt"
    );
}

#[test]
fn rar_extract_writes_outputs_and_rejects_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let out_dir = temp.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    let first = run(&[
        std::ffi::OsStr::new("rar"),
        std::ffi::OsStr::new("extract"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        first.status.success(),
        "extract failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(out_dir.join("small.txt").is_file());

    let second = run(&[
        std::ffi::OsStr::new("rar"),
        std::ffi::OsStr::new("extract"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert_eq!(second.status.code(), Some(3));
}

#[test]
fn rar_extract_accepts_password_file() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_hp_store.rar",
    ]);
    let pass_file = temp.path().join("passwords.txt");
    std::fs::write(&pass_file, "wrong\nsecretpass\n").unwrap();
    let out_dir = temp.path().join("out");

    let output = run(&[
        std::ffi::OsStr::new("--password-file"),
        pass_file.as_os_str(),
        std::ffi::OsStr::new("rar"),
        std::ffi::OsStr::new("extract"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "encrypted extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("small.txt").is_file());
}

#[test]
fn auto_permanent_delete_removes_consumed_sources_after_success() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let archive = temp.path().join("rar5_store.rar");
    std::fs::copy(source, &archive).unwrap();

    let output = run(&[
        std::ffi::OsStr::new("auto"),
        std::ffi::OsStr::new("--delete-sources"),
        std::ffi::OsStr::new("--permanent-delete"),
        archive.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "auto cleanup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!archive.exists(), "source archive should be deleted");
    assert!(temp.path().join("small.txt").is_file());
}

#[test]
fn auto_json_outputs_single_final_report() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let archive = temp.path().join("rar5_store.rar");
    std::fs::copy(source, &archive).unwrap();

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--json"),
        archive.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "auto --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout should be a single JSON document: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(json["executed_actions"].as_array().unwrap().len(), 1);
    assert_eq!(json["executed_actions"][0]["action"], "rar_extract");
    assert!(temp.path().join("small.txt").is_file());
}

#[test]
fn auto_extracts_classic_multivolume_ppmd_set() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let download_dir = temp.path().join("download");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&download_dir).unwrap();
    for name in [
        "rar4_ppm_oldmv.rar",
        "rar4_ppm_oldmv.r00",
        "rar4_ppm_oldmv.r01",
        "rar4_ppm_oldmv.r02",
    ] {
        std::fs::copy(fixture_dir.join(name), download_dir.join(name)).unwrap();
    }

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--output"),
        out_dir.as_os_str(),
        download_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "classic PPMd volume extraction failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(out_dir.join("ppmd-oldmv.txt")).unwrap();
    assert_eq!(bytes.len(), 256 * 1024);
    assert_eq!(&bytes[..16], b"cevAd36NmwQavaFb");
}

#[test]
fn auto_rediscovers_rar_volumes_after_par2_repair() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    let missing_volume = work_dir.join("fixture_rar5_lz_plain.part2.rar");
    std::fs::remove_file(&missing_volume).unwrap();

    let output = run(&[OsStr::new("auto"), work_dir.as_os_str()]);
    assert!(
        output.status.success(),
        "auto repair/extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        missing_volume.is_file(),
        "PAR2 repair should recreate the missing RAR volume"
    );
    assert!(work_dir.join("rar5_lz_plain_clip.mkv").is_file());
}

#[test]
fn par_repair_dry_run_does_not_create_missing_file() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    let missing_volume = work_dir.join("fixture_rar5_lz_plain.part2.rar");
    std::fs::remove_file(&missing_volume).unwrap();

    let output = run(&[
        OsStr::new("--dry-run"),
        OsStr::new("par"),
        OsStr::new("repair"),
        work_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "dry-run repair failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !missing_volume.exists(),
        "dry-run must not recreate missing files"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("dry-run: would repair"));
}

#[test]
fn par_repair_accepts_relative_par2_file_and_emits_json() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);

    let output = run_in_dir(
        &work_dir,
        &[
            OsStr::new("--json"),
            OsStr::new("par"),
            OsStr::new("repair"),
            OsStr::new("fixture_rar5_lz_plain_repair.par2"),
        ],
    );
    assert!(
        output.status.success(),
        "relative PAR2 repair failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "repair");
    assert_eq!(report["success"], true);
    assert_eq!(report["repaired"], false);
    assert!(report["recovery_blocks_needed"].is_null());
}

#[test]
fn sab_par2_repair_invocation_accepts_a_healthy_set() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    let par2_path = work_dir.join("fixture_rar5_lz_plain_repair.par2");
    let wildcard = work_dir.join("fixture_rar5_lz_plain*");

    let output = run(&[
        OsStr::new("r"),
        OsStr::new("-t6"),
        par2_path.as_os_str(),
        wildcard.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "SAB PAR2 invocation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "All files are correct"
    );
}

#[test]
fn sab_par2_repair_invocation_accepts_a_recovery_volume_as_parfile() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    std::fs::remove_file(work_dir.join("fixture_rar5_lz_plain.part2.rar")).unwrap();

    let output = run(&[
        OsStr::new("r"),
        OsStr::new("-t6"),
        work_dir
            .join("fixture_rar5_lz_plain_repair.vol00+2.par2")
            .as_os_str(),
        work_dir.join("fixture_rar5_lz_plain*").as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "SAB PAR2 recovery-volume invocation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Repair is required"));
    assert!(stdout.contains("Repair is possible"));
    assert!(stdout.contains("Repair complete"));
    assert!(work_dir.join("fixture_rar5_lz_plain.part2.rar").is_file());
}

#[test]
fn sab_par2_repair_invocation_requests_missing_recovery_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    std::fs::remove_file(work_dir.join("fixture_rar5_lz_plain.part2.rar")).unwrap();
    for entry in std::fs::read_dir(&work_dir).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains(".vol"))
        {
            std::fs::remove_file(path).unwrap();
        }
    }

    let output = run(&[
        OsStr::new("r"),
        OsStr::new("-t6"),
        work_dir
            .join("fixture_rar5_lz_plain_repair.par2")
            .as_os_str(),
        work_dir.join("fixture_rar5_lz_plain*").as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("You need ")
            && String::from_utf8_lossy(&output.stdout).contains("to be able to repair."),
        "unexpected downloader output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let json = run(&[
        OsStr::new("--json"),
        OsStr::new("par"),
        OsStr::new("repair"),
        work_dir.as_os_str(),
    ]);
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert!(report["recovery_blocks_needed"].as_u64().is_some());
}

#[test]
fn rar_extract_retries_member_wrong_password_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_enc_store.rar",
    ]);
    let pass_file = temp.path().join("passwords.txt");
    std::fs::write(&pass_file, "wrong\ntestpass123\n").unwrap();
    let out_dir = temp.path().join("out");

    let output = run(&[
        OsStr::new("--password-file"),
        pass_file.as_os_str(),
        OsStr::new("rar"),
        OsStr::new("extract"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "member-encrypted extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("small.txt").is_file());
}

#[cfg(unix)]
#[test]
fn cleanup_rejects_wrong_symlink_output() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_symlink.rar",
    ]);
    let archive = temp.path().join("rar5_symlink.rar");
    std::fs::copy(source, &archive).unwrap();

    let extract = run(&[
        OsStr::new("rar"),
        OsStr::new("extract"),
        archive.as_os_str(),
        temp.path().as_os_str(),
    ]);
    assert!(
        extract.status.success(),
        "symlink fixture extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&extract.stdout),
        String::from_utf8_lossy(&extract.stderr)
    );
    let link = temp.path().join("link_to_hello.txt");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    std::fs::remove_file(&link).unwrap();
    std::fs::write(&link, b"not a symlink").unwrap();

    let cleanup = run(&[
        OsStr::new("cleanup"),
        OsStr::new("--permanent-delete"),
        archive.as_os_str(),
    ]);
    assert_eq!(
        cleanup.status.code(),
        Some(1),
        "cleanup should fail validation: stdout={} stderr={}",
        String::from_utf8_lossy(&cleanup.stdout),
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(
        archive.exists(),
        "source archive must remain after failed cleanup validation"
    );
}

#[test]
fn compat_unrar_no_args_does_not_emit_unrar_banner() {
    let output = Command::new(bin()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("UNRAR"), "stdout was {stdout}");
    assert!(!stderr.contains("UNRAR"), "stderr was {stderr}");
}

#[test]
fn compat_unrar_extract_emits_downloader_contract() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let out_dir = temp.path().join("out");

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-idp"),
        OsStr::new("-scf"),
        OsStr::new("-o+"),
        OsStr::new("-ai"),
        OsStr::new("-p-"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "compat extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Extracting from "));
    assert!(stdout.contains("Extracting  "));
    assert!(stdout.contains(" OK"));
    assert!(stdout.contains("All OK"));
    assert!(!stdout.contains("UNRAR"));
    assert!(out_dir.join("small.txt").is_file());
}

#[test]
fn compat_unrar_extract_accepts_relative_archive_path() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();
    for volume in 1..=5 {
        let name = format!("rar4_tiny_volumes.part{volume}.rar");
        std::fs::copy(fixture_dir.join(&name), download_dir.join(name)).unwrap();
    }
    let out_dir = temp.path().join("out");

    let output = run_in_dir(
        &download_dir,
        &[
            OsStr::new("x"),
            OsStr::new("-o+"),
            OsStr::new("rar4_tiny_volumes.part1.rar"),
            out_dir.as_os_str(),
        ],
    );
    assert!(
        output.status.success(),
        "relative compat extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("random_4k.bin").is_file());
}

#[test]
fn compat_unrar_extract_accepts_bare_relative_wildcard() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();
    for volume in 1..=5 {
        let name = format!("rar4_tiny_volumes.part{volume}.rar");
        std::fs::copy(fixture_dir.join(&name), download_dir.join(name)).unwrap();
    }
    let out_dir = temp.path().join("out");

    let output = run_in_dir(
        &download_dir,
        &[
            OsStr::new("x"),
            OsStr::new("-o+"),
            OsStr::new("*.rar"),
            out_dir.as_os_str(),
        ],
    );
    assert!(
        output.status.success(),
        "wildcard compat extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("random_4k.bin").is_file());
}

#[test]
fn compat_unrar_extracts_header_encrypted_multivolume_set() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();
    for volume in 1..=5 {
        let name = format!("rar5_enc_mv_store.part{volume}.rar");
        std::fs::copy(fixture_dir.join(&name), download_dir.join(name)).unwrap();
    }
    let archive = download_dir.join("rar5_enc_mv_store.part1.rar");
    let out_dir = temp.path().join("out");

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-o+"),
        OsStr::new("-ptestpass123"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "encrypted multivolume extraction failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("binary.bin").is_file());
}

#[test]
fn compat_unrar_extract_restores_missing_recovery_volume() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();
    let present = [
        "rar5_recovery_volumes.part01.rar",
        "rar5_recovery_volumes.part02.rar",
        "rar5_recovery_volumes.part03.rar",
        "rar5_recovery_volumes.part04.rar",
        "rar5_recovery_volumes.part06.rar",
        "rar5_recovery_volumes.part07.rar",
        "rar5_recovery_volumes.part08.rar",
        "rar5_recovery_volumes.part09.rar",
        "rar5_recovery_volumes.part10.rar",
        "rar5_recovery_volumes.part01.rev",
        "rar5_recovery_volumes.part02.rev",
    ];
    for name in present {
        std::fs::copy(fixture_dir.join(name), download_dir.join(name)).unwrap();
    }
    let archive = download_dir.join("rar5_recovery_volumes.part01.rar");
    let restored = download_dir.join("rar5_recovery_volumes.part05.rar");
    let out_dir = temp.path().join("out");

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-o+"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "recovery-volume extraction failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(restored.is_file());
    assert!(out_dir.join("payload.bin").is_file());
}

#[test]
fn compat_unrar_lb_lists_bare_member_names() {
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);

    let output = run(&[OsStr::new("lb"), archive.as_os_str()]);
    assert!(
        output.status.success(),
        "compat list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "small.txt\n");
}

#[test]
fn compat_unrar_overwrite_skip_preserves_existing_file() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("small.txt"), b"keep me").unwrap();

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-o-"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "compat skip failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("small.txt")).unwrap(),
        b"keep me"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("All OK"));
}

#[test]
fn compat_unrar_wrong_password_uses_unrar_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_hp_store.rar",
    ]);

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-pwrong"),
        archive.as_os_str(),
        temp.path().as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(11),
        "wrong password should use UnRAR password exit: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("password is incorrect"));
}

#[test]
fn compat_unrar_incremental_vp_continue_extracts_after_later_volumes_arrive() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&download_dir).unwrap();

    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let first = download_dir.join("rar4_tiny_volumes.part1.rar");
    std::fs::copy(fixture_dir.join("rar4_tiny_volumes.part1.rar"), &first).unwrap();

    let mut child = Command::new(bin())
        .args([
            OsStr::new("x"),
            OsStr::new("-vp"),
            OsStr::new("-o+"),
            first.as_os_str(),
            out_dir.as_os_str(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn({
        let fixture_dir = fixture_dir.clone();
        let download_dir = download_dir.clone();
        move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            for volume in 2..=5 {
                let name = format!("rar4_tiny_volumes.part{volume}.rar");
                std::fs::copy(fixture_dir.join(&name), download_dir.join(&name)).unwrap();
            }
            stdin.write_all(b"C\nC\nC\nC\n").unwrap();
        }
    });

    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "incremental compat extract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Insert disk with "));
    assert!(stdout.contains("[C]ontinue, [Q]uit "));
    assert!(stdout.contains("All OK"));
    assert!(out_dir.join("random_4k.bin").is_file());
}

#[test]
fn compat_unrar_incremental_vp_quit_exits_fatal() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();

    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let first = download_dir.join("rar4_tiny_volumes.part1.rar");
    std::fs::copy(fixture_dir.join("rar4_tiny_volumes.part1.rar"), &first).unwrap();

    let output = run_with_input(
        &[
            OsStr::new("x"),
            OsStr::new("-vp"),
            OsStr::new("-o+"),
            first.as_os_str(),
            temp.path().as_os_str(),
        ],
        b"Q\n",
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "incremental quit should be fatal: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[C]ontinue, [Q]uit "));
    assert!(stdout.contains("User break"));
    assert!(!stdout.contains("All OK"));
}

#[test]
fn default_path_invocation_runs_auto_workflow() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let archive = temp.path().join("release.rar");
    std::fs::copy(source, &archive).unwrap();

    let output = run(&[archive.as_os_str()]);
    assert!(
        output.status.success(),
        "default auto invocation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temp.path().join("small.txt").is_file());
}

#[test]
fn rar_list_and_test_validate_a_real_archive() {
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);

    let list = run(&[OsStr::new("rar"), OsStr::new("list"), archive.as_os_str()]);
    assert!(
        list.status.success(),
        "rar list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&list.stdout), "small.txt\n");

    let test = run(&[OsStr::new("rar"), OsStr::new("test"), archive.as_os_str()]);
    assert!(
        test.status.success(),
        "rar test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );
}

/// Run `rarpar` from `dir` with `--password-file pass_file`.
fn run_in_dir_with_password_file(dir: &Path, pass_file: &Path, args: &[&OsStr]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .arg("--password-file")
        .arg(pass_file)
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rar_list_and_test_follow_the_volume_chain() {
    // Two members over nine volumes, the second starting in volume 5: naming
    // the first volume has to reach the second member and every volume of
    // both.
    let first = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_mv_store_pair.part01.rar",
    ]);
    let list = run(&[OsStr::new("rar"), OsStr::new("list"), first.as_os_str()]);
    assert_success(&list, "rar list");
    assert_eq!(
        String::from_utf8_lossy(&list.stdout),
        "Silver.Horizon.S02E01.mkv\nSilver.Horizon.S02E02.mkv\n"
    );
    let test = run(&[OsStr::new("rar"), OsStr::new("test"), first.as_os_str()]);
    assert_success(&test, "rar test of a RAR5 volume set");

    let first = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar4",
        "rar4_tiny_volumes.part1.rar",
    ]);
    let test = run(&[OsStr::new("rar"), OsStr::new("test"), first.as_os_str()]);
    assert_success(&test, "rar test of a RAR4 volume set");
}

#[test]
fn rar_list_and_test_refuse_a_missing_archive_as_missing_input() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("absent.rar");
    for command in ["list", "test"] {
        let output = run(&[OsStr::new("rar"), OsStr::new(command), missing.as_os_str()]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "rar {command}: {stderr}");
        assert!(
            stderr.contains(&format!("input path does not exist: {}", missing.display())),
            "rar {command}: {stderr}"
        );
    }
}

#[test]
fn rar_list_and_test_take_the_volume_set_under_another_case_of_its_name() {
    // Named `SET.part01.rar` over volumes stored as `set.partNN.rar`, the set
    // is all nine volumes where the filesystem ignores case. Where it does
    // not, no file has the uppercase name.
    let temp = tempfile::tempdir().unwrap();
    let rar5 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    for volume in 1..=9 {
        std::fs::copy(
            rar5.join(format!("rar5_mv_store_pair.part{volume:02}.rar")),
            temp.path().join(format!("set.part{volume:02}.rar")),
        )
        .unwrap();
    }
    let named = temp.path().join("SET.part01.rar");
    if std::fs::File::open(&named).is_err() {
        eprintln!("skipping test: this filesystem tells SET.part01.rar from set.part01.rar");
        return;
    }

    let list = run(&[OsStr::new("rar"), OsStr::new("list"), named.as_os_str()]);
    assert_success(&list, "rar list");
    assert_eq!(
        String::from_utf8_lossy(&list.stdout),
        "Silver.Horizon.S02E01.mkv\nSilver.Horizon.S02E02.mkv\n"
    );
    let test = run(&[OsStr::new("rar"), OsStr::new("test"), named.as_os_str()]);
    assert_success(&test, "rar test");
}

/// On APFS as macOS formats it by default, which ignores case, volumes stored
/// under three spellings of the set's name are one set, as the filesystem
/// itself treats them.
#[cfg(target_os = "macos")]
#[test]
fn rar_list_on_apfs_joins_volumes_stored_under_mixed_case_names() {
    let temp = tempfile::tempdir().unwrap();
    let rar5 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    let spellings = ["set", "Set", "SET"];
    for volume in 1..=9 {
        std::fs::copy(
            rar5.join(format!("rar5_mv_store_pair.part{volume:02}.rar")),
            temp.path()
                .join(format!("{}.part{volume:02}.rar", spellings[volume % 3])),
        )
        .unwrap();
    }
    if std::fs::File::open(temp.path().join("sEt.part01.rar")).is_err() {
        eprintln!("skipping test: this APFS volume is case-sensitive");
        return;
    }
    let named = temp.path().join("sEt.part01.rar");
    let list = run(&[OsStr::new("rar"), OsStr::new("list"), named.as_os_str()]);
    assert_success(&list, "rar list");
    assert_eq!(
        String::from_utf8_lossy(&list.stdout),
        "Silver.Horizon.S02E01.mkv\nSilver.Horizon.S02E02.mkv\n"
    );
}

#[test]
fn rar_test_decrypts_a_member_split_across_volumes() {
    // One encrypted member over five volumes: tested from the first volume
    // alone, its packed data stops at a size that is not a whole number of
    // AES blocks.
    let temp = tempfile::tempdir().unwrap();
    let pass_file = temp.path().join("passwords.txt");
    std::fs::write(&pass_file, "testpass123\n").unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let test = run_in_dir_with_password_file(
        &fixture_dir,
        &pass_file,
        &[
            OsStr::new("rar"),
            OsStr::new("test"),
            OsStr::new("rar4_enc_mv_store.part1.rar"),
        ],
    );
    assert_success(&test, "rar test of an encrypted RAR4 volume set");
}

#[test]
fn rar_commands_accept_a_bare_archive_name() {
    let temp = tempfile::tempdir().unwrap();
    let rar4 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let rar5 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    for volume in 1..=5 {
        let name = format!("rar4_tiny_volumes.part{volume}.rar");
        std::fs::copy(rar4.join(&name), temp.path().join(name)).unwrap();
    }
    std::fs::copy(
        rar5.join("rar5_hp_store.rar"),
        temp.path().join("rar5_hp_store.rar"),
    )
    .unwrap();
    let pass_file = temp.path().join("passwords.txt");
    std::fs::write(&pass_file, "secretpass\n").unwrap();

    // A header-encrypted archive and a volume set both make discovery list
    // the archive's directory, which a bare name's empty parent is not.
    for (archive, member) in [
        ("rar4_tiny_volumes.part1.rar", "random_4k.bin"),
        ("rar5_hp_store.rar", "small.txt"),
    ] {
        let out = format!("out-{archive}");
        for args in [
            vec!["rar", "list", archive],
            vec!["rar", "test", archive],
            vec!["rar", "extract", archive, out.as_str()],
        ] {
            let args = args.iter().map(OsStr::new).collect::<Vec<_>>();
            let output = run_in_dir_with_password_file(temp.path(), &pass_file, &args);
            assert_success(&output, &format!("{args:?}"));
        }
        assert!(temp.path().join(&out).join(member).is_file());
    }
}

#[test]
fn rar_restore_volumes_restores_a_missing_volume_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    let download_dir = temp.path().join("download");
    std::fs::create_dir_all(&download_dir).unwrap();
    for name in [
        "rar5_recovery_volumes.part01.rar",
        "rar5_recovery_volumes.part02.rar",
        "rar5_recovery_volumes.part03.rar",
        "rar5_recovery_volumes.part04.rar",
        "rar5_recovery_volumes.part06.rar",
        "rar5_recovery_volumes.part07.rar",
        "rar5_recovery_volumes.part08.rar",
        "rar5_recovery_volumes.part09.rar",
        "rar5_recovery_volumes.part10.rar",
        "rar5_recovery_volumes.part01.rev",
        "rar5_recovery_volumes.part02.rev",
    ] {
        std::fs::copy(fixture_dir.join(name), download_dir.join(name)).unwrap();
    }
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let restored = download_dir.join("rar5_recovery_volumes.part05.rar");

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        first.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "explicit volume restore failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(restored.is_file());
}

/// Copy the ten RAR5 data volumes of `rar5_recovery_volumes` and its two
/// `.rev` files into `dir`.
fn copy_rar5_recovery_set(dir: &Path) {
    let rar5 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    std::fs::create_dir_all(dir).unwrap();
    let volumes = (1..=10).map(|volume| format!("rar5_recovery_volumes.part{volume:02}.rar"));
    let revs = (1..=2).map(|volume| format!("rar5_recovery_volumes.part{volume:02}.rev"));
    for name in volumes.chain(revs) {
        std::fs::copy(rar5.join(&name), dir.join(&name)).unwrap();
    }
}

/// Invert the byte of `path` that `at` picks from the file's length, in a
/// test's own copy of a fixture.
fn flip_byte(path: &Path, at: impl FnOnce(usize) -> usize) {
    let mut bytes = std::fs::read(path).unwrap();
    let offset = at(bytes.len());
    bytes[offset] ^= 0xff;
    std::fs::write(path, bytes).unwrap();
}

/// The names in `dir`, sorted, to show a dry run left it as it was.
fn listing(dir: &Path) -> Vec<std::ffi::OsString> {
    let mut names = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_data_failure(output: &Output, what: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{what}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rar_test_volumes_checks_each_named_recovery_volume() {
    let temp = tempfile::tempdir().unwrap();
    copy_rar5_recovery_set(temp.path());
    let rar4 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    let rar3_rev = temp.path().join("rar3_recovery_volumes.part1.rev");
    std::fs::copy(rar4.join("rar3_recovery_volumes.part1.rev"), &rar3_rev).unwrap();
    let first = temp.path().join("rar5_recovery_volumes.part01.rev");
    let second = temp.path().join("rar5_recovery_volumes.part02.rev");
    let volume = temp.path().join("rar5_recovery_volumes.part01.rar");
    let missing = temp.path().join("rar5_recovery_volumes.part03.rev");

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("test-volumes"),
        first.as_os_str(),
        second.as_os_str(),
    ]);
    assert_success(&output, "rar test-volumes");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}: OK\n{}: OK\n", first.display(), second.display())
    );

    // A RAR5 .rev's CRC32 covers everything after its header, the last byte
    // included.
    flip_byte(&second, |len| len - 1);
    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("test-volumes"),
        first.as_os_str(),
        second.as_os_str(),
        volume.as_os_str(),
        missing.as_os_str(),
        rar3_rev.as_os_str(),
    ]);
    assert_data_failure(&output, "rar test-volumes --json over a damaged .rev");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "rar_test_volumes");
    assert_eq!(report["success"], false);
    let results = report["results"].as_array().unwrap();
    let statuses = results
        .iter()
        .map(|result| {
            (
                result["path"].as_str().unwrap().to_string(),
                result["format"].as_str(),
                result["status"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        [
            (first.display().to_string(), Some("rar5"), "ok"),
            (second.display().to_string(), Some("rar5"), "crc_mismatch"),
            (volume.display().to_string(), None, "not_recovery_volume"),
            (missing.display().to_string(), None, "missing"),
            (rar3_rev.display().to_string(), Some("rar4"), "ok"),
        ]
    );
    assert!(results[0]["expected_crc32"].is_null() && results[0]["actual_crc32"].is_null());
    let expected = results[1]["expected_crc32"].as_u64().unwrap();
    let actual = results[1]["actual_crc32"].as_u64().unwrap();
    assert_ne!(expected, actual);

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("test-volumes"),
        first.as_os_str(),
        second.as_os_str(),
        volume.as_os_str(),
        missing.as_os_str(),
    ]);
    assert_data_failure(&output, "rar test-volumes over a damaged .rev");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "{}: OK\n{}: CRC32 mismatch (expected {expected:08x}, actual {actual:08x})\n\
             {}: not a recovery volume\n{}: missing\n",
            first.display(),
            second.display(),
            volume.display(),
            missing.display()
        )
    );
}

#[test]
fn rar_restore_volumes_dry_run_plans_without_writing() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let missing = download_dir.join("rar5_recovery_volumes.part05.rar");
    std::fs::remove_file(&missing).unwrap();
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let before = listing(&download_dir);

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --dry-run");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "would restore 1 volume(s) (rar5_recovery_volumes.part05.rar) using 1 of 2 usable \
         recovery volume(s)\n"
    );
    assert_eq!(listing(&download_dir), before);

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --dry-run --json");
    assert_eq!(listing(&download_dir), before);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "rar_restore_volumes");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["success"], true);
    assert!(report["outcome"].is_null());
    let plan = &report["plan"];
    assert_eq!(plan["format"], "rar5");
    assert_eq!(plan["data_count"], 10);
    assert_eq!(plan["recovery_count"], 2);
    assert_eq!(plan["needed"], 1);
    assert_eq!(plan["usable_recovery_count"], 2);
    assert_eq!(plan["sufficient"], true);
    let data_volumes = plan["data_volumes"].as_array().unwrap();
    assert_eq!(data_volumes.len(), 10);
    let rebuilt = data_volumes
        .iter()
        .filter(|volume| volume["status"] != "valid")
        .collect::<Vec<_>>();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0]["index"], 4);
    assert_eq!(rebuilt[0]["status"], "missing");
    assert!(rebuilt[0]["path"].is_null());
    assert_eq!(rebuilt[0]["output_path"], missing.display().to_string());
    assert!(rebuilt[0]["set_aside_path"].is_null());
    let recovery_volumes = plan["recovery_volumes"].as_array().unwrap();
    assert_eq!(recovery_volumes.len(), 2);
    assert!(
        recovery_volumes
            .iter()
            .all(|volume| volume["status"] == "ok" && volume["usable"] == true)
    );
    // Volume numbers count the ten data volumes first.
    let numbers = recovery_volumes
        .iter()
        .map(|volume| (volume["slot"].as_u64(), volume["volume_number"].as_u64()))
        .collect::<Vec<_>>();
    assert_eq!(numbers, [(Some(0), Some(10)), (Some(1), Some(11))]);
}

#[test]
fn rar_restore_volumes_json_reports_the_restore() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let missing = download_dir.join("rar5_recovery_volumes.part05.rar");
    std::fs::remove_file(&missing).unwrap();
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --json");
    assert!(missing.is_file());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"], "rar_restore_volumes");
    assert_eq!(report["dry_run"], false);
    assert_eq!(report["success"], true);
    assert_eq!(
        report["message"],
        "restored 1 volume(s) (rar5_recovery_volumes.part05.rar) from 2 recovery volume(s) read"
    );
    assert!(report["plan"].is_null());
    let outcome = &report["outcome"];
    assert_eq!(
        outcome["restored_paths"],
        serde_json::json!([missing.display().to_string()])
    );
    assert_eq!(outcome["missing_volume_numbers"], serde_json::json!([4]));
    assert_eq!(outcome["used_recovery_paths"].as_array().unwrap().len(), 2);

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes over a whole set");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "nothing to restore: all data volumes valid\n"
    );
}

#[test]
fn rar_restore_volumes_dry_run_fails_short_of_recovery_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    for name in [
        "rar5_recovery_volumes.part03.rar",
        "rar5_recovery_volumes.part07.rar",
    ] {
        flip_byte(&download_dir.join(name), |len| len / 2);
    }
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let before = listing(&download_dir);

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_data_failure(&output, "rar restore-volumes --dry-run short of .rev files");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "insufficient recovery volumes: need 3, have 2 for rar5_recovery_volumes.part03.rar, \
         rar5_recovery_volumes.part05.rar, rar5_recovery_volumes.part07.rar\n"
    );

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_data_failure(
        &output,
        "rar restore-volumes --dry-run --json short of .rev files",
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert_eq!(report["plan"]["sufficient"], false);
    assert_eq!(report["plan"]["needed"], 3);
    assert_eq!(report["plan"]["usable_recovery_count"], 2);
    let statuses = report["plan"]["data_volumes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|volume| volume["status"] != "valid")
        .map(|volume| {
            (
                volume["index"].as_u64().unwrap(),
                volume["status"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        [(2, "crc_mismatch"), (4, "missing"), (6, "crc_mismatch")]
    );
    assert_eq!(listing(&download_dir), before);
}

#[test]
fn auto_dry_run_fails_a_set_short_of_recovery_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    for name in [
        "rar5_recovery_volumes.part03.rar",
        "rar5_recovery_volumes.part07.rar",
    ] {
        flip_byte(&download_dir.join(name), |len| len / 2);
    }
    let before = listing(&download_dir);

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        download_dir.as_os_str(),
    ]);
    assert_data_failure(&output, "auto --dry-run short of .rev files");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(
            "dry-run rar_restore_volumes [failed]: insufficient recovery volumes: need 3, have 2"
        ),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
        download_dir.as_os_str(),
    ]);
    assert_data_failure(&output, "auto --dry-run --json short of .rev files");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    let actions = report["executed_actions"].as_array().unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["action"], "rar_restore_volumes");
    assert_eq!(actions[0]["success"], false);
    assert!(actions[0].get("deferred_to").is_none());
    assert!(
        actions[0]["message"]
            .as_str()
            .unwrap()
            .starts_with("insufficient recovery volumes: need 3, have 2 for ")
    );
    assert_eq!(listing(&download_dir), before);
}

/// The names of `rar5_recovery_volumes` data volumes `numbers`.
fn rar5_volume_names(numbers: impl IntoIterator<Item = usize>) -> Vec<String> {
    numbers
        .into_iter()
        .map(|volume| format!("rar5_recovery_volumes.part{volume:02}.rar"))
        .collect()
}

/// Create a `PAR2` or `PAR3` set named `set` in `dir` over `files`, with 16
/// recovery blocks of 256 bytes: enough to rebuild any three of the
/// `rar5_recovery_volumes` data volumes.
fn create_parity(dir: &Path, parity: &str, files: &[String]) {
    create_parity_with(dir, parity, files, 16);
}

/// [`create_parity`] with `recovery_count` recovery blocks; one is short of
/// any damaged `rar5_recovery_volumes` data volume.
fn create_parity_with(dir: &Path, parity: &str, files: &[String], recovery_count: usize) {
    let recovery_count = recovery_count.to_string();
    let mut create = match parity {
        "PAR2" => vec![
            "--quiet",
            "par",
            "create",
            "set",
            "--block-size",
            "256",
            "--recovery-count",
            &recovery_count,
        ],
        _ => vec![
            "--quiet",
            "par3",
            "create",
            "set",
            "-s",
            "256",
            "-c",
            &recovery_count,
        ],
    };
    create.extend(files.iter().map(String::as_str));
    let create = create.into_iter().map(OsStr::new).collect::<Vec<_>>();
    assert_success(&run_in_dir(dir, &create), parity);
}

/// Remove volume 5 of the RAR5 set in `dir` and damage volumes 3 and 7: one
/// volume more than its two `.rev` files restore.
fn damage_three_rar5_volumes(dir: &Path) {
    std::fs::remove_file(dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    for name in rar5_volume_names([3, 7]) {
        flip_byte(&dir.join(name), |len| len / 2);
    }
}

/// `auto --dry-run --json` over `dir`, with its exit code and its steps.
fn auto_dry_run_steps(dir: &Path) -> (Option<i32>, Vec<serde_json::Value>) {
    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
        dir.as_os_str(),
    ]);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "auto --dry-run --json: {error}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(report["dry_run"], true);
    let actions = report["executed_actions"].as_array().unwrap().clone();
    (output.status.code(), actions)
}

/// `auto --dry-run --json` over `dir`, with its exit code and its one
/// restore step; every parity step before it passes.
fn auto_dry_run_restore_step(dir: &Path) -> (Option<i32>, serde_json::Value) {
    let (code, actions) = auto_dry_run_steps(dir);
    let (restores, parity): (Vec<_>, Vec<_>) = actions
        .iter()
        .partition(|action| action["action"] == "rar_restore_volumes");
    assert_eq!(restores.len(), 1, "{actions:?}");
    for step in parity {
        assert!(
            step["action"].as_str().unwrap().contains("par")
                && step["success"] == true
                && step.get("deferred_to").is_none(),
            "{step}"
        );
    }
    (code, restores[0].clone())
}

/// A parity set short of the recovery data its damaged volumes need fails
/// the real run at its repair, before any restore, so the dry run assesses
/// each repair the same way and fails the parity step and the restore it
/// would otherwise have deferred, instead of passing on the volumes the set
/// merely lists.
#[test]
fn auto_dry_run_fails_a_restore_deferred_to_parity_short_of_recovery_data() {
    let damaged = rar5_volume_names([3, 5, 7]).join(", ");
    for (parity, step) in [
        ("PAR2", "par_verify_repair"),
        ("PAR3", "par3_verify_repair"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let download_dir = temp.path().join("download");
        copy_rar5_recovery_set(&download_dir);
        create_parity_with(&download_dir, parity, &rar5_volume_names(1..=10), 1);
        damage_three_rar5_volumes(&download_dir);
        let before = listing(&download_dir);

        let (code, actions) = auto_dry_run_steps(&download_dir);
        assert_eq!(code, Some(1), "auto --dry-run with {parity}: {actions:?}");
        let steps = actions
            .iter()
            .map(|action| {
                (
                    action["action"].as_str().unwrap(),
                    action["success"].as_bool().unwrap(),
                    action.get("deferred_to").cloned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            steps,
            [(step, false, None), ("rar_restore_volumes", false, None)],
            "{actions:?}"
        );
        assert_eq!(
            actions[1]["message"],
            format!("insufficient recovery volumes: need 3, have 2 for {damaged}")
        );
        let output = run(&[
            OsStr::new("auto"),
            OsStr::new("--dry-run"),
            download_dir.as_os_str(),
        ]);
        assert_data_failure(&output, &format!("auto --dry-run with {parity}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("dry-run {step} [failed]: "))
                && stdout.contains(
                    "dry-run rar_restore_volumes [failed]: insufficient recovery volumes"
                ),
            "{stdout}"
        );
        assert_eq!(listing(&download_dir), before, "the dry run wrote a file");

        let out_dir = temp.path().join("out");
        assert_data_failure(
            &auto_into(&download_dir, &out_dir),
            &format!("auto with {parity}"),
        );
    }
}

/// The real run repairs with PAR3, then PAR2, then reassesses the PAR3 sets
/// that were short, so a PAR3 set short of recovery data whose incomplete
/// files a sufficient PAR2 set rebuilds is repaired by the time the restore
/// runs. The dry run, which repairs nothing, defers that set to the PAR2
/// repair instead of failing it, and the restore to both.
#[test]
fn auto_dry_run_defers_a_short_par3_set_to_the_par2_repair_before_it() {
    let damaged = rar5_volume_names([3, 5, 7]).join(", ");
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    create_parity_with(&download_dir, "PAR3", &rar5_volume_names(1..=10), 1);
    create_parity(&download_dir, "PAR2", &rar5_volume_names(1..=10));
    damage_three_rar5_volumes(&download_dir);

    let (code, actions) = auto_dry_run_steps(&download_dir);
    assert_eq!(code, Some(0), "{actions:?}");
    let steps = actions
        .iter()
        .map(|action| {
            (
                action["action"].as_str().unwrap(),
                action["success"].as_bool().unwrap(),
                action.get("deferred_to").and_then(|to| to.as_str()),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        steps,
        [
            ("par3_verify_repair", false, None),
            ("par_verify_repair", true, None),
            ("par3_verify_repair", true, Some("par2")),
            ("rar_restore_volumes", true, Some("par2+par3")),
        ],
        "{actions:?}"
    );
    assert_eq!(
        actions[2]["message"],
        format!("PAR2 repair runs first for {damaged}")
    );
    assert_eq!(
        actions[3]["message"],
        format!(
            "insufficient recovery volumes: need 3, have 2 for {damaged}; PAR3 and PAR2 \
             repairs run first for {damaged}"
        )
    );

    let out_dir = temp.path().join("out");
    assert_success(&auto_into(&download_dir, &out_dir), "auto");
    assert!(out_dir.join("payload.bin").is_file());
}

/// The real `auto` run over `dir`, extracting into `out_dir`.
fn auto_into(dir: &Path, out_dir: &Path) -> Output {
    run(&[
        OsStr::new("--quiet"),
        OsStr::new("auto"),
        OsStr::new("--output"),
        out_dir.as_os_str(),
        dir.as_os_str(),
    ])
}

/// `auto` repairs with PAR2 or PAR3 before it restores from `.rev` files, so
/// a dry run that finds too few `.rev` files for a set whose damaged volumes
/// parity protects defers to that repair instead of failing; the real run
/// then repairs the set without them.
#[test]
fn auto_dry_run_leaves_a_short_restore_to_the_parity_repair_before_it() {
    let damaged = rar5_volume_names([3, 5, 7]).join(", ");
    for (parity, deferred_to) in [("PAR2", "par2"), ("PAR3", "par3")] {
        let temp = tempfile::tempdir().unwrap();
        let download_dir = temp.path().join("download");
        copy_rar5_recovery_set(&download_dir);
        create_parity(&download_dir, parity, &rar5_volume_names(1..=10));
        damage_three_rar5_volumes(&download_dir);

        let (code, action) = auto_dry_run_restore_step(&download_dir);
        assert_eq!(code, Some(0), "auto --dry-run with {parity}: {action}");
        assert_eq!(action["success"], true);
        assert_eq!(action["deferred_to"], deferred_to);
        assert_eq!(
            action["message"],
            format!(
                "insufficient recovery volumes: need 3, have 2 for {damaged}; {parity} repair \
                 runs first for {damaged}"
            )
        );
        let output = run(&[
            OsStr::new("auto"),
            OsStr::new("--dry-run"),
            download_dir.as_os_str(),
        ]);
        assert_success(&output, &format!("auto --dry-run with {parity}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("dry-run rar_restore_volumes [deferred]: insufficient recovery"),
            "{stdout}"
        );

        let out_dir = temp.path().join("out");
        assert_success(
            &auto_into(&download_dir, &out_dir),
            &format!("auto with {parity}"),
        );
        assert!(out_dir.join("payload.bin").is_file());
    }
}

/// Parity counts toward a short restore only for the damaged volumes it
/// names: a PAR2 set over a file beside the volumes, or over volumes that
/// are intact, rebuilds none of them, so the dry run fails as the real run
/// does.
#[test]
fn auto_dry_run_fails_a_short_restore_parity_does_not_cover() {
    for nfo_only in [true, false] {
        let case = if nfo_only {
            "PAR2 over the .nfo only"
        } else {
            "PAR2 over volumes 1-4 with 5-7 missing"
        };
        let temp = tempfile::tempdir().unwrap();
        let download_dir = temp.path().join("download");
        copy_rar5_recovery_set(&download_dir);
        if nfo_only {
            let nfo = "rar5_recovery_volumes.nfo".to_string();
            std::fs::write(download_dir.join(&nfo), [b'n'; 4096]).unwrap();
            create_parity(&download_dir, "PAR2", &[nfo]);
            damage_three_rar5_volumes(&download_dir);
        } else {
            create_parity(&download_dir, "PAR2", &rar5_volume_names(1..=4));
            for name in rar5_volume_names(5..=7) {
                std::fs::remove_file(download_dir.join(name)).unwrap();
            }
        }

        let (code, action) = auto_dry_run_restore_step(&download_dir);
        assert_eq!(code, Some(1), "auto --dry-run, {case}: {action}");
        assert_eq!(action["success"], false, "{case}");
        assert!(action.get("deferred_to").is_none(), "{case}: {action}");
        let message = action["message"].as_str().unwrap();
        assert!(
            message.starts_with("insufficient recovery volumes: need 3, have 2 for ")
                && !message.contains("first for"),
            "{case}: {message}"
        );

        let output = auto_into(&download_dir, &temp.path().join("out"));
        assert_data_failure(&output, &format!("auto, {case}"));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("insufficient RAR5 recovery volumes: need 3, have 2"),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A PAR3 set over exactly the volumes that are gone covers them although
/// none of them is present to match by: the dry run defers, and the real run
/// rebuilds them from PAR3 and extracts.
#[test]
fn auto_dry_run_defers_to_parity_over_exactly_the_missing_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let removed = rar5_volume_names([3, 5, 7]);
    create_parity(&download_dir, "PAR3", &removed);
    for name in &removed {
        std::fs::remove_file(download_dir.join(name)).unwrap();
    }

    let (code, action) = auto_dry_run_restore_step(&download_dir);
    assert_eq!(code, Some(0), "{action}");
    assert_eq!(action["success"], true);
    assert_eq!(action["deferred_to"], "par3");
    let removed = removed.join(", ");
    assert_eq!(
        action["message"],
        format!(
            "insufficient recovery volumes: need 3, have 2 for {removed}; PAR3 repair runs \
             first for {removed}"
        )
    );

    let out_dir = temp.path().join("out");
    assert_success(&auto_into(&download_dir, &out_dir), "auto with PAR3");
    assert!(out_dir.join("payload.bin").is_file());
}

/// A `.rev` file the parity lists is rebuilt before the restore, like a
/// data volume, so the dry run counts it among the usable recovery volumes
/// by then and defers a restore it makes sufficient instead of failing it.
/// The real run then repairs the `.rev` file, restores from it and
/// extracts.
#[test]
fn auto_dry_run_defers_to_parity_over_a_missing_recovery_volume() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let rev = "rar5_recovery_volumes.part02.rev".to_string();
    create_parity(&download_dir, "PAR2", std::slice::from_ref(&rev));
    std::fs::remove_file(download_dir.join(&rev)).unwrap();
    let removed = rar5_volume_names([3, 5]);
    for name in &removed {
        std::fs::remove_file(download_dir.join(name)).unwrap();
    }

    let (code, action) = auto_dry_run_restore_step(&download_dir);
    assert_eq!(code, Some(0), "{action}");
    assert_eq!(action["success"], true);
    assert_eq!(action["deferred_to"], "par2");
    assert_eq!(
        action["message"],
        format!(
            "insufficient recovery volumes: need 2, have 1 for {}; PAR2 repair runs first for \
             {rev}",
            removed.join(", ")
        )
    );

    let out_dir = temp.path().join("out");
    assert_success(&auto_into(&download_dir, &out_dir), "auto with PAR2");
    assert!(out_dir.join("payload.bin").is_file());
}

/// A set with no `.rev` file on disk is restored by the real run only once
/// the parity has rebuilt its `.rev` files, so the dry run defers that
/// restore to the parity without a plan, having nothing to plan from, and
/// plans nothing at all for a set whose `.rev` files no parity lists.
#[test]
fn auto_dry_run_defers_to_parity_over_every_missing_recovery_volume() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let revs = [1, 2]
        .map(|rev| format!("rar5_recovery_volumes.part{rev:02}.rev"))
        .to_vec();
    create_parity(&download_dir, "PAR3", &revs);
    for name in &revs {
        std::fs::remove_file(download_dir.join(name)).unwrap();
    }
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();

    let (code, action) = auto_dry_run_restore_step(&download_dir);
    assert_eq!(code, Some(0), "{action}");
    assert_eq!(action["success"], true);
    assert_eq!(action["deferred_to"], "par3");
    assert_eq!(
        action["message"],
        format!(
            "no recovery volumes present to plan with; PAR3 repair runs first for {}",
            revs.join(", ")
        )
    );

    let out_dir = temp.path().join("out");
    assert_success(&auto_into(&download_dir, &out_dir), "auto with PAR3");
    assert!(out_dir.join("payload.bin").is_file());

    let unlisted = temp.path().join("unlisted");
    copy_rar5_recovery_set(&unlisted);
    for name in &revs {
        std::fs::remove_file(unlisted.join(name)).unwrap();
    }
    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
        unlisted.as_os_str(),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["executed_actions"].as_array().unwrap().len(), 0);
}

/// A data volume is placed by its name and judged by its size and CRC32,
/// never by its headers, so one whose headers are damaged plans as the
/// restore treats it: the dry run would restore it from the `.rev` files,
/// or defers to the parity over it when they are too few, and the real run
/// then restores or repairs it.
#[test]
fn auto_dry_run_plans_a_volume_with_damaged_headers_as_the_real_run_restores_it() {
    let damaged = "rar5_recovery_volumes.part03.rar";
    // Byte 13 is the type of the volume's first header.
    let damage_headers = |dir: &Path| flip_byte(&dir.join(damaged), |_| 13);

    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    damage_headers(&download_dir);
    let before = listing(&download_dir);
    let (code, action) = auto_dry_run_restore_step(&download_dir);
    assert_eq!(code, Some(0), "{action}");
    assert_eq!(action["success"], true);
    assert!(action.get("deferred_to").is_none(), "{action}");
    assert_eq!(
        action["message"],
        format!(
            "would restore 1 volume(s) ({damaged}) using 1 of 2 usable recovery volume(s); \
             would set aside 1 damaged volume(s) as .bad"
        )
    );
    assert_eq!(listing(&download_dir), before);

    let out_dir = temp.path().join("out");
    assert_success(
        &auto_into(&download_dir, &out_dir),
        "auto over a volume with damaged headers",
    );
    assert!(out_dir.join("payload.bin").is_file());
    let rar5 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5"]);
    assert_eq!(
        std::fs::read(download_dir.join(damaged)).unwrap(),
        std::fs::read(rar5.join(damaged)).unwrap()
    );
    assert!(download_dir.join(format!("{damaged}.bad")).is_file());

    for (parity, deferred_to) in [("PAR2", "par2"), ("PAR3", "par3")] {
        let temp = tempfile::tempdir().unwrap();
        let download_dir = temp.path().join("download");
        copy_rar5_recovery_set(&download_dir);
        create_parity(&download_dir, parity, &rar5_volume_names(1..=10));
        std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
        flip_byte(
            &download_dir.join("rar5_recovery_volumes.part07.rar"),
            |len| len / 2,
        );
        damage_headers(&download_dir);

        let (code, action) = auto_dry_run_restore_step(&download_dir);
        assert_eq!(code, Some(0), "auto --dry-run with {parity}: {action}");
        assert_eq!(action["success"], true);
        assert_eq!(action["deferred_to"], deferred_to);
        let bad = rar5_volume_names([3, 5, 7]).join(", ");
        assert_eq!(
            action["message"],
            format!(
                "insufficient recovery volumes: need 3, have 2 for {bad}; {parity} repair runs \
                 first for {bad}"
            )
        );

        let out_dir = temp.path().join("out");
        assert_success(
            &auto_into(&download_dir, &out_dir),
            &format!("auto with {parity} over a volume with damaged headers"),
        );
        assert!(out_dir.join("payload.bin").is_file());
    }
}

/// Copy the five RAR3 data volumes of `rar3_recovery_volumes` and its two
/// `.rev` files into `dir`.
fn copy_rar3_recovery_set(dir: &Path) {
    let rar4 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    std::fs::create_dir_all(dir).unwrap();
    let volumes = (1..=5).map(|volume| format!("rar3_recovery_volumes.part{volume}.rar"));
    let revs = (1..=2).map(|volume| format!("rar3_recovery_volumes.part{volume}.rev"));
    for name in volumes.chain(revs) {
        std::fs::copy(rar4.join(&name), dir.join(&name)).unwrap();
    }
}

/// A set whose restore cannot be planned is a failed step of the dry run,
/// not the end of it: the sets after it are planned and the report printed.
#[test]
fn auto_dry_run_records_a_set_it_cannot_plan_and_plans_the_rest() {
    let temp = tempfile::tempdir().unwrap();
    // Sets are planned in directory order, so the broken one comes first.
    // Discovery takes a stray `part11` into the set by its name, but the
    // `.rev` files describe ten data volumes, so the restore refuses it.
    let broken = temp.path().join("a");
    copy_rar5_recovery_set(&broken);
    std::fs::copy(
        broken.join("rar5_recovery_volumes.part10.rar"),
        broken.join("rar5_recovery_volumes.part11.rar"),
    )
    .unwrap();
    let healthy = temp.path().join("b");
    copy_rar3_recovery_set(&healthy);
    let before = (listing(&broken), listing(&healthy));

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
        broken.as_os_str(),
        healthy.as_os_str(),
    ]);
    assert_data_failure(&output, "auto --dry-run --json over an unplannable set");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    let actions = report["executed_actions"].as_array().unwrap();
    let steps = actions
        .iter()
        .map(|action| {
            (
                action["action"].as_str().unwrap(),
                action["success"].as_bool().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        steps,
        [
            ("rar_restore_volumes", false),
            ("rar_restore_volumes", true)
        ],
        "{actions:?}"
    );
    let message = actions[0]["message"].as_str().unwrap();
    assert!(
        message.starts_with("cannot plan restore: ")
            && message.ends_with(
                "rar5_recovery_volumes.part11.rar names data volume 11, but its recovery set \
                 has 10 data volumes"
            ),
        "{message}"
    );
    assert_eq!(
        actions[1]["message"],
        "nothing to restore: all data volumes valid"
    );

    let output = run(&[
        OsStr::new("auto"),
        OsStr::new("--dry-run"),
        broken.as_os_str(),
        healthy.as_os_str(),
    ]);
    assert_data_failure(&output, "auto --dry-run over an unplannable set");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("rarpar discovery\n"), "{stdout}");
    assert!(
        stdout.contains("dry-run rar_restore_volumes [failed]: cannot plan restore: "),
        "{stdout}"
    );
    assert_eq!((listing(&broken), listing(&healthy)), before);
}

/// A volume damaged in place is set aside as `.bad` before it is rebuilt. A
/// dry run names that backup, and when one is already there fails as the
/// restore does, with the same message and exit code.
#[test]
fn rar_restore_volumes_dry_run_foresees_an_existing_bad_volume_backup() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    let damaged = download_dir.join("rar5_recovery_volumes.part03.rar");
    flip_byte(&damaged, |len| len / 2);
    let backup = download_dir.join("rar5_recovery_volumes.part03.rar.bad");
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --dry-run --json");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["message"],
        "would restore 1 volume(s) (rar5_recovery_volumes.part03.rar) using 1 of 2 usable \
         recovery volume(s); would set aside 1 damaged volume(s) as .bad"
    );
    let volume = &report["plan"]["data_volumes"][2];
    assert_eq!(volume["status"], "crc_mismatch");
    assert_eq!(volume["path"], damaged.display().to_string());
    assert_eq!(volume["output_path"], damaged.display().to_string());
    assert_eq!(volume["set_aside_path"], backup.display().to_string());

    std::fs::write(&backup, b"an earlier backup").unwrap();
    let before = listing(&download_dir);
    let refusal = format!(
        "refusing to overwrite existing bad-volume backup {}",
        backup.display()
    );
    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "dry run: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{refusal}\n")
    );
    assert_eq!(listing(&download_dir), before);

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        first.as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "restore: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&refusal),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run(&[
        OsStr::new("--overwrite"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --dry-run --overwrite");
}

/// With `--output`, a volume is rebuilt into that directory, and a file
/// already there stops the restore and fails the dry run alike.
#[test]
fn rar_restore_volumes_dry_run_foresees_an_existing_output() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let existing = out_dir.join("rar5_recovery_volumes.part05.rar");
    std::fs::write(&existing, b"another file").unwrap();
    let refusal = format!(
        "refusing to overwrite existing restored volume {}",
        existing.display()
    );

    for dry_run in [true, false] {
        let mut args = vec![
            OsStr::new("--output"),
            out_dir.as_os_str(),
            OsStr::new("rar"),
            OsStr::new("restore-volumes"),
        ];
        if dry_run {
            args.push(OsStr::new("--dry-run"));
        }
        args.push(first.as_os_str());
        let output = run(&args);
        assert_data_failure(
            &output,
            &format!("restore over an existing output, dry run {dry_run}"),
        );
        let shown = if dry_run {
            &output.stdout
        } else {
            &output.stderr
        };
        assert!(
            String::from_utf8_lossy(shown).contains(&refusal),
            "dry run {dry_run}: {}",
            String::from_utf8_lossy(shown)
        );
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"another file");
}

#[test]
fn quiet_restore_plans_and_volume_tests_print_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let first_rev = download_dir.join("rar5_recovery_volumes.part01.rev");
    let second_rev = download_dir.join("rar5_recovery_volumes.part02.rev");
    let commands = [
        vec![
            OsStr::new("--quiet"),
            OsStr::new("rar"),
            OsStr::new("restore-volumes"),
            OsStr::new("--dry-run"),
            first.as_os_str(),
        ],
        vec![
            OsStr::new("--quiet"),
            OsStr::new("auto"),
            OsStr::new("--dry-run"),
            download_dir.as_os_str(),
        ],
        vec![
            OsStr::new("--quiet"),
            OsStr::new("rar"),
            OsStr::new("test-volumes"),
            first_rev.as_os_str(),
            second_rev.as_os_str(),
        ],
    ];
    for args in &commands {
        let output = run(args);
        assert_success(&output, &format!("{args:?}"));
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "{args:?}"
        );
    }

    // Failing, they still print nothing: the exit code says it.
    flip_byte(&second_rev, |len| len - 1);
    for name in rar5_volume_names([3, 7]) {
        std::fs::remove_file(download_dir.join(name)).unwrap();
    }
    for args in &commands {
        let output = run(args);
        assert_data_failure(&output, &format!("{args:?}"));
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "{args:?}"
        );
    }
}

/// A path that cannot be read is reported `unreadable` with its I/O error
/// kind; the other paths are still tested.
#[test]
fn rar_test_volumes_reports_an_unreadable_path_and_tests_the_rest() {
    let temp = tempfile::tempdir().unwrap();
    copy_rar5_recovery_set(temp.path());
    let first = temp.path().join("rar5_recovery_volumes.part01.rev");
    let unreadable = temp.path().join("directory.rev");
    std::fs::create_dir(&unreadable).unwrap();
    let second = temp.path().join("rar5_recovery_volumes.part02.rev");

    let output = run(&[
        OsStr::new("rar"),
        OsStr::new("test-volumes"),
        first.as_os_str(),
        unreadable.as_os_str(),
        second.as_os_str(),
    ]);
    assert_data_failure(&output, "rar test-volumes over a directory");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert_eq!(lines[0], format!("{}: OK", first.display()));
    let unreadable_line = lines[1].to_string();
    assert_eq!(lines[2], format!("{}: OK", second.display()));

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("test-volumes"),
        first.as_os_str(),
        unreadable.as_os_str(),
        second.as_os_str(),
    ]);
    assert_data_failure(&output, "rar test-volumes --json over a directory");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    let results = report["results"].as_array().unwrap();
    let statuses = results
        .iter()
        .map(|result| result["status"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(statuses, ["ok", "unreadable", "ok"]);
    assert_eq!(results[1]["path"], unreadable.display().to_string());
    assert!(results[1]["format"].is_null());
    // The kind differs by platform (a directory opens on Unix but not on
    // Windows), so it is checked only to agree between the two outputs.
    let kind = results[1]["message"].as_str().unwrap();
    assert!(!kind.is_empty());
    assert_eq!(
        unreadable_line,
        format!("{}: unreadable ({kind})", unreadable.display())
    );
    assert!(results[0]["message"].is_null() && results[2]["message"].is_null());
}

#[test]
fn rar_restore_volumes_plans_and_restores_a_rar3_set() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar3_recovery_set(&download_dir);
    let missing = download_dir.join("rar3_recovery_volumes.part3.rar");
    std::fs::remove_file(&missing).unwrap();
    let first = download_dir.join("rar3_recovery_volumes.part1.rar");

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        OsStr::new("--dry-run"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --dry-run --json over RAR3");
    assert!(!missing.exists());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["message"],
        "would restore 1 volume(s) (rar3_recovery_volumes.part3.rar) using 1 of 2 usable \
         recovery volume(s)"
    );
    let plan = &report["plan"];
    assert_eq!(plan["format"], "rar4");
    assert_eq!(plan["data_count"], 5);
    assert_eq!(plan["needed"], 1);
    assert_eq!(plan["usable_recovery_count"], 2);
    let numbers = plan["recovery_volumes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|volume| volume["volume_number"].as_u64())
        .collect::<Vec<_>>();
    assert_eq!(numbers, [Some(5), Some(6)]);
    let rebuilt = plan["data_volumes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|volume| volume["status"] != "valid")
        .collect::<Vec<_>>();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0]["index"], 2);
    assert_eq!(rebuilt[0]["status"], "missing");
    assert_eq!(rebuilt[0]["output_path"], missing.display().to_string());

    let output = run(&[
        OsStr::new("--json"),
        OsStr::new("rar"),
        OsStr::new("restore-volumes"),
        first.as_os_str(),
    ]);
    assert_success(&output, "rar restore-volumes --json over RAR3");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let read = report["outcome"]["used_recovery_paths"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        report["message"],
        format!(
            "restored 1 volume(s) (rar3_recovery_volumes.part3.rar) from {read} recovery \
             volume(s) read"
        )
    );
    assert_eq!(
        report["outcome"]["missing_volume_numbers"],
        serde_json::json!([2])
    );
    let rar4 = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar4"]);
    assert_eq!(
        std::fs::read(&missing).unwrap(),
        std::fs::read(rar4.join("rar3_recovery_volumes.part3.rar")).unwrap()
    );
}

#[test]
fn cleanup_deletes_validated_sources_after_explicit_extraction() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let archive = temp.path().join("release.rar");
    std::fs::copy(source, &archive).unwrap();

    let extract = run(&[
        OsStr::new("rar"),
        OsStr::new("extract"),
        archive.as_os_str(),
        temp.path().as_os_str(),
    ]);
    assert!(extract.status.success());

    let cleanup = run(&[
        OsStr::new("cleanup"),
        OsStr::new("--permanent-delete"),
        archive.as_os_str(),
    ]);
    assert!(
        cleanup.status.success(),
        "cleanup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cleanup.stdout),
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(!archive.exists());
}

#[test]
fn compat_unrar_e_flattens_member_paths() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_dirs.rar",
    ]);
    let out_dir = temp.path().join("out");

    let output = run(&[
        OsStr::new("e"),
        OsStr::new("-o+"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "compat flat extraction failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("a.txt").is_file());
    assert!(out_dir.join("b.txt").is_file());
    assert!(!out_dir.join("dir1").exists());
}

#[test]
fn compat_unrar_test_writes_nothing_for_plain_files() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["rar5_multifile_store.rar", "rar5_symlink.rar"] {
        let archive = fixture(&["crates", "unrar-rs", "tests", "fixtures", "rar5", name]);
        let test = Command::new(bin())
            .env("TMPDIR", tmp.path())
            .args([OsStr::new("t"), archive.as_os_str()])
            .output()
            .unwrap();
        assert!(
            test.status.success(),
            "compat test of {name} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&test.stdout),
            String::from_utf8_lossy(&test.stderr)
        );
        assert!(String::from_utf8_lossy(&test.stdout).contains("All OK"));
        // The scratch tree a link set needs is removed when the run ends;
        // a set of plain files never creates one.
        assert_eq!(
            std::fs::read_dir(tmp.path()).unwrap().count(),
            0,
            "{name} left files in TMPDIR"
        );
    }
    let store = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_multifile_store.rar",
    ]);
    let stdout = String::from_utf8_lossy(
        &Command::new(bin())
            .env("TMPDIR", "/nonexistent-rarpar-test-tmpdir")
            .args([OsStr::new("t"), store.as_os_str()])
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();
    assert!(
        stdout.contains("All OK"),
        "plain files needed a scratch tree: {stdout}"
    );
}

#[test]
fn compat_unrar_test_and_list_cover_operational_commands() {
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_multifile_store.rar",
    ]);

    let test = run(&[OsStr::new("t"), archive.as_os_str()]);
    assert!(
        test.status.success(),
        "compat test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );
    assert!(String::from_utf8_lossy(&test.stdout).contains("Testing from "));
    assert!(String::from_utf8_lossy(&test.stdout).contains("All OK"));

    let list = run(&[OsStr::new("l"), archive.as_os_str()]);
    assert!(
        list.status.success(),
        "compat list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    for name in ["hello.txt", "second.txt", "random_512.bin"] {
        assert!(stdout.contains(name), "missing {name} from {stdout}");
    }
}

/// CRC-32 (IEEE), bitwise: enough to reseal one tampered RAR5 header.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn read_rar5_vint(data: &[u8], pos: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = data[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// Flip one byte of the first file header's data CRC32 in a RAR5 archive
/// and reseal that header's own CRC, so the header still parses and only
/// the member's checksum is wrong.
fn tamper_rar5_data_crc(archive: &mut [u8]) {
    const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
    const FILE_HEADER: u64 = 2;
    const END_OF_ARCHIVE: u64 = 5;
    assert!(archive.starts_with(SIGNATURE), "not a RAR5 archive");
    let mut block = SIGNATURE.len();
    while block < archive.len() {
        let mut pos = block + 4;
        let header_size = read_rar5_vint(archive, &mut pos) as usize;
        let header_end = pos + header_size;
        let kind = read_rar5_vint(archive, &mut pos);
        let flags = read_rar5_vint(archive, &mut pos);
        if flags & 0x1 != 0 {
            read_rar5_vint(archive, &mut pos); // extra area size
        }
        let data_size = if flags & 0x2 != 0 {
            read_rar5_vint(archive, &mut pos) as usize
        } else {
            0
        };
        if kind == FILE_HEADER {
            let file_flags = read_rar5_vint(archive, &mut pos);
            read_rar5_vint(archive, &mut pos); // unpacked size
            read_rar5_vint(archive, &mut pos); // attributes
            if file_flags & 0x2 != 0 {
                pos += 4; // mtime
            }
            assert!(file_flags & 0x4 != 0, "fixture member carries no CRC32");
            archive[pos] ^= 0xff;
            let header_crc = crc32_ieee(&archive[block + 4..header_end]);
            archive[block..block + 4].copy_from_slice(&header_crc.to_le_bytes());
            return;
        }
        assert_ne!(kind, END_OF_ARCHIVE, "no file header before the end");
        block = header_end + data_size;
    }
    panic!("no file header in the archive");
}

/// `t` still verifies a stored member's checksum on the sink path: a member
/// whose recorded CRC32 does not match its data fails the test.
#[test]
fn compat_unrar_test_reports_a_tampered_crc() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let mut bytes = std::fs::read(&source).unwrap();
    tamper_rar5_data_crc(&mut bytes);
    let archive = temp.path().join("tampered.rar");
    std::fs::write(&archive, &bytes).unwrap();

    let intact = run(&[OsStr::new("t"), source.as_os_str()]);
    assert!(
        intact.status.success(),
        "untampered fixture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&intact.stdout),
        String::from_utf8_lossy(&intact.stderr)
    );

    let test = run(&[OsStr::new("t"), archive.as_os_str()]);
    let stdout = String::from_utf8_lossy(&test.stdout);
    assert_eq!(
        test.status.code(),
        Some(3),
        "tampered CRC must fail the test: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&test.stderr)
    );
    assert!(
        stdout.contains("small.txt - CRC failed"),
        "missing CRC failure: {stdout}"
    );
    assert!(!stdout.contains("All OK"), "reported success: {stdout}");
}

#[test]
fn compat_unrar_auto_rename_and_suppression_switches_are_honored() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_store.rar",
    ]);
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("small.txt"), b"original").unwrap();

    let renamed = run(&[
        OsStr::new("x"),
        OsStr::new("-or"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        renamed.status.success(),
        "compat auto-rename failed: stdout={} stderr={}",
        String::from_utf8_lossy(&renamed.stdout),
        String::from_utf8_lossy(&renamed.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("small.txt")).unwrap(),
        b"original"
    );
    assert!(out_dir.join("small(1).txt").is_file());

    let quiet = run(&[
        OsStr::new("x"),
        OsStr::new("-idq"),
        OsStr::new("-y"),
        OsStr::new("-ai"),
        OsStr::new("-scf"),
        OsStr::new("-tsm-"),
        OsStr::new("-mlp"),
        OsStr::new("-om"),
        OsStr::new("-om1"),
        OsStr::new("-om-"),
        OsStr::new("-ri6:10"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        quiet.status.success(),
        "compat accepted switches failed: stdout={} stderr={}",
        String::from_utf8_lossy(&quiet.stdout),
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert!(quiet.stdout.is_empty());

    let names_hidden = run(&[
        OsStr::new("x"),
        OsStr::new("-idn"),
        archive.as_os_str(),
        out_dir.as_os_str(),
    ]);
    assert!(
        names_hidden.status.success(),
        "compat name suppression failed: stdout={} stderr={}",
        String::from_utf8_lossy(&names_hidden.stdout),
        String::from_utf8_lossy(&names_hidden.stderr)
    );
    let stdout = String::from_utf8_lossy(&names_hidden.stdout);
    assert!(stdout.contains("All OK"));
    assert!(!stdout.contains("small.txt"));
}

#[test]
fn compat_unrar_password_disabled_returns_password_exit() {
    let temp = tempfile::tempdir().unwrap();
    let archive = fixture(&[
        "crates",
        "unrar-rs",
        "tests",
        "fixtures",
        "rar5",
        "rar5_hp_store.rar",
    ]);

    let output = run(&[
        OsStr::new("x"),
        OsStr::new("-p-"),
        archive.as_os_str(),
        temp.path().as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(11),
        "disabled password should use the password exit: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("password is incorrect"));
}

#[test]
fn compat_unrar_rejects_every_unsupported_modifying_command() {
    for command in [
        "a", "c", "cf", "ch", "cw", "d", "f", "i", "k", "m", "r", "rc", "rn", "rr", "rv", "s", "u",
        "v",
    ] {
        let output = run(&[OsStr::new(command), OsStr::new("ignored.rar")]);
        assert_eq!(
            output.status.code(),
            Some(7),
            "{command} should return the command-line exit: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Unsupported command"),
            "{command} did not identify the unsupported command"
        );
    }
}

#[test]
fn compat_par2_repair_honors_base_directory() {
    let temp = tempfile::tempdir().unwrap();
    let fixture_dir = fixture(&["crates", "par2-rs", "tests", "fixtures", "rar5_lz_plain"]);
    let work_dir = temp.path().join("rar5_lz_plain");
    copy_dir_recursive(&fixture_dir, &work_dir);
    let par2_path = work_dir.join("fixture_rar5_lz_plain_repair.par2");

    let output = run_in_dir(
        temp.path(),
        &[
            OsStr::new("r"),
            OsStr::new("-B"),
            work_dir.as_os_str(),
            par2_path.as_os_str(),
            work_dir.join("fixture_rar5_lz_plain*").as_os_str(),
        ],
    );
    assert!(
        output.status.success(),
        "compat PAR2 base-directory repair failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "All files are correct"
    );
}

#[test]
fn compat_par2_facade_is_consumer_side_only() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("ledger.bin"), b"invented input bytes").unwrap();
    for (args, message) in [
        (
            &["c", "set.par2", "ledger.bin"][..],
            "rarpar does not create PAR2 files through the par2cmdline facade (c is not supported)",
        ),
        (
            &["create", "-r10", "set.par2", "ledger.bin"],
            "(create is not supported); use `rarpar par create`.",
        ),
        (
            &["v", "set.par2"],
            "rarpar does not verify through the par2cmdline facade (v is not supported)",
        ),
        (&["verify", "set.par2"], "(verify is not supported)"),
        (
            &["r", "-s100", "set.par2"],
            "Cannot specify block size unless creating.",
        ),
        (
            &["r", "-B", ".", "-r10", "set.par2"],
            "Cannot specify redundancy unless creating.",
        ),
        (
            &["r", "-b4", "set.par2"],
            "Cannot specify block count unless creating.",
        ),
        (
            &["r", "-c2", "set.par2"],
            "Cannot specify recovery block count unless creating.",
        ),
        (
            &["r", "-f1", "set.par2"],
            "Cannot specify first block number unless creating.",
        ),
        (
            &["r", "-u", "set.par2"],
            "Cannot specify uniform files unless creating.",
        ),
        (
            &["r", "-l", "set.par2"],
            "Cannot specify limit files unless creating.",
        ),
        (
            &["r", "-n2", "set.par2"],
            "Cannot specify recovery file count unless creating.",
        ),
        (
            &["r", "-R", "set.par2"],
            "Cannot specific Recursive unless creating.",
        ),
    ] {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let output = run_in_dir(temp.path(), &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
    // Nothing was written.
    let mut names: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["ledger.bin"]);
}

/// A symlink at a missing volume's output name, even one pointing nowhere,
/// is a directory entry the restore's exclusive create refuses, so the dry
/// run refuses it too instead of following the link and finding the name
/// free. The link is left as it was.
#[cfg(unix)]
#[test]
fn rar_restore_volumes_dry_run_foresees_a_dangling_symlink_at_the_output() {
    let temp = tempfile::tempdir().unwrap();
    let download_dir = temp.path().join("download");
    copy_rar5_recovery_set(&download_dir);
    std::fs::remove_file(download_dir.join("rar5_recovery_volumes.part05.rar")).unwrap();
    let first = download_dir.join("rar5_recovery_volumes.part01.rar");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let occupied = out_dir.join("rar5_recovery_volumes.part05.rar");
    std::os::unix::fs::symlink("nowhere", &occupied).unwrap();
    let refusal = format!(
        "refusing to overwrite existing restored volume {}",
        occupied.display()
    );

    for dry_run in [true, false] {
        let mut args = vec![
            OsStr::new("--output"),
            out_dir.as_os_str(),
            OsStr::new("rar"),
            OsStr::new("restore-volumes"),
        ];
        if dry_run {
            args.push(OsStr::new("--dry-run"));
        }
        args.push(first.as_os_str());
        let output = run(&args);
        assert_data_failure(
            &output,
            &format!("restore over a dangling symlink, dry run {dry_run}"),
        );
        let shown = if dry_run {
            &output.stdout
        } else {
            &output.stderr
        };
        assert!(
            String::from_utf8_lossy(shown).contains(&refusal),
            "dry run {dry_run}: {}",
            String::from_utf8_lossy(shown)
        );
    }
    assert_eq!(
        std::fs::read_link(&occupied).unwrap(),
        Path::new("nowhere"),
        "the link was replaced"
    );
    assert_eq!(listing(&out_dir).len(), 1);
}
