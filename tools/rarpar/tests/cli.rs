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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
        "weaver-unrar",
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
        "weaver-unrar",
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
        "weaver-unrar",
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
        "weaver-unrar",
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
        "weaver-unrar",
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
    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar4"]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
    let fixture_dir = fixture(&[
        "crates",
        "weaver-par2",
        "tests",
        "fixtures",
        "rar5_lz_plain",
    ]);
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
        "weaver-unrar",
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
        "weaver-unrar",
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
        "weaver-unrar",
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
    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar4"]);
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
    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar4"]);
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
    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar5"]);
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
    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar5"]);
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
        "weaver-unrar",
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
        "weaver-unrar",
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
        "weaver-unrar",
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

    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar4"]);
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

    let fixture_dir = fixture(&["crates", "weaver-unrar", "tests", "fixtures", "rar4"]);
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
