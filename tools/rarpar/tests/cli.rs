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
