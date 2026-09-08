use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run(root: &Path, args: &[&str], code: i32) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "args={args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn input(root: &Path, name: &str) -> Vec<u8> {
    let bytes: Vec<_> = (0..1024)
        .map(|index| ((index * 31 + index / 256) % 251) as u8)
        .collect();
    std::fs::write(root.join(name), &bytes).unwrap();
    bytes
}

#[test]
fn cauchy_create_verify_repair_preserves_clean_files_and_backups() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bytes = input(root, "data.bin");
    std::fs::write(root.join("clean.txt"), b"keep this file").unwrap();
    let created = run(
        root,
        &[
            "par3",
            "create",
            "set.par3",
            "data.bin",
            "clean.txt",
            "-s",
            "256",
            "-c",
            "2",
        ],
        0,
    );
    assert_eq!(created["outputs"][0], "set.par3");
    run(root, &["par3", "verify", "set.par3"], 0);
    let clean_time = std::fs::metadata(root.join("clean.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let mut damaged = bytes.clone();
    damaged[10] ^= 0x80;
    std::fs::write(root.join("data.bin"), &damaged).unwrap();
    let verify = run(root, &["par3", "verify", "set.par3"], 1);
    assert_eq!(verify["status"], "Ready");
    let planned = run(root, &["par3", "repair", "set.par3", "--dry-run"], 0);
    assert_eq!(planned["installed"], serde_json::json!([]));
    assert_eq!(std::fs::read(root.join("data.bin")).unwrap(), damaged);
    let repaired = run(root, &["par3", "repair", "set.par3"], 0);
    assert_eq!(repaired["installed"].as_array().unwrap().len(), 1);
    let backup = repaired["installed"][0]["backup"].as_str().unwrap();
    assert_eq!(std::fs::read(root.join(backup)).unwrap(), damaged);
    assert_eq!(std::fs::read(root.join("data.bin")).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(root.join("clean.txt"))
            .unwrap()
            .modified()
            .unwrap(),
        clean_time
    );
    run(root, &["par3", "verify", "set.par3"], 0);
}

#[test]
fn fft_auto_repairs_missing_input_with_interleaved_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bytes = input(root, "data.bin");
    let created = run(
        root,
        &[
            "par3",
            "create",
            "fft",
            "data.bin",
            "-s",
            "256",
            "-c",
            "4",
            "--codec",
            "fft",
            "--capacity-log2",
            "2",
            "--interleave",
            "1",
            "--volume-blocks",
            "1",
        ],
        0,
    );
    assert_eq!(created["cohorts"], 2);
    std::fs::remove_file(root.join("data.bin")).unwrap();
    let plan = run(root, &["inspect", "fft.par3"], 0);
    assert_eq!(plan["par3_sets"].as_array().unwrap().len(), 1);
    let auto = run(root, &["fft.par3"], 0);
    assert_eq!(auto["executed_actions"][0]["action"], "par3_verify_repair");
    assert_eq!(std::fs::read(root.join("data.bin")).unwrap(), bytes);
}

#[test]
fn data_only_and_deduplicated_creation_restore_aliases() {
    for dedup in ["aligned", "sliding"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let bytes = input(root, "first.bin");
        std::fs::write(root.join("alias.bin"), &bytes).unwrap();
        let created = run(
            root,
            &[
                "par3",
                "create",
                "data",
                "first.bin",
                "alias.bin",
                "-s",
                "256",
                "-c",
                "0",
                "--data-packets",
                "--dedup",
                dedup,
            ],
            0,
        );
        assert!(created["reused_blocks"].as_u64().unwrap() > 0);
        std::fs::remove_file(root.join("first.bin")).unwrap();
        std::fs::remove_file(root.join("alias.bin")).unwrap();
        run(root, &["par3", "repair", "data.par3", "--no-backup"], 0);
        assert_eq!(std::fs::read(root.join("first.bin")).unwrap(), bytes);
        assert_eq!(std::fs::read(root.join("alias.bin")).unwrap(), bytes);
    }
}

#[test]
fn smart_placement_recovers_renamed_data_without_parity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bytes = input(root, "data.bin");
    run(
        root,
        &["par3", "create", "set", "data.bin", "-s", "256", "-c", "0"],
        0,
    );
    std::fs::create_dir(root.join("candidates")).unwrap();
    std::fs::rename(root.join("data.bin"), root.join("candidates/renamed.bin")).unwrap();
    run(
        root,
        &["par3", "repair", "set.par3", "--par-placement", "canonical"],
        1,
    );
    run(
        root,
        &["par3", "repair", "set.par3", "--search-dir", "candidates"],
        0,
    );
    assert_eq!(std::fs::read(root.join("data.bin")).unwrap(), bytes);
}

#[test]
fn creation_dry_run_overwrite_and_resource_limits() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    input(root, "data.bin");
    let args = [
        "par3", "create", "out/set", "data.bin", "-s", "256", "-r", "50",
    ];
    let mut dry = args.to_vec();
    dry.push("--dry-run");
    run(root, &dry, 0);
    assert!(!root.join("out").exists());
    run(root, &args, 0);
    run(root, &args, 3);
    let mut overwrite = args.to_vec();
    overwrite.push("--overwrite");
    run(root, &overwrite, 0);
    run(
        root,
        &[
            "par3",
            "verify",
            "out/set.par3",
            "-C",
            ".",
            "--par3-memory-mib",
            "0",
        ],
        4,
    );
    let verify = run(root, &["par3", "verify", "out/set.par3", "-C", "."], 0);
    assert_eq!(verify["status"], "Complete");
}

#[test]
fn directory_requires_set_selection_and_invalid_carrier_fails_auto() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    input(root, "a.bin");
    input(root, "b.bin");
    let a = run(root, &["par3", "create", "a", "a.bin", "-s", "256"], 0);
    run(root, &["par3", "create", "b", "b.bin", "-s", "256"], 0);
    run(root, &["par3", "verify", "."], 2);
    run(
        root,
        &[
            "par3",
            "verify",
            ".",
            "--set-id",
            a["set_id"].as_str().unwrap(),
        ],
        0,
    );
    std::fs::write(root.join("invalid.par3"), b"not a PAR3 packet").unwrap();
    // Auto errors are printed on stderr, matching other automatic pipeline failures.
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(root)
        .args(["auto", "invalid.par3"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn symlink_member_is_rejected_without_touching_its_target() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    input(root, "data.bin");
    run(
        root,
        &["par3", "create", "set", "data.bin", "-s", "256", "-c", "4"],
        0,
    );
    std::fs::remove_file(root.join("data.bin")).unwrap();
    std::fs::write(root.join("outside.bin"), b"keep").unwrap();
    std::os::unix::fs::symlink("outside.bin", root.join("data.bin")).unwrap();
    run(root, &["par3", "repair", "set.par3"], 3);
    assert_eq!(std::fs::read(root.join("outside.bin")).unwrap(), b"keep");
}

#[test]
fn auto_restores_rar_before_extraction_and_cleans_only_consumed_carriers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/par2-rs/tests/fixtures/rar5_lz_plain");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(fixture).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|ext| ext == "rar") {
            let name = entry.file_name().into_string().unwrap();
            std::fs::copy(entry.path(), root.join(&name)).unwrap();
            names.push(name);
        }
    }
    assert!(!names.is_empty(), "existing RAR corpus must be hydrated");
    names.sort();
    let mut args = vec![
        "par3",
        "create",
        "archive",
        "--block-size",
        "65536",
        "--recovery-count",
        "0",
        "--data-packets",
    ];
    args.extend(names.iter().map(String::as_str));
    let created = run(root, &args, 0);
    std::fs::remove_file(root.join(&names[0])).unwrap();
    let result = run(
        root,
        &["auto", ".", "--delete-sources", "--permanent-delete"],
        0,
    );
    assert_eq!(
        result["executed_actions"][0]["action"],
        "par3_verify_repair"
    );
    assert!(root.join("rar5_lz_plain_clip.mkv").is_file());
    for name in names {
        assert!(!root.join(name).exists());
    }
    for path in created["outputs"].as_array().unwrap() {
        assert!(!root.join(path.as_str().unwrap()).exists());
    }
}

#[test]
fn fft_surplus_in_one_cohort_cannot_cover_the_other() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    input(root, "data.bin");
    run(
        root,
        &[
            "par3",
            "create",
            "set",
            "data.bin",
            "-s",
            "256",
            "-c",
            "4",
            "--codec",
            "fft",
            "--capacity-log2",
            "2",
            "--interleave",
            "1",
            "--volume-blocks",
            "1",
        ],
        0,
    );
    std::fs::remove_file(root.join("set.vol1+1.par3")).unwrap();
    std::fs::remove_file(root.join("set.vol3+1.par3")).unwrap();
    std::fs::remove_file(root.join("data.bin")).unwrap();
    let report = run(
        root,
        &["par3", "repair", "set.par3", "--par-placement", "canonical"],
        1,
    );
    assert_eq!(report["status"], "NeedRecovery");
    assert_eq!(report["requirements"][0]["additional"], 0);
    assert_eq!(report["requirements"][1]["additional"], 2);
    assert!(!root.join("data.bin").exists());
}

#[test]
fn base_path_and_inline_empty_files_are_supported() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("inputs")).unwrap();
    std::fs::write(root.join("inputs/empty"), b"").unwrap();
    std::fs::write(root.join("inputs/tiny"), b"inline").unwrap();
    run(
        root,
        &[
            "par3",
            "create",
            "set",
            "empty",
            "tiny",
            "--base-path",
            "inputs",
            "-c",
            "0",
        ],
        0,
    );
    std::fs::remove_file(root.join("inputs/empty")).unwrap();
    std::fs::remove_file(root.join("inputs/tiny")).unwrap();
    run(root, &["par3", "repair", "set.par3", "-C", "inputs"], 0);
    assert_eq!(std::fs::read(root.join("inputs/tiny")).unwrap(), b"inline");
    assert!(std::fs::read(root.join("inputs/empty")).unwrap().is_empty());
}

#[test]
fn auto_repairs_independent_copies_without_counting_rediscovery_twice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("one")).unwrap();
    std::fs::create_dir(root.join("two")).unwrap();
    let bytes = input(&root.join("one"), "data.bin");
    run(
        &root.join("one"),
        &["par3", "create", "set", "data.bin", "-s", "256", "-c", "4"],
        0,
    );
    for entry in std::fs::read_dir(root.join("one")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), root.join("two").join(entry.file_name())).unwrap();
    }
    std::fs::remove_file(root.join("one/data.bin")).unwrap();
    std::fs::remove_file(root.join("two/data.bin")).unwrap();
    let report = run(root, &["auto", ".", "--max-files", "10"], 0);
    assert_eq!(report["par3_sets"].as_array().unwrap().len(), 2);
    assert_eq!(std::fs::read(root.join("one/data.bin")).unwrap(), bytes);
    assert_eq!(std::fs::read(root.join("two/data.bin")).unwrap(), bytes);
}

#[test]
fn auto_uses_valid_packets_despite_an_unusable_sibling_carrier() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bytes = input(root, "data.bin");
    run(
        root,
        &["par3", "create", "set", "data.bin", "-s", "256", "-c", "4"],
        0,
    );
    // Model an unavailable carrier by truncation; no packet bytes are edited.
    std::fs::write(root.join("omitted.par3"), []).unwrap();
    std::fs::remove_file(root.join("data.bin")).unwrap();
    run(root, &["auto", "."], 0);
    assert_eq!(std::fs::read(root.join("data.bin")).unwrap(), bytes);
    assert!(root.join("omitted.par3").exists());
}

#[test]
fn directory_selection_uses_the_selected_carriers_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("nested")).unwrap();
    let bytes = input(&root.join("nested"), "data.bin");
    run(
        &root.join("nested"),
        &["par3", "create", "set", "data.bin", "-s", "256", "-c", "4"],
        0,
    );
    run(root, &["par3", "verify", "."], 0);
    std::fs::remove_file(root.join("nested/data.bin")).unwrap();
    run(root, &["par3", "repair", "."], 0);
    assert_eq!(std::fs::read(root.join("nested/data.bin")).unwrap(), bytes);
    assert!(!root.join("data.bin").exists());
}
