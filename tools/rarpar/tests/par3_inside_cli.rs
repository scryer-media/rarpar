//! `rarpar par3 inside` over a RARLAB-made RAR5 volume set: insert, verify,
//! in-place repair of a lost and a damaged volume, and byte-exact removal.
//! The fixtures are not committed; each test skips when they are absent.
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const STEM: &str = "generated_matrix_rar5_store_plain";

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
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Copy the seven-volume fixture into `root/original`, or `None` when absent.
fn originals(root: &Path) -> Option<Vec<PathBuf>> {
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/unrar-rs/tests/fixtures/rar5");
    let directory = root.join("original");
    std::fs::create_dir_all(&directory).unwrap();
    let mut copies = Vec::new();
    for part in 1..=7 {
        let name = format!("{STEM}.part{part}.rar");
        let source = fixtures.join(&name);
        if !source.is_file() {
            eprintln!("skipping: fixture {} is not present", source.display());
            return None;
        }
        std::fs::copy(&source, directory.join(&name)).unwrap();
        copies.push(directory.join(name));
    }
    Some(copies)
}

fn name(part: usize) -> String {
    format!("{STEM}.part{part}.rar")
}

#[test]
fn inside_lifecycle_repairs_lost_and_damaged_volumes_and_removes_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let first = sources[0].to_str().unwrap();

    let inserted = run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "-d",
            "protected",
            "-s",
            "4096",
            "-c",
            "56",
            "--layout",
            "service",
        ],
        0,
    );
    assert_eq!(inserted["outputs"].as_array().unwrap().len(), 7);
    let protected = root.join("protected");
    let pristine: Vec<Vec<u8>> = (1..=7)
        .map(|part| std::fs::read(protected.join(name(part))).unwrap())
        .collect();
    let entry = protected.join(name(1));
    let entry = entry.to_str().unwrap();
    run(root, &["par3", "inside", "verify", entry], 0);

    std::fs::remove_file(protected.join(name(1))).unwrap();
    let damaged = protected.join(name(4));
    let mut bytes = std::fs::read(&damaged).unwrap();
    let middle = bytes.len() / 2;
    for byte in &mut bytes[middle..middle + 64] {
        *byte ^= 0x5a;
    }
    std::fs::write(&damaged, bytes).unwrap();

    let entry = protected.join(name(2));
    let entry = entry.to_str().unwrap();
    let verified = run(root, &["par3", "inside", "verify", entry], 1);
    assert_eq!(verified["repairable"], true);
    let repaired = run(root, &["par3", "inside", "repair", entry], 0);
    assert_eq!(repaired["status"], "repaired");
    for part in 1..=7 {
        assert_eq!(
            std::fs::read(protected.join(name(part))).unwrap(),
            pristine[part - 1],
            "volume {part} after repair"
        );
    }
    run(root, &["par3", "inside", "verify", entry], 0);

    run(
        root,
        &["par3", "inside", "remove", entry, "-d", "stripped"],
        0,
    );
    for (part, source) in sources.iter().enumerate() {
        assert_eq!(
            std::fs::read(root.join("stripped").join(name(part + 1))).unwrap(),
            std::fs::read(source).unwrap(),
            "volume {} after removal",
            part + 1
        );
    }
}

#[test]
fn inside_reports_a_missing_volume_no_independent_set_covers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let Some(sources) = originals(root) else {
        return;
    };
    let first = sources[0].to_str().unwrap();
    run(
        root,
        &[
            "par3",
            "inside",
            "insert",
            first,
            "-d",
            "protected",
            "-s",
            "4096",
            "-r",
            "10",
            "--placement",
            "independent",
        ],
        0,
    );
    let protected = root.join("protected");
    std::fs::remove_file(protected.join(name(3))).unwrap();
    let entry = protected.join(name(1));
    let entry = entry.to_str().unwrap();
    let verified = run(root, &["par3", "inside", "verify", entry], 1);
    assert_eq!(verified["repairable"], false);
    assert_eq!(
        verified["unprotected_missing_volumes"],
        serde_json::json!([name(3)])
    );
    let repaired = run(root, &["par3", "inside", "repair", entry], 1);
    assert_eq!(
        repaired["unprotected_missing_volumes"],
        serde_json::json!([name(3)])
    );
}
