//! Tests over the checked-in corpus data: `test-corpus/sources.json`,
//! `test-corpus/profiles.json`, `test-corpus/lock.json` and the toolchain lock,
//! read from this workspace. They run without fixture bytes (paths and digests
//! are all they need), so every CI lane sees them.

#![cfg(test)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::ledger::{Ledger, Source};
use super::lock::{GITHUB_OIDC_ISSUER, Lock, PUBLISH_WORKFLOW_IDENTITY};
use super::manifest::{Manifest, ToolchainLock};
use super::profiles::ProfilesFile;
use super::{LEDGER_FILE, LOCK_FILE, PROFILES_FILE, TOOLCHAINS_FILE, repo_path};

const FIXTURE_ROOTS: [&str; 2] = [
    "crates/unrar-rs/tests/fixtures",
    "crates/par2-rs/tests/fixtures",
];
/// Text that lives beside the fixtures but is not corpus content.
const NON_CORPUS_SUFFIXES: [&str; 4] = [".md", ".sh", ".py", ".txt"];

fn root() -> PathBuf {
    crate::workspace_root()
}

fn load() -> (Ledger, ProfilesFile, ToolchainLock, String) {
    let (lock, lock_sha256) = ToolchainLock::load(&repo_path(&root(), TOOLCHAINS_FILE)).unwrap();
    let ledger = Ledger::load(&repo_path(&root(), LEDGER_FILE)).unwrap();
    let profiles = ProfilesFile::load(&repo_path(&root(), PROFILES_FILE)).unwrap();
    (ledger, profiles, lock, lock_sha256)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn the_ledger_is_consistent_with_the_toolchain_lock_and_has_no_blocked_paths() {
    let (ledger, _, lock, _) = load();
    let findings = ledger.validate(&lock);
    assert!(
        findings.is_empty(),
        "ledger findings:\n{}",
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    let blocked: Vec<&str> = ledger
        .blocked()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert!(
        blocked.is_empty(),
        "blocked paths would stop publication:\n{}",
        blocked.join("\n")
    );
    assert_eq!(ledger.files.len(), 371, "the corpus has 371 fixture paths");
    // The ledger's on-disk layout is the canonical one, so `--update-ledger`
    // never reformats a reviewed file.
    let on_disk = std::fs::read_to_string(repo_path(&root(), LEDGER_FILE)).unwrap();
    assert_eq!(
        on_disk,
        ledger.render().unwrap(),
        "sources.json is not in canonical layout; run `cargo xtask test-corpus build --update-ledger`"
    );
}

#[test]
fn every_fixture_path_in_the_tree_is_in_the_ledger_and_nothing_else_is() {
    let (ledger, _, _, _) = load();
    let mut on_disk = BTreeSet::new();
    for fixture_root in FIXTURE_ROOTS {
        let mut paths = Vec::new();
        walk(&repo_path(&root(), fixture_root), &mut paths);
        for path in paths {
            let relative = path
                .strip_prefix(root())
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let name = relative.rsplit('/').next().unwrap();
            if NON_CORPUS_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
                || name.starts_with('.')
            {
                continue;
            }
            on_disk.insert(relative);
        }
    }
    let listed = ledger.paths();
    let missing: Vec<&String> = on_disk.difference(&listed).collect();
    let extra: Vec<&String> = listed.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "fixture files without a ledger entry:\n{missing:#?}"
    );
    assert!(
        extra.is_empty(),
        "ledger entries with no file in the tree:\n{extra:#?}"
    );
    // Nothing outside the two fixture roots is corpus content: no benchmark
    // output, no source, no scratch.
    for path in &listed {
        assert!(
            FIXTURE_ROOTS
                .iter()
                .any(|fixture_root| path.starts_with(&format!("{fixture_root}/"))),
            "{path} is outside the fixture roots"
        );
        assert!(
            !path.starts_with("bench/") && !path.contains("/target/"),
            "{path} looks like benchmark output"
        );
    }
}

#[test]
fn the_rar_15_and_20_oracles_are_immutable_imports_without_a_rarlab_writer() {
    let (ledger, _, _, _) = load();
    let mut seen = 0;
    for entry in &ledger.files {
        if entry.format == "rar15"
            || entry.format == "rar20"
            || entry.path.ends_with("boat_modern_english.wav")
        {
            seen += 1;
            match &entry.source {
                Source::Upstream { upstream, .. } => {
                    assert_eq!(upstream, "junrar", "{}", entry.path)
                }
                other => panic!("{} must be a junrar import, not {other:?}", entry.path),
            }
        }
    }
    assert_eq!(seen, 4, "three RAR 1.5/2.0 archives and their expected WAV");
    // Structurally, an upstream entry cannot carry toolchains at all; and no
    // generated entry may claim a RAR 1.5/2.0 format either.
    for entry in &ledger.files {
        if let Source::Generated { toolchains, .. } = &entry.source {
            assert!(
                entry.format != "rar15" && entry.format != "rar20",
                "{} claims a synthetic writer for a RAR 1.5/2.0 archive",
                entry.path
            );
            for id in toolchains {
                assert!(
                    id.starts_with("rarlab-")
                        || id.starts_with("ffmpeg-")
                        || id.starts_with("par2cmdline-turbo-"),
                    "{}: unexpected toolchain {id}",
                    entry.path
                );
            }
        }
    }
}

#[test]
fn era_profiles_partition_the_rar_fixtures_by_format() {
    let (ledger, profiles, lock, lock_sha256) = load();
    let manifest = Manifest::build(&ledger, &profiles, &lock, &lock_sha256).unwrap();
    let format_of = |path: &str| manifest.file(path).unwrap().format.clone();
    let members = |name: &str| {
        manifest
            .profiles
            .get(name)
            .unwrap_or_else(|| panic!("profile {name}"))
    };

    for path in members("rar12") {
        let format = format_of(path);
        assert!(
            !format.starts_with("rar4")
                && !format.starts_with("rar5")
                && !format.starts_with("sfx"),
            "rar12 carries {path} ({format})"
        );
    }
    for path in members("rar34") {
        let format = format_of(path);
        assert!(
            !format.starts_with("rar5")
                && !format.starts_with("sfx-rar5")
                && format != "rar15"
                && format != "rar20",
            "rar34 carries {path} ({format})"
        );
    }
    for path in members("rar57") {
        let format = format_of(path);
        assert!(
            !format.starts_with("rar4")
                && !format.starts_with("sfx-rar4")
                && format != "rar15"
                && format != "rar20",
            "rar57 carries {path} ({format})"
        );
    }
    // The three eras cover every unrar-rs fixture between them, and nothing else.
    let mut union: BTreeSet<&String> = BTreeSet::new();
    for name in ["rar12", "rar34", "rar57"] {
        union.extend(members(name));
    }
    let unrar: BTreeSet<&String> = members("unrar").iter().collect();
    assert_eq!(
        union, unrar,
        "rar12 ∪ rar34 ∪ rar57 must equal the unrar profile"
    );
    // Every era carries the originals the integration tests compare against.
    for name in ["rar12", "rar34", "rar57"] {
        assert!(
            members(name)
                .iter()
                .any(|path| path.contains("/originals/")),
            "{name} carries no originals"
        );
    }
    // The lanes' profiles resolve to what the CI hydration patterns resolved to.
    assert_eq!(members("unit").len(), 2);
    assert!(
        members("cli")
            .iter()
            .any(|path| path.ends_with("rar5/rar5_store.rar"))
    );
    assert!(
        members("cli")
            .iter()
            .all(|path| path.ends_with("rar5/rar5_store.rar") || path.contains("/rar5_lz_plain/"))
    );
    assert_eq!(members("ppmd-perf").len(), 3);
    assert_eq!(members("all").len(), ledger.files.len());
    assert_eq!(
        members("unrar").len() + members("par2").len(),
        ledger.files.len()
    );
    // No benchmark output: every profile member is a ledger path under the fixture roots.
    for (name, paths) in &manifest.profiles {
        for path in paths {
            assert!(
                FIXTURE_ROOTS
                    .iter()
                    .any(|fixture_root| path.starts_with(&format!("{fixture_root}/"))),
                "profile {name} carries {path}"
            );
        }
    }
}

#[test]
fn the_lock_is_valid_and_pins_the_publish_workflow_identity() {
    let lock = Lock::load(&repo_path(&root(), LOCK_FILE)).unwrap();
    assert_eq!(
        lock.signature.certificate_identity,
        PUBLISH_WORKFLOW_IDENTITY
    );
    assert_eq!(lock.signature.certificate_oidc_issuer, GITHUB_OIDC_ISSUER);
    // The workflow the identity names must exist in the tree under that name.
    let workflow = repo_path(&root(), ".github/workflows/test-corpus-publish.yml");
    assert!(workflow.is_file(), "{} is missing", workflow.display());
    let text = std::fs::read_to_string(&workflow).unwrap();
    assert!(
        text.contains("workflow_dispatch"),
        "publish workflow must be manual"
    );
    assert!(
        text.contains("refs/heads/main"),
        "publish workflow must refuse other refs"
    );
    for secret in [
        "secrets.R2_CORPUS_ENDPOINT",
        "secrets.R2_CORPUS_S3_ACCESS_KEY",
        "secrets.R2_CORPUS_S3_SECRET",
    ] {
        assert!(text.contains(secret), "publish workflow must read {secret}");
    }
    assert!(
        !text.contains("R2_CORPUS_CF_TOKEN") && !text.contains("sha256sum"),
        "publish workflow must not derive credentials from a CF token"
    );
    assert!(
        !text.contains("pull_request:") && !text.contains("push:"),
        "publish workflow must not run on push or PR"
    );
}

#[test]
fn every_generated_entry_names_toolchains_from_the_shared_lock() {
    let (ledger, _, lock, _) = load();
    let ids = lock.ids();
    for id in [
        "rarlab-3.93",
        "rarlab-4.20",
        "rarlab-5.00",
        "rarlab-6.24",
        "rarlab-7.20",
        "rarlab-7.23",
    ] {
        assert!(ids.contains(id), "toolchain lock is missing {id}");
    }
    let mut used = BTreeSet::new();
    for entry in &ledger.files {
        if let Source::Generated {
            toolchains,
            generator,
            ..
        } = &entry.source
        {
            let declared = &ledger.generators[generator];
            for id in toolchains {
                assert!(ids.contains(id), "{}: {id} is not in the lock", entry.path);
                assert!(
                    declared.toolchains.contains(id),
                    "{}: {id} is not one {generator} may use",
                    entry.path
                );
                used.insert(id.clone());
            }
        }
    }
    // The test corpus is written by 6.24 (RAR4) and 7.20 (RAR5), never by the
    // benchmark-only writers.
    for id in ["rarlab-6.24", "rarlab-7.20"] {
        assert!(used.contains(id), "no fixture names {id}");
    }
    for id in ["rarlab-3.93", "rarlab-4.20", "rarlab-5.00", "rarlab-7.23"] {
        assert!(
            !used.contains(id),
            "a test fixture claims benchmark writer {id}"
        );
    }
}
