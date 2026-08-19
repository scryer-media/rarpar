//! Tests over the checked-in corpus data: `test-corpus/sources.json`,
//! `test-corpus/profiles.json`, `test-corpus/lock.json` and the toolchain lock,
//! read from this workspace. They run without fixture bytes (paths and digests
//! are all they need), so every CI lane sees them.

#![cfg(test)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::generate::{FIXTURE_ROOTS, corpus_paths_on_disk};
use super::ledger::{Ledger, Source};
use super::lock::{GITHUB_OIDC_ISSUER, Lock, PUBLISH_WORKFLOW_IDENTITY};
use super::manifest::{Manifest, ToolchainLock};
use super::profiles::ProfilesFile;
use super::{LEDGER_FILE, LOCK_FILE, PROFILES_FILE, TOOLCHAINS_FILE, repo_path};

fn root() -> PathBuf {
    crate::workspace_root()
}

fn load() -> (Ledger, ProfilesFile, ToolchainLock, String) {
    let (lock, lock_blake3) = ToolchainLock::load(&repo_path(&root(), TOOLCHAINS_FILE)).unwrap();
    let ledger = Ledger::load(&repo_path(&root(), LEDGER_FILE)).unwrap();
    let profiles = ProfilesFile::load(&repo_path(&root(), PROFILES_FILE)).unwrap();
    (ledger, profiles, lock, lock_blake3)
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
    assert_eq!(ledger.files.len(), 376, "the corpus has 376 fixture paths");
    // The ledger's on-disk layout is the canonical one, so `--update-ledger`
    // never reformats a reviewed file.
    // Compared with line endings normalised: a Windows checkout with
    // core.autocrlf rewrites the file to CRLF, which is not a layout change.
    let on_disk = std::fs::read_to_string(repo_path(&root(), LEDGER_FILE))
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        on_disk,
        ledger.render().unwrap(),
        "sources.json is not in canonical layout; run `cargo xtask test-corpus build --update-ledger`"
    );
}

#[test]
fn every_fixture_file_in_the_tree_is_in_the_ledger() {
    let (ledger, _, _, _) = load();
    let on_disk = corpus_paths_on_disk(&root()).unwrap();
    let listed = ledger.paths();
    let missing: Vec<&String> = on_disk.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "fixture files without a ledger entry:\n{missing:#?}"
    );
    // The converse — every ledger path present on disk — is deliberately NOT
    // asserted here. Since the corpus left Git LFS the repository carries no
    // fixture bytes, so an unhydrated checkout (this test's normal habitat:
    // the no-fixture unit-tests lane, a fresh clone) legitimately has none of
    // them. Presence is hydration's contract, enforced where hydration
    // happens: `hydrate` fails on any shortfall, and the corpus lanes run
    // `verify --all-present` after it.
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

/// The corpus is generated, not carried forward, and that has two checkable
/// consequences here: nothing may come from an upstream the publish workflow
/// cannot re-fetch, and every generated entry's recipe has to exist in the tree.
///
/// The third — that every recipe the ledger declares is one `generate` actually
/// runs — is checked on the Go side, in
/// `bench/rarpar-bench/internal/testcorpus`, because that is where the
/// orchestrator's table lives. It is the seam that would rot silently: a
/// generator added to the ledger and not to the orchestrator produces nothing,
/// and the corpus would simply be short a fixture.
#[test]
fn every_fixture_is_reproducible_and_names_a_recipe_that_exists() {
    let (ledger, _, _, _) = load();

    for (name, upstream) in &ledger.upstreams {
        assert!(
            !upstream.private,
            "upstream {name} is private: the publish workflow cannot re-fetch it, so the corpus \
             cannot be generated from it"
        );
    }

    for entry in &ledger.files {
        if let Source::Generated { generator, .. } = &entry.source {
            let declared = ledger
                .generators
                .get(generator)
                .unwrap_or_else(|| panic!("{}: generator {generator} is not declared", entry.path));
            assert!(
                repo_path(&root(), &declared.path).is_file(),
                "{}: generator script {} is missing from the tree",
                entry.path,
                declared.path
            );
        }
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
    let (ledger, profiles, lock, lock_blake3) = load();
    let manifest = Manifest::build(&ledger, &profiles, &lock, &lock_blake3).unwrap();
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
