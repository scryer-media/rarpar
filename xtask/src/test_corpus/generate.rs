//! `test-corpus generate`: produce the whole corpus from its recipes.
//!
//! The corpus is *generated*, never carried forward: every fixture is either
//! written by a checked-in recipe on the shared pinned toolchain, or fetched
//! byte-identically from a public upstream at its pinned commit.
//!
//! The recipes themselves live in Go, in
//! `bench/rarpar-bench/internal/testcorpus`, so they run wherever the harness
//! does — Windows included — and so the pinned FFmpeg encoder is called in
//! process rather than through another shell. This command delegates to them
//! exactly the way `xtask bench` delegates to the harness, and then does the
//! ledger-side work in Rust: the produced tree has to be exactly the ledger's
//! path set, and the ledger's sizes and digests are refreshed to match.
//!
//! It rewrites the fixture tree in place. That is the point — a corpus revision
//! is a regeneration — but it means the working tree's fixture bytes and the
//! ledger's digests are both replaced by whatever this run produced.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ledger::Ledger;
use super::manifest::ToolchainLock;
use super::{LEDGER_FILE, Result, TOOLCHAINS_FILE, fail, next_string, repo_path, write_atomic};

/// The two directories that hold corpus content.
pub(crate) const FIXTURE_ROOTS: [&str; 2] = [
    "crates/unrar-rs/tests/fixtures",
    "crates/par2-rs/tests/fixtures",
];

/// Text that lives beside the fixtures but is not corpus content: the
/// generators that are still scripts, the READMEs, and the small text inputs
/// which are ordinary tracked files rather than published objects.
pub(crate) const NON_CORPUS_SUFFIXES: [&str; 4] = [".md", ".sh", ".py", ".txt"];

/// Where the recipes live.
const HARNESS_DIR: &str = "bench/rarpar-bench";

pub(crate) fn run(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut jobs: Option<String> = None;
    let mut only: Vec<String> = Vec::new();
    let mut docker: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--jobs") => {
                let value = next_string(&mut iter, "--jobs")?;
                if value.parse::<usize>().unwrap_or(0) == 0 {
                    return fail("--jobs must be a positive integer");
                }
                jobs = Some(value);
            }
            Some("--only") => only.push(next_string(&mut iter, "--only")?),
            Some("--docker") => docker = Some(next_string(&mut iter, "--docker")?),
            Some("-h" | "--help") => {
                super::commands::print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown generate option {arg:?}")),
        }
    }

    // Fail on a ledger that is inconsistent with itself before spending twenty
    // minutes producing a tree it could not describe.
    let (lock, _) = ToolchainLock::load(&repo_path(root, TOOLCHAINS_FILE))?;
    let mut ledger = Ledger::load(&repo_path(root, LEDGER_FILE))?;
    super::commands::report(
        &ledger.validate(&lock),
        "ledger is inconsistent with itself or the toolchain lock",
    )?;

    println!(
        "test-corpus generate: rewriting the fixture tree under {}{}",
        FIXTURE_ROOTS.join(" and "),
        if only.is_empty() {
            ", and the sizes and digests in test-corpus/sources.json, from the checked-in recipes \
             and the pinned upstream imports"
        } else {
            ""
        }
    );

    run_recipes(root, &jobs, &only, &docker)?;

    if !only.is_empty() {
        println!(
            "test-corpus generate: --only ran {} recipe(s); the path-set check and the ledger \
             refresh are skipped. Run without --only to produce a corpus revision.",
            only.len()
        );
        return Ok(());
    }

    check_path_set(root, &ledger)?;

    let changed = ledger.refresh_digests(root)?;
    write_atomic(&repo_path(root, LEDGER_FILE), ledger.render()?.as_bytes())?;

    let total: u64 = ledger.files.iter().map(|entry| entry.size).sum();
    println!(
        "test-corpus generate: {} fixture(s), {total} bytes; {changed} ledger digest(s) refreshed \
         in {LEDGER_FILE}",
        ledger.files.len()
    );

    // The benchmark corpus imports six fixture sets by digest, so a corpus
    // revision moves those pins. Print them here rather than making the operator
    // remember a second command.
    let pins = super::bench_pins::pins_from_tree(root)?;
    print!("{}", super::bench_pins::render(&pins));
    let moved = pins
        .iter()
        .filter(|pin| pin.pinned_sha256 != pin.computed_sha256)
        .count();
    println!(
        "test-corpus generate: {moved} of {} benchmark fixture pin(s) moved; land them in {} with \
         this revision",
        pins.len(),
        super::bench_pins::BENCH_CORPUS_FILE
    );
    Ok(())
}

/// Run the Go recipes, the same delegation `xtask bench` performs.
fn run_recipes(
    root: &Path,
    jobs: &Option<String>,
    only: &[String],
    docker: &Option<String>,
) -> Result<()> {
    let harness = root.join(HARNESS_DIR);
    if !harness.join("go.mod").is_file() {
        return fail(format!("benchmark harness is missing {HARNESS_DIR}/go.mod"));
    }
    let mut command = Command::new("go");
    command
        .args(["run", "./cmd/rarpar-bench", "testcorpus", "generate"])
        .current_dir(&harness)
        .env("RARPAR_BENCH_WORKSPACE_ROOT", root);
    if let Some(jobs) = jobs {
        command.args(["--jobs", jobs]);
    }
    for name in only {
        command.args(["--only", name]);
    }
    if let Some(docker) = docker {
        command.args(["--docker", docker]);
    }
    let status = command
        .status()
        .map_err(|source| super::error(format!("run go run ./cmd/rarpar-bench: {source}")))?;
    if !status.success() {
        return fail(format!("corpus generation exited with {status}"));
    }
    Ok(())
}

/// Every corpus file in the tree, by repository-relative path. The rule matches
/// the one `checked_in.rs` holds the ledger to, so "the tree" means the same
/// thing in both places.
pub(crate) fn corpus_paths_on_disk(root: &Path) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for fixture_root in FIXTURE_ROOTS {
        let mut found = Vec::new();
        walk(&repo_path(root, fixture_root), &mut found)?;
        for path in found {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| super::error(format!("{} is outside the tree", path.display())))?
                .to_string_lossy()
                .replace('\\', "/");
            let name = relative.rsplit('/').next().unwrap_or_default();
            if NON_CORPUS_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
                || name.starts_with('.')
            {
                continue;
            }
            paths.insert(relative);
        }
    }
    Ok(paths)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// The produced tree has to be exactly the ledger's path set: a fixture the
/// recipes no longer write is as much a break as one they write and nobody
/// ledgered.
fn check_path_set(root: &Path, ledger: &Ledger) -> Result<()> {
    let on_disk = corpus_paths_on_disk(root)?;
    let listed = ledger.paths();
    let missing: Vec<&String> = listed.difference(&on_disk).collect();
    let extra: Vec<&String> = on_disk.difference(&listed).collect();
    if missing.is_empty() && extra.is_empty() {
        println!(
            "test-corpus generate: the produced tree is exactly the ledger's {} path(s)",
            listed.len()
        );
        return Ok(());
    }
    let mut message = String::new();
    if !missing.is_empty() {
        message.push_str(&format!(
            "{} ledger path(s) no recipe produced:\n  {}\n",
            missing.len(),
            missing
                .iter()
                .map(|path| path.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        ));
    }
    if !extra.is_empty() {
        message.push_str(&format!(
            "{} produced path(s) the ledger does not list:\n  {}\n",
            extra.len(),
            extra
                .iter()
                .map(|path| path.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        ));
    }
    fail(message)
}
