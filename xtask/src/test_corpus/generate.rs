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

use super::ledger::{Ledger, Source};
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
    let mut assemble = false;
    let mut imports_only = false;
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
            Some("--assemble") => assemble = true,
            Some("--imports-only") => imports_only = true,
            Some("-h" | "--help") => {
                super::commands::print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown generate option {arg:?}")),
        }
    }
    if assemble && (imports_only || !only.is_empty() || jobs.is_some() || docker.is_some()) {
        return fail(
            "--assemble runs no generator: it takes none of --only, --imports-only, --jobs, --docker",
        );
    }
    if imports_only && !only.is_empty() {
        return fail("--imports-only fetches the upstream imports alone and takes no --only");
    }

    // Fail on a ledger that is inconsistent with itself before spending twenty
    // minutes producing a tree it could not describe.
    let (lock, _) = ToolchainLock::load(&repo_path(root, TOOLCHAINS_FILE))?;
    let ledger = Ledger::load(&repo_path(root, LEDGER_FILE))?;
    super::commands::report(
        &ledger.validate(&lock),
        "ledger is inconsistent with itself or the toolchain lock",
    )?;

    // The assembly half of a fanned-out generation: the per-generator jobs each
    // produced their own share of the tree, and this is the single place that
    // decides whether those shares add up to a corpus revision. No generator
    // runs; a path the ledger lists that no artifact carried is still whatever
    // the checkout left behind, which the refresh below refuses as a Git LFS
    // pointer rather than digesting.
    if assemble {
        println!(
            "test-corpus generate --assemble: no recipe runs; holding the assembled tree under {} \
             to {LEDGER_FILE} and refreshing its sizes and digests",
            FIXTURE_ROOTS.join(" and ")
        );
        return finish(root, ledger);
    }

    let partial = imports_only || !only.is_empty();
    println!(
        "test-corpus generate: rewriting the fixture tree under {}{}",
        FIXTURE_ROOTS.join(" and "),
        if partial {
            ""
        } else {
            ", and the sizes and digests in test-corpus/sources.json, from the checked-in recipes \
             and the pinned upstream imports"
        }
    );

    run_recipes(root, &jobs, &only, &docker, imports_only)?;

    if imports_only {
        println!(
            "test-corpus generate: --imports-only fetched the upstream imports; the path-set check \
             and the ledger refresh belong to the run that assembles the whole tree."
        );
        return Ok(());
    }
    if !only.is_empty() {
        println!(
            "test-corpus generate: --only ran {} recipe(s); the path-set check and the ledger \
             refresh are skipped. Run without --only to produce a corpus revision.",
            only.len()
        );
        return Ok(());
    }

    finish(root, ledger)
}

/// What every path to a corpus revision ends with, whether one runner produced
/// the tree or thirteen did: the tree has to be exactly the ledger's path set,
/// the ledger's sizes and digests are refreshed from the bytes that are there,
/// and the benchmark pins that move with a revision are printed.
fn finish(root: &Path, mut ledger: Ledger) -> Result<()> {
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
    imports_only: bool,
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
    if imports_only {
        command.arg("--imports-only");
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

/// `test-corpus paths`: which fixture paths belong to one part of the corpus.
///
/// Generation fans out one runner per generator, and each runner has to know
/// exactly two things: which files to remove before its recipe runs, so nothing
/// is carried forward from the checkout, and which files to hand on afterwards.
/// Both are this list — the ledger's own answer, never a guess from the shape
/// of the tree.
pub(crate) fn paths(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut generators: Vec<String> = Vec::new();
    let mut upstreams = false;
    let mut all = false;
    let mut verify = false;
    let mut out: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--generator") => generators.push(next_string(&mut iter, "--generator")?),
            Some("--upstreams") => upstreams = true,
            Some("--all") => all = true,
            Some("--verify") => verify = true,
            Some("--out") => out = Some(super::next_path(&mut iter, "--out")?),
            Some("-h" | "--help") => {
                super::commands::print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown paths option {arg:?}")),
        }
    }
    if generators.is_empty() && !upstreams && !all {
        return fail("test-corpus paths needs --generator NAME, --upstreams or --all");
    }

    let ledger = Ledger::load(&repo_path(root, LEDGER_FILE))?;
    for name in &generators {
        if !ledger.generators.contains_key(name) {
            return fail(format!(
                "{name:?} is not a generator in {LEDGER_FILE}; known: {}",
                ledger
                    .generators
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let mut selected: BTreeSet<String> = BTreeSet::new();
    for entry in &ledger.files {
        let wanted = all
            || match &entry.source {
                Source::Generated { generator, .. } => {
                    generators.iter().any(|name| name == generator)
                }
                Source::Upstream { .. } => upstreams,
                Source::Blocked { .. } => false,
            };
        if wanted {
            selected.insert(entry.path.clone());
        }
    }
    if selected.is_empty() {
        return fail("that selection covers no fixture in the ledger");
    }

    if verify {
        verify_produced(root, &ledger, &selected)?;
    }

    let rendered = selected
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    match out {
        Some(path) => {
            write_atomic(&path, rendered.as_bytes())?;
            println!(
                "test-corpus paths: {} path(s) written to {}",
                selected.len(),
                path.display()
            );
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// What a generation job proves before it hands its share of the corpus on:
/// every path it owns is present as produced bytes, and it produced nothing the
/// ledger does not list. The two failures this catches are a recipe that
/// quietly stopped writing a fixture — the tree would still hold the pointer
/// the checkout left — and one that writes a fixture nobody ledgered, which
/// would travel no further than the runner it was written on.
fn verify_produced(root: &Path, ledger: &Ledger, selected: &BTreeSet<String>) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();
    for path in selected {
        let full = repo_path(root, path);
        if !full.is_file() {
            problems.push(format!("{path}: no recipe produced it"));
            continue;
        }
        let digest = super::digest_file(&full)?;
        if digest.lfs_pointer {
            problems.push(format!(
                "{path}: is still a Git LFS pointer, so nothing produced it in this job"
            ));
        } else if digest.size == 0 {
            problems.push(format!("{path}: was produced empty"));
        }
    }
    let listed = ledger.paths();
    for path in corpus_paths_on_disk(root)? {
        if !listed.contains(&path) {
            problems.push(format!("{path}: produced but not listed in {LEDGER_FILE}"));
        }
    }
    if problems.is_empty() {
        println!(
            "test-corpus paths: all {} selected path(s) were produced, and nothing outside {LEDGER_FILE} was",
            selected.len()
        );
        return Ok(());
    }
    problems.sort();
    fail(format!(
        "{} problem(s) with this group's output:\n  {}",
        problems.len(),
        problems.join("\n  ")
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_corpus::blake3_bytes;

    const ALPHA: &str = "crates/unrar-rs/tests/fixtures/rar5/alpha.rar";
    const BETA: &str = "crates/unrar-rs/tests/fixtures/rar5/beta.rar";
    const GAMMA: &str = "crates/par2-rs/tests/fixtures/gamma.rar";
    const IMPORT: &str = "crates/unrar-rs/tests/fixtures/rar4/imported.rar";

    /// A miniature repository whose corpus is split across two generators and
    /// one upstream — the shape the fanned-out publish workflow assembles from.
    fn scaffold(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("xtask-corpus-group-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bench/rarpar-bench/config")).unwrap();
        fs::create_dir_all(root.join("test-corpus")).unwrap();
        fs::copy(
            crate::workspace_root().join(TOOLCHAINS_FILE),
            root.join(TOOLCHAINS_FILE),
        )
        .unwrap();
        // `finish` prints the benchmark pins a corpus revision moves, and they
        // are read from here. One importing case is enough to exercise that
        // tail; its pin is deliberately stale, which is the normal outcome of a
        // regeneration rather than a failure.
        fs::write(
            root.join(super::super::bench_pins::BENCH_CORPUS_FILE),
            r#"{"schema_version":1,"cases":[{"id":"imports-alpha",
               "fixture_dir":"../../crates/unrar-rs/tests/fixtures/rar5",
               "fixture_prefix":"alpha",
               "fixture_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#,
        )
        .unwrap();
        let generated = |generator: &str, path: &str, bytes: &[u8]| {
            format!(
                r#"{{"path":"{path}","size":{},"blake3":"{}","format":"rar5","source":{{"kind":"generated","generator":"{generator}","toolchains":["rarlab-7.20"]}}}}"#,
                bytes.len(),
                blake3_bytes(bytes)
            )
        };
        let import = format!(
            r#"{{"path":"{IMPORT}","size":{},"blake3":"{}","format":"rar15","source":{{"kind":"upstream","upstream":"junrar","path":"src/test/x.rar"}}}}"#,
            b"imported".len(),
            blake3_bytes(b"imported")
        );
        let ledger = format!(
            r#"{{"schema_version":1,"toolchains":"{TOOLCHAINS_FILE}",
                "generators":{{
                  "first":{{"path":"bench/rarpar-bench/internal/testcorpus/first.go","toolchains":["rarlab-7.20"],"byte_reproducible":false}},
                  "second":{{"path":"bench/rarpar-bench/internal/testcorpus/second.go","toolchains":["rarlab-7.20"],"byte_reproducible":false}}}},
                "upstreams":{{"junrar":{{"repository":"https://github.com/junrar/junrar","commit":"0123456789abcdef0123456789abcdef01234567","license":"LicenseRef-UnRAR","encoding":"raw"}}}},
                "files":[{},{},{},{import}]}}"#,
            generated("first", ALPHA, b"alpha"),
            generated("first", BETA, b"beta"),
            generated("second", GAMMA, b"gamma"),
        );
        fs::write(root.join(LEDGER_FILE), ledger).unwrap();
        root
    }

    fn place(root: &Path, path: &str, bytes: &[u8]) {
        write_atomic(&repo_path(root, path), bytes).unwrap();
    }

    fn ledger_of(root: &Path) -> Ledger {
        Ledger::load(&repo_path(root, LEDGER_FILE)).unwrap()
    }

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    /// The list a generation job works from: exactly the ledger's paths for the
    /// group it owns, and every ledger path uploaded by exactly one group.
    #[test]
    fn paths_partitions_the_ledger_by_generator_and_upstream() {
        let root = scaffold("select");
        let out = root.join("paths.txt");
        let listed = |args: &[&str]| {
            let mut argv = arguments(args);
            argv.push("--out".into());
            argv.push(out.clone().into());
            paths(&root, argv).unwrap();
            fs::read_to_string(&out)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(listed(&["--generator", "first"]), vec![ALPHA, BETA]);
        assert_eq!(listed(&["--generator", "second"]), vec![GAMMA]);
        assert_eq!(listed(&["--upstreams"]), vec![IMPORT]);
        // The three groups partition the corpus: no path twice, none left out.
        let mut union = listed(&["--generator", "first"]);
        union.extend(listed(&["--generator", "second"]));
        union.extend(listed(&["--upstreams"]));
        union.sort();
        let mut all = listed(&["--all"]);
        all.sort();
        assert_eq!(union, all, "every ledger path belongs to exactly one group");

        assert!(paths(&root, arguments(&["--generator", "nope"])).is_err());
        assert!(paths(&root, arguments(&[])).is_err(), "no selection");
        let _ = fs::remove_dir_all(root);
    }

    /// `--verify` is what a job runs before handing its share on: a fixture the
    /// recipe did not write is a failure even though the checkout left a file
    /// there, and a fixture nobody ledgered is a failure too.
    #[test]
    fn paths_verify_refuses_pointers_and_unledgered_output() {
        let root = scaffold("verify");
        place(&root, ALPHA, b"alpha");
        place(&root, BETA, b"beta");
        paths(&root, arguments(&["--generator", "first", "--verify"])).unwrap();

        // What a checkout with GIT_LFS_SKIP_SMUDGE leaves where bytes belong.
        place(
            &root,
            BETA,
            b"version https://git-lfs.github.com/spec/v1\noid sha256:0\nsize 4\n",
        );
        let err = paths(&root, arguments(&["--generator", "first", "--verify"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Git LFS pointer"), "{err}");

        place(&root, BETA, b"beta");
        place(&root, "crates/par2-rs/tests/fixtures/stray.par2", b"stray");
        let err = paths(&root, arguments(&["--generator", "first", "--verify"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("stray.par2"), "{err}");

        fs::remove_file(repo_path(&root, "crates/par2-rs/tests/fixtures/stray.par2")).unwrap();
        fs::remove_file(repo_path(&root, ALPHA)).unwrap();
        let err = paths(&root, arguments(&["--generator", "first", "--verify"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no recipe produced it"), "{err}");
        let _ = fs::remove_dir_all(root);
    }

    /// `--assemble` is the one place that decides whether the per-generator
    /// artifacts add up to a corpus revision: exactly the ledger's path set,
    /// digests refreshed from the bytes that arrived, and no recipe run.
    #[test]
    fn assemble_holds_the_gathered_tree_to_the_ledger_and_refreshes_it() {
        let root = scaffold("assemble");
        // A short tree fails before anything is written: what the jobs did not
        // deliver, nothing else may substitute.
        place(&root, ALPHA, b"alpha-regenerated");
        place(&root, BETA, b"beta");
        let err = run(&root, arguments(&["--assemble"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains(GAMMA) && err.contains(IMPORT), "{err}");
        assert_eq!(
            ledger_of(&root).files[0].blake3,
            blake3_bytes(b"alpha"),
            "a failed assembly leaves the ledger untouched"
        );

        place(&root, GAMMA, b"gamma");
        place(&root, IMPORT, b"imported");
        run(&root, arguments(&["--assemble"])).unwrap();
        let refreshed = ledger_of(&root);
        let entry = refreshed
            .files
            .iter()
            .find(|entry| entry.path == ALPHA)
            .unwrap();
        assert_eq!(entry.blake3, blake3_bytes(b"alpha-regenerated"));
        assert_eq!(entry.size, b"alpha-regenerated".len() as u64);

        // A fixture no group owns is as much a break as a missing one.
        place(&root, "crates/unrar-rs/tests/fixtures/rar5/extra.rar", b"x");
        let err = run(&root, arguments(&["--assemble"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not list"), "{err}");
        fs::remove_file(repo_path(
            &root,
            "crates/unrar-rs/tests/fixtures/rar5/extra.rar",
        ))
        .unwrap();

        // A path an artifact did not carry is still the checkout's pointer, and
        // a pointer is never digested into the ledger.
        place(
            &root,
            GAMMA,
            b"version https://git-lfs.github.com/spec/v1\noid sha256:0\nsize 5\n",
        );
        let err = run(&root, arguments(&["--assemble"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Git LFS pointer"), "{err}");

        // --assemble runs no generator, so the options that select one are a
        // contradiction rather than a no-op.
        for conflicting in [
            vec!["--assemble", "--only", "first"],
            vec!["--assemble", "--imports-only"],
            vec!["--assemble", "--jobs", "4"],
        ] {
            assert!(
                run(&root, arguments(&conflicting)).is_err(),
                "{conflicting:?} was accepted"
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}
