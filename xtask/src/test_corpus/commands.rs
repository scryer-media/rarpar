//! `test-corpus build | verify | fetch | publish`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use super::curl::{self, Download, S3Credentials};
use super::ledger::{Finding, Ledger};
use super::lock::Lock;
use super::manifest::{Manifest, Provenance, ToolchainLock};
use super::profiles::ProfilesFile;
use super::sigstore;
use super::{
    LEDGER_FILE, LOCK_FILE, MANIFESTS_PREFIX, OBJECTS_PREFIX, PROFILES_FILE, Result,
    TOOLCHAINS_FILE, blake3_bytes, digest_file, fail, next_path, next_string, repo_path,
    write_atomic,
};

pub(crate) fn run(args: Vec<OsString>) -> Result<()> {
    let root = crate::workspace_root();
    let mut args = args.into_iter();
    let command = args.next().and_then(|arg| arg.into_string().ok());
    match command.as_deref() {
        Some("build") => build(&root, args.collect()),
        Some("generate") => super::generate::run(&root, args.collect()),
        Some("bench-pins") => super::bench_pins::run(&root, args.collect()),
        Some("verify") => verify(&root, args.collect()),
        Some("fetch") => fetch(&root, args.collect()),
        Some("hydrate") => hydrate(&root, args.collect()),
        Some("sign") => sign(args.collect()),
        Some("publish") => publish(&root, args.collect()),
        Some("-h" | "--help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => fail(format!("unknown test-corpus command {other:?}")),
    }
}

pub(crate) fn print_usage() {
    eprintln!(
        "\
Usage:
  cargo run -p xtask -- test-corpus generate [--jobs N] [--only GENERATOR]...
      Produce the whole corpus from its recipes: run every generator on the
      pinned toolchain images, fetch every upstream import at its pinned commit,
      require the produced tree to be exactly the ledger's path set, and refresh
      the ledger's sizes and digests. REWRITES the fixture tree and
      test-corpus/sources.json. --only runs named generators and skips the
      upstreams, the path-set check and the ledger refresh.
  cargo run -p xtask -- test-corpus bench-pins [--out FILE]
      Recompute the benchmark corpus's fixture_sha256 pins the way the Go
      harness does — SHA-256, because that is what the benchmark corpus's own
      contract specifies — and print old -> new for
      bench/rarpar-bench/config/corpus.json. Reads the fixture bytes.
  cargo run -p xtask -- test-corpus build [--out DIR] [--update-ledger]
      Validate test-corpus/sources.json against the tree and the toolchain lock,
      resolve profiles, and write DIR/manifest.json, DIR/manifest.blake3,
      DIR/provenance.json and DIR/objects.tsv (default DIR: target/test-corpus/build).
      --update-ledger refreshes sizes/digests of paths already in the ledger.
  cargo run -p xtask -- test-corpus verify [--require-signature] [--offline] [--all-present] [--upstreams]
      Check ledger vs tree, recompute the manifest and compare it to the lock,
      verify the published manifest's Sigstore bundle (with cosign), and with
      --upstreams re-fetch every public upstream import at its pinned commit.
  cargo run -p xtask -- test-corpus fetch --profile NAME [--profile NAME]... [--check] [--parallel N]
      Hydrate the named profiles from the locked manifest into the tree,
      verifying every object digest. Fails before Cargo when anything is missing.
  cargo run -p xtask -- test-corpus hydrate --profile NAME [--profile NAME]... [--parallel N]
      What CI runs before Cargo: `fetch` when test-corpus/lock.json pins a
      published manifest, otherwise a verified `git lfs pull` of the same
      profiles. Either way every fixture is digest-checked and a shortfall fails.
  cargo run -p xtask -- test-corpus sign --dir DIR
      Sign DIR/manifest.json and DIR/provenance.json keyless with cosign under
      the ambient OIDC identity (publish workflow only).
  cargo run -p xtask -- test-corpus publish --dir DIR --base-url URL --s3-endpoint URL [--bucket NAME]
      Upload objects, manifest, provenance and their Sigstore bundles from a
      build directory (publish workflow only; credentials from
      R2_CORPUS_ACCESS_KEY_ID / R2_CORPUS_SECRET_ACCESS_KEY)."
    );
}

// -------------------------------------------------------------- hydrate ----

/// The one hydration entry point CI and developers use. While the lock pins
/// no published manifest it pulls the same profiles through Git LFS (the
/// legacy transport) and verifies every file against the ledger; once a
/// manifest is pinned it is `fetch`. Either way, a fixture that is missing,
/// still a pointer, or has the wrong digest fails the step before any test.
fn hydrate(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut profiles: Vec<String> = Vec::new();
    let mut parallel = 8usize;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--profile") => profiles.push(next_string(&mut iter, "--profile")?),
            Some("--parallel") => {
                parallel = next_string(&mut iter, "--parallel")?
                    .parse()
                    .map_err(|_| super::error("--parallel must be a positive integer"))?;
            }
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown hydrate option {arg:?}")),
        }
    }
    if profiles.is_empty() {
        return fail("hydrate requires at least one --profile");
    }
    let lock = Lock::load(&repo_path(root, LOCK_FILE))?;
    if !lock.is_unpublished() {
        let mut forwarded: Vec<OsString> = Vec::new();
        for profile in &profiles {
            forwarded.push("--profile".into());
            forwarded.push(profile.into());
        }
        forwarded.push("--parallel".into());
        forwarded.push(parallel.to_string().into());
        return fetch(root, forwarded);
    }

    // Legacy transport: Git LFS, with the profile globs as the include set (the
    // profile vocabulary is the `git lfs pull --include` vocabulary).
    let inputs = load_inputs(root)?;
    let pulls = lfs_pull_plan(&inputs.profiles, &profiles)?;
    let resolved = inputs.profiles.resolve(&inputs.ledger.paths())?;
    let mut wanted: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    for name in &profiles {
        wanted.extend(&resolved[name]);
    }
    println!(
        "test-corpus hydrate: no published manifest pinned; pulling profiles [{}] ({} files) through Git LFS",
        profiles.join(", "),
        wanted.len()
    );
    let git = |args: &[&str]| -> Result<()> {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .map_err(|source| super::error(format!("run git {}: {source}", args.join(" "))))?;
        if !status.success() {
            return fail(format!("git {} failed ({status})", args.join(" ")));
        }
        Ok(())
    };
    git(&["lfs", "install", "--local"])?;
    for (include_arg, exclude_arg) in &pulls {
        git(&["lfs", "pull", include_arg, exclude_arg])?;
    }

    // Verify against the ledger, not against a pointer prefix: every wanted
    // file present, real bytes, right digest.
    let wanted_count = wanted.len();
    let mut failures = Vec::new();
    for path in wanted {
        let Some(entry) = inputs.ledger.files.iter().find(|entry| &entry.path == path) else {
            failures.push(format!(
                "{path}: resolved by a profile but has no ledger entry"
            ));
            continue;
        };
        let file = repo_path(root, path);
        match digest_file(&file) {
            Err(err) => failures.push(format!("{path}: {err}")),
            Ok(digest) if digest.lfs_pointer => {
                failures.push(format!("{path}: still a Git LFS pointer after pull"))
            }
            Ok(digest) if digest.blake3 != entry.blake3 || digest.size != entry.size => failures
                .push(format!(
                    "{path}: hydrated bytes hash to {} ({} bytes), ledger says {} ({} bytes)",
                    digest.blake3, digest.size, entry.blake3, entry.size
                )),
            Ok(_) => {}
        }
    }
    if !failures.is_empty() {
        failures.sort();
        return fail(format!(
            "test-corpus hydrate: {} fixture(s) not hydrated\n  {}",
            failures.len(),
            failures.join("\n  ")
        ));
    }
    println!(
        "test-corpus hydrate: {wanted_count} fixture(s) present and verified against the ledger"
    );
    Ok(())
}

/// The `git lfs pull` argument pairs the named profiles need: one
/// `(--include, --exclude)` pull per profile, never one pull over merged
/// patterns. An exclude belongs to the profile that declares it, so merging
/// would let `rar34`'s exclusions cancel `rar12`'s includes whenever both are
/// asked for on one command line — and the ledger check afterwards would then
/// fail on files the caller legitimately asked for.
fn lfs_pull_plan(profiles: &ProfilesFile, names: &[String]) -> Result<Vec<(String, String)>> {
    let mut pulls: Vec<(String, String)> = Vec::new();
    for name in names {
        let profile = profiles.profiles.get(name).ok_or_else(|| {
            super::error(format!(
                "profile {name:?} is not defined in {PROFILES_FILE}"
            ))
        })?;
        let pull = (
            format!("--include={}", profile.include.join(",")),
            format!("--exclude={}", profile.exclude.join(",")),
        );
        if !pulls.contains(&pull) {
            pulls.push(pull);
        }
    }
    Ok(pulls)
}

// ----------------------------------------------------------------- sign ----

fn sign(args: Vec<OsString>) -> Result<()> {
    let mut dir: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--dir") => dir = Some(next_path(&mut iter, "--dir")?),
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown sign option {arg:?}")),
        }
    }
    let dir = dir.ok_or_else(|| super::error("--dir is required"))?;
    if !sigstore::cosign_available() {
        return fail("cosign is not installed (install cosign, or set RARPAR_COSIGN)");
    }
    let manifest_blake3 = fs::read_to_string(dir.join("manifest.blake3"))?
        .trim()
        .to_owned();
    let manifest_bytes = fs::read(dir.join("manifest.json"))?;
    if blake3_bytes(&manifest_bytes) != manifest_blake3 {
        return fail("manifest.json does not hash to manifest.blake3; rebuild before signing");
    }
    for document in ["manifest.json", "provenance.json"] {
        let blob = dir.join(document);
        let bundle = dir.join(format!("{document}.sigstore.json"));
        sigstore::sign_blob(&blob, &bundle)?;
        println!(
            "test-corpus sign: {} -> {}",
            blob.display(),
            bundle.display()
        );
    }
    Ok(())
}

pub(crate) fn report(findings: &[Finding], what: &str) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    let mut lines: Vec<String> = findings.iter().map(ToString::to_string).collect();
    lines.sort();
    lines.dedup();
    fail(format!(
        "{what}: {} problem(s)\n  {}",
        lines.len(),
        lines.join("\n  ")
    ))
}

/// Everything the tree says about the corpus, loaded and structurally valid.
struct Inputs {
    ledger: Ledger,
    profiles: ProfilesFile,
    lock: ToolchainLock,
    lock_blake3: String,
}

fn load_inputs(root: &Path) -> Result<Inputs> {
    let (lock, lock_blake3) = ToolchainLock::load(&repo_path(root, TOOLCHAINS_FILE))?;
    let ledger = Ledger::load(&repo_path(root, LEDGER_FILE))?;
    let profiles = ProfilesFile::load(&repo_path(root, PROFILES_FILE))?;
    report(
        &ledger.validate(&lock),
        "ledger is inconsistent with itself or the toolchain lock",
    )?;
    Ok(Inputs {
        ledger,
        profiles,
        lock,
        lock_blake3,
    })
}

// ---------------------------------------------------------------- build ----

fn build(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut out = root.join("target").join("test-corpus").join("build");
    let mut update_ledger = false;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--out") => out = next_path(&mut iter, "--out")?,
            Some("--update-ledger") => update_ledger = true,
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown build option {arg:?}")),
        }
    }
    let mut inputs = load_inputs(root)?;
    if update_ledger {
        let changed = inputs.ledger.refresh_digests(root)?;
        write_atomic(
            &repo_path(root, LEDGER_FILE),
            inputs.ledger.render()?.as_bytes(),
        )?;
        eprintln!("test-corpus: refreshed {changed} ledger digest(s) in {LEDGER_FILE}");
    }
    report(
        &inputs.ledger.check_tree(root, true),
        "tree disagrees with the ledger",
    )?;
    let manifest = Manifest::build(
        &inputs.ledger,
        &inputs.profiles,
        &inputs.lock,
        &inputs.lock_blake3,
    )?;
    let bytes = manifest.canonical_bytes()?;
    let digest = blake3_bytes(&bytes);
    let provenance = Provenance::from_environment(&manifest, &digest, &inputs.lock_blake3);
    let mut provenance_bytes = serde_json::to_vec_pretty(&provenance)?;
    provenance_bytes.push(b'\n');

    fs::create_dir_all(&out)?;
    write_atomic(&out.join("manifest.json"), &bytes)?;
    write_atomic(
        &out.join("manifest.blake3"),
        format!("{digest}\n").as_bytes(),
    )?;
    write_atomic(&out.join("provenance.json"), &provenance_bytes)?;
    // objects.tsv: "<blake3>\t<repo path>" for every file, so the publisher and
    // a human can see exactly what a publication uploads.
    let mut objects = String::new();
    for file in &manifest.files {
        objects.push_str(&file.blake3);
        objects.push('\t');
        objects.push_str(&file.path);
        objects.push('\n');
    }
    write_atomic(&out.join("objects.tsv"), objects.as_bytes())?;
    println!(
        "test-corpus: manifest {digest} ({} files, {} bytes, {} profiles) written to {}",
        manifest.files.len(),
        manifest.files.iter().map(|file| file.size).sum::<u64>(),
        manifest.profiles.len(),
        out.display()
    );
    for (name, members) in &manifest.profiles {
        println!("  profile {name}: {} files", members.len());
    }
    Ok(())
}

// --------------------------------------------------------------- verify ----

fn verify(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut require_signature = false;
    let mut offline = false;
    let mut all_present = false;
    let mut upstreams = false;
    for arg in args {
        match arg.to_str() {
            Some("--require-signature") => require_signature = true,
            Some("--offline") => offline = true,
            Some("--all-present") => all_present = true,
            Some("--upstreams") => upstreams = true,
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown verify option {arg:?}")),
        }
    }
    let inputs = load_inputs(root)?;
    let mut problems: Vec<String> = Vec::new();

    let findings = inputs.ledger.check_tree(root, all_present);
    problems.extend(findings.iter().map(ToString::to_string));
    let blocked = inputs.ledger.blocked();
    for entry in &blocked {
        problems.push(format!("{}: blocked on incomplete provenance", entry.path));
    }
    if upstreams {
        if offline {
            problems.push("--upstreams cannot be satisfied with --offline".to_owned());
        } else {
            let checks = super::upstream::verify_public_upstreams(&inputs.ledger);
            let verified = checks.iter().filter(|check| check.outcome.is_ok()).count();
            for check in &checks {
                if let Err(err) = &check.outcome {
                    problems.push(format!("{} ({}): {err}", check.path, check.upstream));
                }
            }
            println!(
                "test-corpus: {verified} of {} public upstream import(s) re-fetched byte-identical at their pinned commits",
                checks.len()
            );
        }
    }

    let lock = Lock::load(&repo_path(root, LOCK_FILE))?;
    if !blocked.is_empty() {
        // The manifest cannot be built; report and stop before touching the lock.
        problems.sort();
        return fail(format!(
            "test-corpus verify: {} problem(s)\n  {}",
            problems.len(),
            problems.join("\n  ")
        ));
    }
    let manifest = Manifest::build(
        &inputs.ledger,
        &inputs.profiles,
        &inputs.lock,
        &inputs.lock_blake3,
    )?;
    let bytes = manifest.canonical_bytes()?;
    let digest = blake3_bytes(&bytes);
    println!("test-corpus: manifest recomputed from the tree: {digest}");

    if lock.is_unpublished() {
        // Nothing is published, so there is nothing whose signature could be
        // required; the flag becomes effective the moment a manifest is pinned,
        // which is what lets CI carry it before the first publication.
        println!(
            "test-corpus: lock.json pins no published manifest yet (LFS hydration remains in force{})",
            if require_signature {
                "; --require-signature applies once a manifest is pinned"
            } else {
                ""
            }
        );
    } else {
        if lock.manifest.blake3 != digest {
            problems.push(format!(
                "lock.json pins manifest {} but the tree recomputes {digest}; republish and re-pin, or restore the ledger",
                lock.manifest.blake3
            ));
        }
        if !offline {
            match curl::get_to_vec(&lock.manifest.url) {
                Err(err) => problems.push(format!("published manifest unavailable: {err}")),
                Ok(published) => {
                    let published_digest = blake3_bytes(&published);
                    if published_digest != lock.manifest.blake3 {
                        problems.push(format!(
                            "published manifest at {} hashes to {published_digest}, lock pins {}",
                            lock.manifest.url, lock.manifest.blake3
                        ));
                    } else if published != bytes {
                        problems.push("published manifest bytes differ from the recomputed manifest despite equal digest".to_owned());
                    } else {
                        println!("test-corpus: published manifest matches the lock and the tree");
                        let signature = verify_signature(&lock, &published);
                        match (signature, require_signature) {
                            (Ok(()), _) => println!(
                                "test-corpus: Sigstore bundle verified for {}",
                                lock.signature.certificate_identity
                            ),
                            (Err(err), true) => {
                                problems.push(format!("signature verification failed: {err}"))
                            }
                            (Err(err), false) => {
                                eprintln!("test-corpus: warning: signature not verified: {err}")
                            }
                        }
                    }
                }
            }
        } else if require_signature {
            problems.push("--require-signature cannot be satisfied with --offline".to_owned());
        }
    }
    if problems.is_empty() {
        println!(
            "test-corpus verify: ok ({} ledger entries)",
            inputs.ledger.files.len()
        );
        return Ok(());
    }
    problems.sort();
    problems.dedup();
    fail(format!(
        "test-corpus verify: {} problem(s)\n  {}",
        problems.len(),
        problems.join("\n  ")
    ))
}

/// Verify the pinned manifest's Sigstore bundle with cosign: exact workflow
/// identity, exact issuer. Requires cosign on PATH (or `RARPAR_COSIGN`).
fn verify_signature(lock: &Lock, manifest_bytes: &[u8]) -> Result<()> {
    if !sigstore::cosign_available() {
        return fail("cosign is not installed (install cosign, or set RARPAR_COSIGN)");
    }
    let bundle = curl::get_to_vec(&lock.signature.bundle_url)?;
    let dir = std::env::temp_dir().join(format!("rarpar-corpus-verify-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let manifest_path = dir.join("manifest.json");
    let bundle_path = dir.join("manifest.json.sigstore.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, &bundle)?;
    let result = sigstore::verify_blob(
        &manifest_path,
        &bundle_path,
        &lock.signature.certificate_identity,
        &lock.signature.certificate_oidc_issuer,
    );
    let _ = fs::remove_dir_all(&dir);
    result
}

// ---------------------------------------------------------------- fetch ----

fn fetch(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut profiles: Vec<String> = Vec::new();
    let mut check_only = false;
    let mut parallel = 8usize;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--profile") => profiles.push(next_string(&mut iter, "--profile")?),
            Some("--check") => check_only = true,
            Some("--parallel") => {
                parallel = next_string(&mut iter, "--parallel")?
                    .parse()
                    .map_err(|_| super::error("--parallel must be a positive integer"))?;
                if parallel == 0 {
                    return fail("--parallel must be a positive integer");
                }
            }
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown fetch option {arg:?}")),
        }
    }
    if profiles.is_empty() {
        return fail("fetch requires at least one --profile");
    }
    let lock = Lock::load(&repo_path(root, LOCK_FILE))?;
    if lock.is_unpublished() {
        return fail(format!(
            "{LOCK_FILE} pins no published manifest; publish a corpus and pin it before fetching (LFS hydration remains the transport until then)"
        ));
    }
    let manifest = locked_manifest(root, &lock)?;
    let wanted = manifest.select(&profiles)?;
    // Objects are content-addressed, so identical bytes under two paths are one
    // download: plan per digest, then place per path.
    let mut missing: Vec<&super::manifest::ManifestFile> = Vec::new();
    let mut present = 0usize;
    for file in &wanted {
        let destination = repo_path(root, &file.path);
        if destination.is_file() {
            let digest = digest_file(&destination)?;
            if !digest.lfs_pointer && digest.blake3 == file.blake3 && digest.size == file.size {
                present += 1;
                continue;
            }
        }
        missing.push(file);
    }
    let scratch = root.join("target").join("test-corpus").join("objects");
    let mut downloads: Vec<Download> = Vec::new();
    let mut by_digest: BTreeMap<String, PathBuf> = BTreeMap::new();
    for file in &missing {
        by_digest.entry(file.blake3.clone()).or_insert_with(|| {
            let temp = scratch.join(format!("{}.{}.part", file.blake3, std::process::id()));
            downloads.push(Download {
                url: lock.object_url(&file.blake3),
                destination: temp.clone(),
            });
            temp
        });
    }
    println!(
        "test-corpus fetch: profiles [{}] = {} files; {present} already present, {} to fetch ({} objects)",
        profiles.join(", "),
        wanted.len(),
        missing.len(),
        downloads.len()
    );
    if check_only {
        if missing.is_empty() {
            return Ok(());
        }
        let mut paths: Vec<&str> = missing.iter().map(|file| file.path.as_str()).collect();
        paths.sort();
        return fail(format!(
            "{} fixture(s) missing or stale:\n  {}",
            paths.len(),
            paths.join("\n  ")
        ));
    }
    if missing.is_empty() {
        return Ok(());
    }
    let transfers = curl::get_many(&downloads, parallel)?;
    // Verify every downloaded object once, by digest.
    let mut verified: BTreeMap<&String, std::result::Result<(), String>> = BTreeMap::new();
    for (blake3, temp) in &by_digest {
        let url = lock.object_url(blake3);
        let status = transfers
            .iter()
            .find(|transfer| transfer.url == url)
            .map(|transfer| transfer.status);
        let outcome = (|| -> Result<()> {
            match status {
                Some(status) if (200..300).contains(&status) => {}
                Some(status) => return fail(format!("HTTP {status} for {url}")),
                None => return fail(format!("no transfer result for {url}")),
            }
            let digest = digest_file(temp)?;
            if digest.blake3 != *blake3 {
                return fail(format!(
                    "object {url} hashed to {} ({} bytes), manifest says {blake3}",
                    digest.blake3, digest.size
                ));
            }
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(temp);
        }
        verified.insert(blake3, outcome.map_err(|err| err.to_string()));
    }
    // Place each path: the last path for a digest takes the temp file, the
    // others copy it, all through the atomic write path.
    let mut failures = Vec::new();
    let mut remaining: BTreeMap<&String, usize> = BTreeMap::new();
    for file in &missing {
        *remaining.entry(&file.blake3).or_default() += 1;
    }
    for file in &missing {
        let destination = repo_path(root, &file.path);
        let temp = &by_digest[&file.blake3];
        let outcome = match &verified[&file.blake3] {
            Err(err) => Err(err.clone()),
            Ok(()) => {
                let left = remaining.get_mut(&file.blake3).expect("counted");
                *left -= 1;
                let result = if *left == 0 {
                    match destination.parent() {
                        Some(parent) => fs::create_dir_all(parent).map_err(|err| err.to_string()),
                        None => Ok(()),
                    }
                    .and_then(|()| {
                        super::rename_into_place(temp, &destination).map_err(|err| err.to_string())
                    })
                } else {
                    fs::read(temp)
                        .map_err(|err| err.to_string())
                        .and_then(|bytes| {
                            write_atomic(&destination, &bytes).map_err(|err| err.to_string())
                        })
                };
                result.and_then(|()| {
                    // Size is checked on the placed file: the digest was
                    // checked on the object, and a copy is only a copy.
                    let placed = digest_file(&destination).map_err(|err| err.to_string())?;
                    if placed.blake3 != file.blake3 || placed.size != file.size {
                        return Err(format!(
                            "placed file hashes to {} ({} bytes), manifest says {} ({} bytes)",
                            placed.blake3, placed.size, file.blake3, file.size
                        ));
                    }
                    Ok(())
                })
            }
        };
        if let Err(err) = outcome {
            failures.push(format!("{}: {err}", file.path));
        }
    }
    for temp in by_digest.values() {
        let _ = fs::remove_file(temp);
    }
    if !failures.is_empty() {
        failures.sort();
        failures.dedup();
        return fail(format!(
            "test-corpus fetch: {} of {} fixture(s) failed; nothing partial was written\n  {}",
            failures.len(),
            missing.len(),
            failures.join("\n  ")
        ));
    }
    println!(
        "test-corpus fetch: {} fixture(s) hydrated and verified",
        missing.len()
    );
    Ok(())
}

/// The manifest the lock pins: from the local cache when its digest matches,
/// otherwise downloaded, digest-checked and cached.
fn locked_manifest(root: &Path, lock: &Lock) -> Result<Manifest> {
    let cache = root
        .join("target")
        .join("test-corpus")
        .join("manifests")
        .join(format!("{}.json", lock.manifest.blake3));
    if cache.is_file() {
        let bytes = fs::read(&cache)?;
        if blake3_bytes(&bytes) == lock.manifest.blake3 {
            return Manifest::parse(&bytes);
        }
        let _ = fs::remove_file(&cache);
    }
    let bytes = curl::get_to_vec(&lock.manifest.url)?;
    let digest = blake3_bytes(&bytes);
    if digest != lock.manifest.blake3 {
        return fail(format!(
            "manifest at {} hashes to {digest}, lock pins {}",
            lock.manifest.url, lock.manifest.blake3
        ));
    }
    let manifest = Manifest::parse(&bytes)?;
    write_atomic(&cache, &bytes)?;
    Ok(manifest)
}

// -------------------------------------------------------------- publish ----

fn publish(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut dir: Option<PathBuf> = None;
    let mut base_url: Option<String> = None;
    let mut s3_endpoint: Option<String> = None;
    let mut bucket: Option<String> = None;
    let mut parallel = 4usize;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--dir") => dir = Some(next_path(&mut iter, "--dir")?),
            Some("--base-url") => base_url = Some(next_string(&mut iter, "--base-url")?),
            Some("--s3-endpoint") => s3_endpoint = Some(next_string(&mut iter, "--s3-endpoint")?),
            Some("--bucket") => bucket = Some(next_string(&mut iter, "--bucket")?),
            Some("--parallel") => {
                parallel = next_string(&mut iter, "--parallel")?
                    .parse()
                    .map_err(|_| super::error("--parallel must be a positive integer"))?;
            }
            Some("-h" | "--help") => {
                print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown publish option {arg:?}")),
        }
    }
    let dir = dir.ok_or_else(|| super::error("--dir is required"))?;
    let base_url = base_url.ok_or_else(|| super::error("--base-url is required"))?;
    let s3_endpoint = s3_endpoint.ok_or_else(|| super::error("--s3-endpoint is required"))?;
    let credentials = S3Credentials {
        access_key_id: std::env::var("R2_CORPUS_ACCESS_KEY_ID")
            .map_err(|_| super::error("R2_CORPUS_ACCESS_KEY_ID is not set"))?,
        secret_access_key: std::env::var("R2_CORPUS_SECRET_ACCESS_KEY")
            .map_err(|_| super::error("R2_CORPUS_SECRET_ACCESS_KEY is not set"))?,
    };
    if credentials.access_key_id.trim().is_empty()
        || credentials.secret_access_key.trim().is_empty()
    {
        return fail("R2 credentials are empty");
    }
    let publisher = Publisher {
        base_url: base_url.trim_end_matches('/').to_owned(),
        write_base: match bucket {
            Some(bucket) => format!("{}/{bucket}", s3_endpoint.trim_end_matches('/')),
            None => s3_endpoint.trim_end_matches('/').to_owned(),
        },
        credentials,
    };

    // What is being published, re-verified from the build directory rather
    // than trusted: manifest bytes hash to manifest.blake3, provenance names
    // that digest, and both bundles exist.
    let manifest_bytes = fs::read(dir.join("manifest.json"))?;
    let manifest_blake3 = fs::read_to_string(dir.join("manifest.blake3"))?
        .trim()
        .to_owned();
    if blake3_bytes(&manifest_bytes) != manifest_blake3 {
        return fail("manifest.json does not hash to manifest.blake3 in the build directory");
    }
    let manifest = Manifest::parse(&manifest_bytes)?;
    let provenance_bytes = fs::read(dir.join("provenance.json"))?;
    let provenance: Provenance = serde_json::from_slice(&provenance_bytes)?;
    if provenance.manifest_blake3 != manifest_blake3 {
        return fail("provenance.json names a different manifest digest");
    }
    let provenance_blake3 = blake3_bytes(&provenance_bytes);
    for bundle in [
        "manifest.json.sigstore.json",
        "provenance.json.sigstore.json",
    ] {
        if !dir.join(bundle).is_file() {
            return fail(format!(
                "{bundle} is missing from the build directory; sign before publishing"
            ));
        }
    }
    // The lock entry this publication will produce must be valid before a
    // single byte is uploaded: a build made outside the publish workflow (no
    // commit, no run) is not publishable.
    let lock = Lock::published(
        &publisher.base_url,
        &manifest_blake3,
        &provenance_blake3,
        &provenance.source.commit,
        &provenance.source.run_url,
    );
    lock.validate().map_err(|err| {
        super::error(format!(
            "refusing to publish a build that was not produced by the publish workflow: {err}"
        ))
    })?;
    // The tree must still hold exactly the bytes the manifest describes.
    let mut objects: Vec<(String, PathBuf, u64)> = Vec::new();
    for file in &manifest.files {
        let path = repo_path(root, &file.path);
        let digest =
            digest_file(&path).map_err(|err| super::error(format!("{}: {err}", file.path)))?;
        if digest.lfs_pointer || digest.blake3 != file.blake3 || digest.size != file.size {
            return fail(format!(
                "{}: tree bytes do not match the manifest; refusing to publish",
                file.path
            ));
        }
        objects.push((file.blake3.clone(), path, file.size));
    }
    // Content-addressed keys dedupe identical bytes.
    objects.sort();
    objects.dedup_by(|left, right| left.0 == right.0);
    println!(
        "test-corpus publish: {} objects ({} unique bytes) → {}",
        manifest.files.len(),
        objects.len(),
        publisher.write_base
    );

    let outcomes = publisher.put_all(&objects, parallel);
    let mut created = 0usize;
    let mut existed = 0usize;
    let mut failures = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(PutOutcome::Created) => created += 1,
            Ok(PutOutcome::AlreadyPresent) => existed += 1,
            Err(err) => failures.push(err.to_string()),
        }
    }
    if !failures.is_empty() {
        failures.sort();
        return fail(format!(
            "object upload failed for {} object(s):\n  {}",
            failures.len(),
            failures.join("\n  ")
        ));
    }
    println!(
        "test-corpus publish: objects: {created} created, {existed} already present and verified"
    );

    // Manifest, provenance and their bundles last, so a manifest never points
    // at objects that are not there. The manifest is deterministic, but its
    // provenance and both bundles are not (timestamps, run ids, ephemeral
    // signing keys), so a manifest that is already published keeps its first
    // publication's provenance and signatures: this run is then an idempotent
    // re-verification, never a rewrite.
    let manifest_key = format!("{MANIFESTS_PREFIX}{manifest_blake3}.json");
    let provenance_key = format!("{MANIFESTS_PREFIX}{manifest_blake3}.provenance.json");
    let lock = match publisher.already_published(&manifest_key, &manifest_bytes)? {
        Some(()) => {
            let existing = curl::get_to_vec(&publisher.public_url(&provenance_key))?;
            let existing_provenance: Provenance =
                serde_json::from_slice(&existing).map_err(|err| {
                    super::error(format!("published provenance is unreadable: {err}"))
                })?;
            if existing_provenance.manifest_blake3 != manifest_blake3 {
                return fail(format!(
                    "published provenance at {provenance_key} names manifest {}, not {manifest_blake3}; failing closed",
                    existing_provenance.manifest_blake3
                ));
            }
            for bundle in [
                format!("{manifest_key}.sigstore.json"),
                format!("{provenance_key}.sigstore.json"),
            ] {
                curl::get_to_vec(&publisher.public_url(&bundle)).map_err(|err| {
                    super::error(format!("published bundle {bundle} is missing: {err}"))
                })?;
            }
            println!(
                "test-corpus publish: manifest {manifest_blake3} was already published by {}; keeping its provenance and signatures",
                existing_provenance.source.run_url
            );
            Lock::published(
                &publisher.base_url,
                &manifest_blake3,
                &blake3_bytes(&existing),
                &existing_provenance.source.commit,
                &existing_provenance.source.run_url,
            )
        }
        None => {
            publisher.put_document(
                &dir.join("manifest.json"),
                &manifest_key,
                "application/json",
                Some(&manifest_blake3),
            )?;
            publisher.put_document(
                &dir.join("manifest.json.sigstore.json"),
                &format!("{manifest_key}.sigstore.json"),
                "application/json",
                None,
            )?;
            publisher.put_document(
                &dir.join("provenance.json"),
                &provenance_key,
                "application/json",
                Some(&provenance_blake3),
            )?;
            publisher.put_document(
                &dir.join("provenance.json.sigstore.json"),
                &format!("{provenance_key}.sigstore.json"),
                "application/json",
                None,
            )?;
            lock
        }
    };
    lock.validate()?;

    let rendered = lock.render()?;
    write_atomic(&dir.join("lock.json"), rendered.as_bytes())?;
    println!(
        "test-corpus publish: done. Pin this in {LOCK_FILE} through a reviewed PR:\n{rendered}"
    );
    Ok(())
}

enum PutOutcome {
    Created,
    AlreadyPresent,
}

struct Publisher {
    base_url: String,
    write_base: String,
    credentials: S3Credentials,
}

impl Publisher {
    fn public_url(&self, key: &str) -> String {
        format!("{}/{key}", self.base_url)
    }

    fn write_url(&self, key: &str) -> String {
        format!("{}/{key}", self.write_base)
    }

    /// Conditional PUT of one object; on 412 the public copy is read back and
    /// must hash to the same digest, otherwise this is an error, never a
    /// replacement.
    fn put_object(&self, blake3: &str, path: &Path, size: u64) -> Result<PutOutcome> {
        let key = format!("{OBJECTS_PREFIX}{blake3}");
        match curl::put_conditional(
            path,
            &self.write_url(&key),
            "application/octet-stream",
            &self.credentials,
        )? {
            status if (200..300).contains(&status) => {
                self.read_back(&key, blake3, size)?;
                Ok(PutOutcome::Created)
            }
            412 => {
                self.read_back(&key, blake3, size)?;
                Ok(PutOutcome::AlreadyPresent)
            }
            status => fail(format!("PUT {key}: HTTP {status}")),
        }
    }

    fn read_back(&self, key: &str, blake3: &str, size: u64) -> Result<()> {
        let temp = std::env::temp_dir().join(format!(
            "rarpar-corpus-readback-{}-{blake3}",
            std::process::id()
        ));
        curl::get_to_file(&self.public_url(key), &temp)?;
        let digest = digest_file(&temp);
        let _ = fs::remove_file(&temp);
        let digest = digest?;
        if digest.blake3 != blake3 || digest.size != size {
            return fail(format!(
                "read-back of {key} hashed to {} ({} bytes), expected {blake3} ({size} bytes): the stored object is not the one being published; failing closed",
                digest.blake3, digest.size
            ));
        }
        Ok(())
    }

    /// Whether the manifest is already on the public side with exactly these
    /// bytes. A manifest that exists with *different* bytes under the same
    /// digest key is a corrupted mirror and fails closed.
    fn already_published(&self, key: &str, bytes: &[u8]) -> Result<Option<()>> {
        let temp = std::env::temp_dir().join(format!(
            "rarpar-corpus-published-{}-{}",
            std::process::id(),
            blake3_bytes(key.as_bytes())
        ));
        match curl::get_to_file(&self.public_url(key), &temp) {
            Err(_) => Ok(None),
            Ok(()) => {
                let existing = fs::read(&temp)?;
                let _ = fs::remove_file(&temp);
                if existing == bytes {
                    Ok(Some(()))
                } else {
                    fail(format!(
                        "{key} is already published with different bytes (blake3 {}); failing closed",
                        blake3_bytes(&existing)
                    ))
                }
            }
        }
    }

    fn put_document(
        &self,
        path: &Path,
        key: &str,
        content_type: &str,
        expected_blake3: Option<&str>,
    ) -> Result<()> {
        let bytes = fs::read(path)?;
        let digest = blake3_bytes(&bytes);
        if let Some(expected) = expected_blake3
            && digest != expected
        {
            return fail(format!("{} does not hash to {expected}", path.display()));
        }
        match curl::put_conditional(path, &self.write_url(key), content_type, &self.credentials)? {
            status if (200..300).contains(&status) => {}
            412 => {}
            status => return fail(format!("PUT {key}: HTTP {status}")),
        }
        let stored = curl::get_to_vec(&self.public_url(key))?;
        if stored != bytes {
            return fail(format!(
                "read-back of {key} differs from the bytes being published; failing closed"
            ));
        }
        println!(
            "test-corpus publish: {key} ({} bytes) verified",
            bytes.len()
        );
        Ok(())
    }

    fn put_all(
        &self,
        objects: &[(String, PathBuf, u64)],
        parallel: usize,
    ) -> Vec<Result<PutOutcome>> {
        let parallel = parallel.clamp(1, 8);
        // Errors cross threads as strings: the boxed error type is not Send.
        let mut results: Vec<Option<std::result::Result<PutOutcome, String>>> =
            (0..objects.len()).map(|_| None).collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots = std::sync::Mutex::new(&mut results);
        std::thread::scope(|scope| {
            for _ in 0..parallel {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if index >= objects.len() {
                            return;
                        }
                        let (blake3, path, size) = &objects[index];
                        let outcome = self
                            .put_object(blake3, path, *size)
                            .map_err(|err| format!("{blake3} ({}): {err}", path.display()));
                        slots.lock().expect("publish result lock")[index] = Some(outcome);
                    }
                });
            }
        });
        results
            .into_iter()
            .map(|slot| match slot {
                Some(Ok(outcome)) => Ok(outcome),
                Some(Err(message)) => fail(message),
                None => fail("object was never attempted"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_corpus::blake3_bytes;
    use crate::test_corpus::curl::CURL_PROTO_ENV;
    use crate::test_corpus::curl::tests::{ENV_LOCK, FakeServer};

    /// A miniature repository: a ledger with three fixtures (two of them
    /// byte-identical), the checked-in toolchain lock, one profile per file
    /// group, and no fixture bytes on disk yet.
    fn scaffold(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("xtask-corpus-e2e-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("test-corpus")).unwrap();
        fs::create_dir_all(root.join("bench/rarpar-bench/config")).unwrap();
        fs::copy(
            crate::workspace_root().join(TOOLCHAINS_FILE),
            root.join(TOOLCHAINS_FILE),
        )
        .unwrap();
        fs::create_dir_all(root.join("gen")).unwrap();
        fs::write(root.join("gen/gen.sh"), "#!/bin/sh\n").unwrap();
        let alpha = blake3_bytes(b"alpha-bytes");
        let beta = blake3_bytes(b"beta-bytes");
        let ledger = format!(
            r#"{{"schema_version":1,"toolchains":"{TOOLCHAINS_FILE}",
                "generators":{{"gen.sh":{{"path":"gen/gen.sh","toolchains":["rarlab-7.20"],"byte_reproducible":false}}}},
                "upstreams":{{}},
                "files":[
                 {{"path":"crates/unrar-rs/tests/fixtures/rar5/a.rar","size":11,"blake3":"{alpha}","format":"rar5","source":{{"kind":"generated","generator":"gen.sh","toolchains":["rarlab-7.20"]}}}},
                 {{"path":"crates/unrar-rs/tests/fixtures/rar5/a-twin.rar","size":11,"blake3":"{alpha}","format":"rar5","source":{{"kind":"generated","generator":"gen.sh","toolchains":["rarlab-7.20"]}}}},
                 {{"path":"crates/par2-rs/tests/fixtures/b.par2","size":10,"blake3":"{beta}","format":"par2","source":{{"kind":"generated","generator":"gen.sh","toolchains":["rarlab-7.20"]}}}}
                ]}}"#
        );
        fs::write(root.join(LEDGER_FILE), ledger).unwrap();
        fs::write(
            root.join(PROFILES_FILE),
            r#"{"schema_version":1,"profiles":{
                "unrar":{"include":["crates/unrar-rs/tests/fixtures/**"]},
                "par2":{"include":["crates/par2-rs/tests/fixtures/**"]}}}"#,
        )
        .unwrap();
        root
    }

    fn manifest_for(root: &Path) -> (Vec<u8>, String) {
        let (lock, lock_blake3) = ToolchainLock::load(&repo_path(root, TOOLCHAINS_FILE)).unwrap();
        let ledger = Ledger::load(&repo_path(root, LEDGER_FILE)).unwrap();
        let profiles = ProfilesFile::load(&repo_path(root, PROFILES_FILE)).unwrap();
        let manifest = Manifest::build(&ledger, &profiles, &lock, &lock_blake3).unwrap();
        let bytes = manifest.canonical_bytes().unwrap();
        let digest = blake3_bytes(&bytes);
        (bytes, digest)
    }

    /// The LFS fallback pulls each profile on its own terms. Merging the
    /// patterns would drop `rar12`'s archives whenever `rar34` — which excludes
    /// exactly those paths from the shared `rar4/` directory — is asked for in
    /// the same command.
    #[test]
    fn the_lfs_pull_plan_keeps_each_profiles_excludes_to_itself() {
        let profiles: ProfilesFile = serde_json::from_str(
            r#"{"schema_version":1,"profiles":{
                "rar12":{"include":["f/rar4/rar15_lz.rar","f/originals/**"]},
                "rar34":{"include":["f/rar4/**","f/originals/**"],"exclude":["f/rar4/rar15_lz.rar"]},
                "rar57":{"include":["f/rar5/**"]}
            }}"#,
        )
        .unwrap();
        let plan = lfs_pull_plan(
            &profiles,
            &["rar12".to_owned(), "rar34".to_owned(), "rar12".to_owned()],
        )
        .unwrap();
        assert_eq!(
            plan,
            vec![
                (
                    "--include=f/rar4/rar15_lz.rar,f/originals/**".to_owned(),
                    "--exclude=".to_owned()
                ),
                (
                    "--include=f/rar4/**,f/originals/**".to_owned(),
                    "--exclude=f/rar4/rar15_lz.rar".to_owned()
                ),
            ],
            "one pull per distinct profile, excludes never merged"
        );
        let plan = lfs_pull_plan(&profiles, &["rar57".to_owned()]).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan[0].1, "--exclude=",
            "an empty exclude is a no-op filter"
        );
        assert!(lfs_pull_plan(&profiles, &["nope".to_owned()]).is_err());
    }

    #[test]
    fn fetch_hydrates_verifies_dedupes_and_fails_closed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = scaffold("fetch");
        let (manifest_bytes, manifest_blake3) = manifest_for(&root);
        let alpha = blake3_bytes(b"alpha-bytes");
        let beta = blake3_bytes(b"beta-bytes");
        let manifest_key = format!("/{MANIFESTS_PREFIX}{manifest_blake3}.json");
        let alpha_key = format!("/{OBJECTS_PREFIX}{alpha}");
        let beta_key = format!("/{OBJECTS_PREFIX}{beta}");
        // beta is served corrupted: the fetch must refuse it and still place alpha.
        let routes: Vec<crate::test_corpus::curl::tests::Route> = vec![
            (
                ("GET", Box::leak(manifest_key.into_boxed_str())),
                (200, manifest_bytes.clone()),
            ),
            (
                ("GET", Box::leak(alpha_key.into_boxed_str())),
                (200, b"alpha-bytes".to_vec()),
            ),
            (
                ("GET", Box::leak(beta_key.into_boxed_str())),
                (200, b"beta-BROKEN".to_vec()),
            ),
        ];
        let server = FakeServer::start(routes);
        unsafe { std::env::set_var(CURL_PROTO_ENV, "=http,https") };
        let lock = Lock::published(
            &server.base_url,
            &manifest_blake3,
            &blake3_bytes(b"provenance"),
            "0123456789abcdef0123456789abcdef01234567",
            "https://github.com/scryer-media/rarpar/actions/runs/1",
        );
        fs::write(root.join(LOCK_FILE), lock.render().unwrap()).unwrap();

        // The unrar profile: two paths, one object.
        fetch(&root, vec!["--profile".into(), "unrar".into()]).unwrap();
        assert_eq!(
            fs::read(root.join("crates/unrar-rs/tests/fixtures/rar5/a.rar")).unwrap(),
            b"alpha-bytes"
        );
        assert_eq!(
            fs::read(root.join("crates/unrar-rs/tests/fixtures/rar5/a-twin.rar")).unwrap(),
            b"alpha-bytes"
        );
        let alpha_gets = server
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, p, _)| m == "GET" && p.ends_with(&alpha))
            .count();
        assert_eq!(alpha_gets, 1, "identical bytes are fetched once");
        // A second fetch finds everything present and downloads nothing.
        let before = server.requests.lock().unwrap().len();
        fetch(&root, vec!["--profile".into(), "unrar".into()]).unwrap();
        assert_eq!(
            server.requests.lock().unwrap().len(),
            before,
            "present fixtures are not re-fetched"
        );
        // --check on the missing profile fails without writing.
        assert!(
            fetch(
                &root,
                vec!["--profile".into(), "par2".into(), "--check".into()]
            )
            .is_err()
        );
        // The corrupted object fails closed: error, and no file placed.
        let err = fetch(&root, vec!["--profile".into(), "par2".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("hashed to"), "{err}");
        assert!(!root.join("crates/par2-rs/tests/fixtures/b.par2").exists());
        assert!(
            !root.join("crates/par2-rs/tests/fixtures").exists()
                || fs::read_dir(root.join("crates/par2-rs/tests/fixtures"))
                    .unwrap()
                    .count()
                    == 0,
            "no partial file"
        );
        // hydrate on a published lock is fetch.
        hydrate(&root, vec!["--profile".into(), "unrar".into()]).unwrap();
        // A tampered manifest (digest mismatch) is refused before anything is read.
        let mut tampered = lock.clone();
        tampered.manifest.blake3 = blake3_bytes(b"other").clone();
        tampered.manifest.url = tampered.manifest_url();
        tampered.signature.bundle_url = format!("{}.sigstore.json", tampered.manifest_url());
        tampered.provenance.url = tampered.provenance_url();
        fs::write(root.join(LOCK_FILE), tampered.render().unwrap()).unwrap();
        fs::remove_file(root.join("crates/unrar-rs/tests/fixtures/rar5/a.rar")).unwrap();
        assert!(fetch(&root, vec!["--profile".into(), "unrar".into()]).is_err());
        assert!(
            !root
                .join("crates/unrar-rs/tests/fixtures/rar5/a.rar")
                .exists()
        );
        unsafe { std::env::remove_var(CURL_PROTO_ENV) };
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn build_writes_a_manifest_that_verify_recomputes_and_publish_rechecks() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = scaffold("build");
        // Put the bytes in place so build can check the tree.
        for (path, bytes) in [
            (
                "crates/unrar-rs/tests/fixtures/rar5/a.rar",
                &b"alpha-bytes"[..],
            ),
            (
                "crates/unrar-rs/tests/fixtures/rar5/a-twin.rar",
                &b"alpha-bytes"[..],
            ),
            ("crates/par2-rs/tests/fixtures/b.par2", &b"beta-bytes"[..]),
        ] {
            write_atomic(&repo_path(&root, path), bytes).unwrap();
        }
        let out = root.join("out");
        build(&root, vec!["--out".into(), out.clone().into()]).unwrap();
        let (bytes, digest) = manifest_for(&root);
        assert_eq!(fs::read(out.join("manifest.json")).unwrap(), bytes);
        assert_eq!(
            fs::read_to_string(out.join("manifest.blake3"))
                .unwrap()
                .trim(),
            digest
        );
        let objects = fs::read_to_string(out.join("objects.tsv")).unwrap();
        assert_eq!(objects.lines().count(), 3);
        let provenance: Provenance =
            serde_json::from_slice(&fs::read(out.join("provenance.json")).unwrap()).unwrap();
        assert_eq!(provenance.manifest_blake3, digest);
        // Corrupt one fixture: build refuses (tree disagrees with ledger).
        fs::write(
            repo_path(&root, "crates/par2-rs/tests/fixtures/b.par2"),
            b"changed",
        )
        .unwrap();
        let err = build(&root, vec!["--out".into(), out.clone().into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("tree disagrees with the ledger"), "{err}");
        // A blocked entry stops the build even with a consistent tree.
        fs::write(
            repo_path(&root, "crates/par2-rs/tests/fixtures/b.par2"),
            b"beta-bytes",
        )
        .unwrap();
        let ledger_text = fs::read_to_string(root.join(LEDGER_FILE)).unwrap();
        let blocked = ledger_text.replace(
            r#""source":{"kind":"generated","generator":"gen.sh","toolchains":["rarlab-7.20"]}}
                ]"#,
            r#""source":{"kind":"blocked","reason":"who wrote this?"}}
                ]"#,
        );
        assert_ne!(blocked, ledger_text);
        fs::write(root.join(LEDGER_FILE), blocked).unwrap();
        let err = build(&root, vec!["--out".into(), out.clone().into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked on incomplete provenance"), "{err}");
        // publish refuses a build directory without signatures.
        fs::write(root.join(LEDGER_FILE), ledger_text).unwrap();
        build(&root, vec!["--out".into(), out.clone().into()]).unwrap();
        unsafe {
            std::env::set_var("R2_CORPUS_ACCESS_KEY_ID", "k");
            std::env::set_var("R2_CORPUS_SECRET_ACCESS_KEY", "s");
        }
        let err = publish(
            &root,
            vec![
                "--dir".into(),
                out.clone().into(),
                "--base-url".into(),
                "https://corpus.example.net".into(),
                "--s3-endpoint".into(),
                "https://acct.r2.cloudflarestorage.com".into(),
                "--bucket".into(),
                "corpus".into(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("sigstore.json is missing"), "{err}");
        unsafe {
            std::env::remove_var("R2_CORPUS_ACCESS_KEY_ID");
            std::env::remove_var("R2_CORPUS_SECRET_ACCESS_KEY");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// publish: conditional PUTs for every unique object and document, each
    /// read back from the public side; a read-back that disagrees fails closed.
    #[test]
    fn publish_uploads_conditionally_and_reads_everything_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = scaffold("publish");
        // A publishable build carries the workflow's identity in its provenance.
        unsafe {
            std::env::set_var("GITHUB_SERVER_URL", "https://github.com");
            std::env::set_var("GITHUB_REPOSITORY", "scryer-media/rarpar");
            std::env::set_var("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567");
            std::env::set_var("GITHUB_RUN_ID", "42");
        }
        for (path, bytes) in [
            (
                "crates/unrar-rs/tests/fixtures/rar5/a.rar",
                &b"alpha-bytes"[..],
            ),
            (
                "crates/unrar-rs/tests/fixtures/rar5/a-twin.rar",
                &b"alpha-bytes"[..],
            ),
            ("crates/par2-rs/tests/fixtures/b.par2", &b"beta-bytes"[..]),
        ] {
            write_atomic(&repo_path(&root, path), bytes).unwrap();
        }
        let out = root.join("out");
        build(&root, vec!["--out".into(), out.clone().into()]).unwrap();
        for bundle in [
            "manifest.json.sigstore.json",
            "provenance.json.sigstore.json",
        ] {
            fs::write(out.join(bundle), format!("{{\"fake\":\"{bundle}\"}}")).unwrap();
        }
        let manifest_blake3 = fs::read_to_string(out.join("manifest.blake3"))
            .unwrap()
            .trim()
            .to_owned();
        let alpha = blake3_bytes(b"alpha-bytes");
        let beta = blake3_bytes(b"beta-bytes");
        let leak = |text: String| -> &'static str { Box::leak(text.into_boxed_str()) };
        // alpha already exists on the bucket (412) and reads back identical;
        // beta and every document are new: their PUTs land in the store and the
        // read-backs are answered from it.
        let routes: Vec<crate::test_corpus::curl::tests::Route> = vec![
            (
                ("PUT", leak(format!("/bucket/{OBJECTS_PREFIX}{alpha}"))),
                (412, Vec::new()),
            ),
            (
                ("GET", leak(format!("/{OBJECTS_PREFIX}{alpha}"))),
                (200, b"alpha-bytes".to_vec()),
            ),
        ];
        let server = FakeServer::start_stateful(routes, "/bucket");
        unsafe {
            std::env::set_var(CURL_PROTO_ENV, "=http,https");
            std::env::set_var("R2_CORPUS_ACCESS_KEY_ID", "AKIDTEST");
            std::env::set_var("R2_CORPUS_SECRET_ACCESS_KEY", "verysecret");
        }
        let args = |base: &str| -> Vec<OsString> {
            vec![
                "--dir".into(),
                out.clone().into(),
                "--base-url".into(),
                base.into(),
                "--s3-endpoint".into(),
                base.into(),
                "--bucket".into(),
                "bucket".into(),
                "--parallel".into(),
                "1".into(),
            ]
        };
        publish(&root, args(&server.base_url)).unwrap();
        let lock = Lock::load(&out.join("lock.json")).unwrap();
        assert_eq!(lock.manifest.blake3, manifest_blake3);
        assert_eq!(lock.base_url, server.base_url);
        {
            let requests = server.requests.lock().unwrap();
            let puts: Vec<&str> = requests
                .iter()
                .filter(|(m, _, _)| m == "PUT")
                .map(|(_, p, _)| p.as_str())
                .collect();
            assert_eq!(puts.len(), 6, "two objects + four documents: {puts:?}");
            assert!(
                puts.iter().all(|p| p.starts_with("/bucket/")),
                "writes go to the S3 endpoint: {puts:?}"
            );
            for (_, _, headers) in requests.iter().filter(|(m, _, _)| m == "PUT") {
                let joined = headers.join("\n").to_ascii_lowercase();
                assert!(joined.contains("if-none-match: *"), "{joined}");
                assert!(
                    joined.contains("authorization: aws4-hmac-sha256"),
                    "{joined}"
                );
                assert!(!joined.contains("verysecret"));
            }
            // Manifest is written after every object.
            let order: Vec<&str> = puts.clone();
            let last_object = order.iter().rposition(|p| p.contains("/objects/")).unwrap();
            let first_manifest = order
                .iter()
                .position(|p| p.contains("/manifests/"))
                .unwrap();
            assert!(last_object < first_manifest, "{order:?}");
        }
        // Publishing the same manifest again is idempotent: objects are
        // re-verified, but the first publication's provenance and signatures
        // stay, and no manifest-side PUT is attempted.
        let before = server.requests.lock().unwrap().len();
        publish(&root, args(&server.base_url)).unwrap();
        {
            let requests = server.requests.lock().unwrap();
            let new_puts: Vec<&str> = requests[before..]
                .iter()
                .filter(|(m, _, _)| m == "PUT")
                .map(|(_, p, _)| p.as_str())
                .collect();
            assert!(
                new_puts.iter().all(|p| p.contains("/objects/")),
                "a republish must not touch manifest, provenance or bundles: {new_puts:?}"
            );
        }
        let again = Lock::load(&out.join("lock.json")).unwrap();
        assert_eq!(again.manifest.blake3, manifest_blake3);
        assert_eq!(again.published_from.run, lock.published_from.run);
        drop(server);

        // Read-back disagreement: the bucket answers 412 (someone else's object
        // under this key) and the public copy is not our bytes.
        let mut routes: Vec<crate::test_corpus::curl::tests::Route> = Vec::new();
        routes.push((
            ("PUT", leak(format!("/bucket/{OBJECTS_PREFIX}{alpha}"))),
            (412, Vec::new()),
        ));
        routes.push((
            ("GET", leak(format!("/{OBJECTS_PREFIX}{alpha}"))),
            (200, b"NOT-alpha".to_vec()),
        ));
        routes.push((
            ("PUT", leak(format!("/bucket/{OBJECTS_PREFIX}{beta}"))),
            (200, Vec::new()),
        ));
        routes.push((
            ("GET", leak(format!("/{OBJECTS_PREFIX}{beta}"))),
            (200, b"beta-bytes".to_vec()),
        ));
        let server = FakeServer::start(routes);
        let err = publish(&root, args(&server.base_url))
            .unwrap_err()
            .to_string();
        assert!(err.contains("failing closed"), "{err}");
        let requests = server.requests.lock().unwrap();
        assert!(
            !requests
                .iter()
                .any(|(m, p, _)| m == "PUT" && p.contains("/manifests/")),
            "no manifest is published when an object fails: {requests:?}"
        );
        drop(requests);
        unsafe {
            std::env::remove_var(CURL_PROTO_ENV);
            std::env::remove_var("R2_CORPUS_ACCESS_KEY_ID");
            std::env::remove_var("R2_CORPUS_SECRET_ACCESS_KEY");
            for name in [
                "GITHUB_SERVER_URL",
                "GITHUB_REPOSITORY",
                "GITHUB_SHA",
                "GITHUB_RUN_ID",
            ] {
                std::env::remove_var(name);
            }
        }
        let _ = fs::remove_dir_all(&root);
    }
}
