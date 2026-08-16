//! `test-corpus bench-pins`: the benchmark corpus's `fixture_sha256` values,
//! recomputed from the tree.
//!
//! Six benchmark cases do not synthesize their payload — they *import* a test
//! fixture set (`fixture_dir` + `fixture_prefix`) and refuse to run unless it
//! hashes to the `fixture_sha256` pinned in
//! `bench/rarpar-bench/config/corpus.json`. Regenerating the corpus moves those
//! digests, so a corpus revision and a benchmark pin update are one reviewed
//! change; this command prints the old→new pairs that change has to carry.
//!
//! The digest is the harness's, not a convenience of our own: Go's
//! `importFixture` copies the matching files flat into a scratch directory,
//! builds `sourceManifest` — `[{path, bytes, sha256}]` sorted by path — encodes
//! it with `encoding/json`, and takes the SHA-256 of those bytes.
//! [`go_canonical_manifest`] reproduces that encoding byte for byte, including
//! the HTML escaping `encoding/json` applies by default, and the tests below
//! hold it to the six pins that are checked in today.
//!
//! **This module is SHA-256 on purpose, and it is the only one left.** The rest
//! of the test corpus digests with BLAKE3, but `fixture_sha256` is the
//! *benchmark* corpus's contract — `importFixture` in the Go harness is what
//! computes it, and fleet evidence already exists against those values. A digest
//! this module computes has to be bit-for-bit what the harness computes, so the
//! algorithm is specified by that contract, not chosen here. Changing it would
//! mean rewriting `bench/rarpar-bench/config/corpus.json` and invalidating every
//! recorded run.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[cfg(test)]
use super::ledger::Ledger;
use super::{Result, fail, hex, next_path, repo_path, write_atomic};

/// SHA-256 of a byte slice: the benchmark contract's digest (see the module
/// note). Local so that nothing outside this file can reach for it by accident.
fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// SHA-256 and size of a file, streamed, plus whether it is a Git LFS pointer
/// rather than content — the same three facts [`super::digest_file`] reports,
/// under the algorithm the benchmark contract fixes.
fn sha256_file(path: &Path) -> Result<(String, u64, bool)> {
    let mut file = fs::File::open(path)
        .map_err(|source| super::error(format!("open {}: {source}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut size = 0u64;
    let mut head: Vec<u8> = Vec::with_capacity(super::LFS_POINTER_PREFIX.len());
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| super::error(format!("read {}: {source}", path.display())))?;
        if read == 0 {
            break;
        }
        if head.len() < super::LFS_POINTER_PREFIX.len() {
            let take = (super::LFS_POINTER_PREFIX.len() - head.len()).min(read);
            head.extend_from_slice(&buffer[..take]);
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((
        hex(&hasher.finalize()),
        size,
        head.starts_with(super::LFS_POINTER_PREFIX),
    ))
}

pub(crate) const BENCH_CORPUS_FILE: &str = "bench/rarpar-bench/config/corpus.json";
/// `fixture_dir` is relative to the harness root, the way the Go harness reads it.
pub(crate) const BENCH_HARNESS_ROOT: &str = "bench/rarpar-bench";

/// One benchmark case that imports a fixture set.
#[derive(Debug, Clone)]
pub(crate) struct FixtureCase {
    pub(crate) id: String,
    pub(crate) fixture_dir: String,
    pub(crate) fixture_prefix: String,
    pub(crate) pinned_sha256: String,
}

/// One file as the harness's `sourceManifest` states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceFile {
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

pub(crate) fn run(root: &Path, args: Vec<OsString>) -> Result<()> {
    let mut out: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--out") => out = Some(next_path(&mut iter, "--out")?),
            Some("-h" | "--help") => {
                super::commands::print_usage();
                return Ok(());
            }
            _ => return fail(format!("unknown bench-pins option {arg:?}")),
        }
    }
    let pins = pins_from_tree(root)?;
    let report = render(&pins);
    print!("{report}");
    let moved = pins
        .iter()
        .filter(|pin| pin.pinned_sha256 != pin.computed_sha256)
        .count();
    if moved == 0 {
        println!(
            "test-corpus bench-pins: all {} pin(s) in {BENCH_CORPUS_FILE} still match the tree",
            pins.len()
        );
    } else {
        println!(
            "test-corpus bench-pins: {moved} of {} pin(s) moved; update fixture_sha256 in \
             {BENCH_CORPUS_FILE} in the same reviewed change that lands the corpus revision",
            pins.len()
        );
    }
    if let Some(out) = out {
        write_atomic(&out, report.as_bytes())?;
        println!(
            "test-corpus bench-pins: report written to {}",
            out.display()
        );
    }
    Ok(())
}

/// One case's pin, as configured and as the tree computes it.
#[derive(Debug, Clone)]
pub(crate) struct Pin {
    pub(crate) id: String,
    pub(crate) pinned_sha256: String,
    pub(crate) computed_sha256: String,
}

/// Every importing case's digest, recomputed from the fixture bytes on disk.
pub(crate) fn pins_from_tree(root: &Path) -> Result<Vec<Pin>> {
    let cases = load_cases(&repo_path(root, BENCH_CORPUS_FILE))?;
    let harness_root = repo_path(root, BENCH_HARNESS_ROOT);
    let mut pins = Vec::new();
    for case in &cases {
        let files = fixture_files(&harness_root, case)?;
        pins.push(Pin {
            id: case.id.clone(),
            pinned_sha256: case.pinned_sha256.clone(),
            computed_sha256: sha256_bytes(go_canonical_manifest(&files).as_bytes()),
        });
    }
    Ok(pins)
}

/// The tab-separated report the workflow uploads and pastes into its summary.
pub(crate) fn render(pins: &[Pin]) -> String {
    let mut report = String::from("case\tpinned\tcomputed\n");
    for pin in pins {
        let _ = writeln!(
            report,
            "{}\t{}\t{}",
            pin.id, pin.pinned_sha256, pin.computed_sha256
        );
    }
    report
}

/// The importing cases in `corpus.json`, in file order.
pub(crate) fn load_cases(path: &Path) -> Result<Vec<FixtureCase>> {
    let value: serde_json::Value = serde_json::from_str(&super::read_to_string(path)?)
        .map_err(|source| super::error(format!("decode {}: {source}", path.display())))?;
    let Some(cases) = value.get("cases").and_then(serde_json::Value::as_array) else {
        return fail(format!("{} has no cases array", path.display()));
    };
    let mut out = Vec::new();
    for case in cases {
        let Some(fixture_dir) = case.get("fixture_dir").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let id = case
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let prefix = case
            .get("fixture_prefix")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let pinned = case
            .get("fixture_sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if id.is_empty() || prefix.is_empty() || pinned.is_empty() {
            return fail(format!(
                "benchmark case {id:?} names a fixture_dir but not all of id, fixture_prefix and fixture_sha256"
            ));
        }
        out.push(FixtureCase {
            id: id.to_owned(),
            fixture_dir: fixture_dir.to_owned(),
            fixture_prefix: prefix.to_owned(),
            pinned_sha256: pinned.to_owned(),
        });
    }
    if out.is_empty() {
        return fail(format!("{} imports no fixtures", path.display()));
    }
    Ok(out)
}

/// The files one case imports, as the harness sees them: regular files directly
/// in `fixture_dir` whose name starts with `fixture_prefix`, sorted by name
/// (which is the sort by path the harness performs, since it copies them flat).
pub(crate) fn fixture_files(harness_root: &Path, case: &FixtureCase) -> Result<Vec<SourceFile>> {
    let mut directory = harness_root.to_path_buf();
    for component in case.fixture_dir.split('/') {
        directory.push(component);
    }
    let mut files = Vec::new();
    let entries = fs::read_dir(&directory)
        .map_err(|source| super::error(format!("read {}: {source}", directory.display())))?;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&case.fixture_prefix) {
            continue;
        }
        let (digest, size, lfs_pointer) = sha256_file(&entry.path())?;
        if lfs_pointer {
            return fail(format!(
                "{}: is a Git LFS pointer, not fixture bytes",
                entry.path().display()
            ));
        }
        files.push(SourceFile {
            path: name,
            bytes: size,
            sha256: digest,
        });
    }
    if files.is_empty() {
        return fail(format!(
            "benchmark case {} matched no files under {}",
            case.id,
            directory.display()
        ));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

/// The paths and sizes one case imports, read out of the ledger instead of the
/// tree. It needs no hydrated checkout, which is what lets the proof below run
/// in every lane — but only over the *set*: the ledger records each fixture's
/// BLAKE3 digest, and this contract's digest is SHA-256, so a pin cannot be
/// derived from the ledger. It is derived from the bytes, by
/// [`fixture_files`].
#[cfg(test)]
pub(crate) fn fixture_sizes_from_ledger(
    ledger: &Ledger,
    case: &FixtureCase,
) -> Result<Vec<(String, u64)>> {
    // `fixture_dir` is harness-relative (`../../crates/...`); normalize it to a
    // repository-relative directory prefix.
    let mut components: Vec<&str> = BENCH_HARNESS_ROOT.split('/').collect();
    for component in case.fixture_dir.split('/') {
        match component {
            "." | "" => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }
    let prefix = format!("{}/", components.join("/"));
    let mut files = Vec::new();
    for entry in &ledger.files {
        let Some(name) = entry.path.strip_prefix(&prefix) else {
            continue;
        };
        if name.contains('/') || !name.starts_with(&case.fixture_prefix) {
            continue;
        }
        files.push((name.to_owned(), entry.size));
    }
    if files.is_empty() {
        return fail(format!(
            "benchmark case {} matched no ledger paths",
            case.id
        ));
    }
    files.sort();
    Ok(files)
}

/// Go's `encoding/json` output for `[]SourceFile`, byte for byte: no
/// whitespace, struct field order, and the escaping `json.Marshal` applies by
/// default (including the HTML escapes it adds unless `SetEscapeHTML(false)`).
pub(crate) fn go_canonical_manifest(files: &[SourceFile]) -> String {
    let mut out = String::from("[");
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"path\":");
        go_json_string(&file.path, &mut out);
        out.push_str(",\"bytes\":");
        out.push_str(&file.bytes.to_string());
        out.push_str(",\"sha256\":");
        go_json_string(&file.sha256, &mut out);
        out.push('}');
    }
    out.push(']');
    out
}

/// One JSON string as `encoding/json` writes it.
fn go_json_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // The HTML escapes `encoding/json` applies unless SetEscapeHTML(false).
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            // The line terminators it escapes so the output is valid JavaScript.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other if (other as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_corpus::LEDGER_FILE;

    fn workspace() -> PathBuf {
        crate::workspace_root()
    }

    /// The two heavy-damage cases import the same set, so they share this table.
    const HEAVY_DAMAGE_FILES: &[(&str, u64, &str)] = &[
        (
            "fixture_rar5_heavy_damage.rar",
            76_201_245,
            "27335088f0f96555cd07b549e67c4032dc3b40b1f408936adb36c335dcef212e",
        ),
        (
            "fixture_rar5_heavy_damage_repair.par2",
            23_688,
            "b55ca8f6253b633052a77b8b00a717606ab73eec3f824a63f53a4e8f48cebd4e",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol000+50.par2",
            3_421_808,
            "bcf0cda8557706cb8e585f87f1cd02ede4d3da4c3fbd0cb159e002b9859e2c9d",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol050+50.par2",
            3_421_808,
            "58b304849a791076df2939147a4685498ce80901c2638733a56fab9f108203b0",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol100+50.par2",
            3_421_808,
            "709c7ecbcf87799b05477e2c843f5185995d21a82e9f8850d9d61f05614d643f",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol150+50.par2",
            3_421_808,
            "e12b3e34e1d4e34b0983287ce3a8a3d5bfdec740acf0d65564c11733aaf08b54",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol200+50.par2",
            3_421_808,
            "cf68df1601bcb6cff042d526a485894bd677d65437036cfc027756f8c4be0755",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol250+50.par2",
            3_421_808,
            "193b1dc05f298fbc4be1997b2cef2bc05da22a42e386a6247a88bb8319d228c5",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol300+50.par2",
            3_421_808,
            "8d6e9b3cba770d590087bdfb969405998e2e1b7fad13997f8f8fc0604adf5f09",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol350+50.par2",
            3_421_808,
            "beadc318a9aceb3690840dca373d40f13a500f759a0cf12b7ec9a6f7d455eced",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol400+50.par2",
            3_421_808,
            "d51e6b23d218b1b7af582fcb48f22496d7f879dbde8f21f2c1c8df12aad7b6b5",
        ),
        (
            "fixture_rar5_heavy_damage_repair.vol450+50.par2",
            3_421_808,
            "089496c4ceb64e96fd34cb784965b74b4d7d61dfcc9b28c4ab95d2f35ed5eff0",
        ),
    ];

    /// The six fixture sets exactly as the harness saw them when
    /// `bench/rarpar-bench/config/corpus.json` was pinned to the digests below:
    /// every file's name, size and SHA-256, and the digest `importFixture`
    /// computed from them.
    ///
    /// Frozen deliberately. A corpus revision moves the live pins — that is what
    /// a revision *is* — so a proof that read the live ledger would evaporate on
    /// the first regeneration. These rows are real harness input and real
    /// harness output, so they keep proving the reimplementation afterwards.
    #[allow(clippy::type_complexity)]
    const FROZEN_PINS: &[(&str, &str, &[(&str, u64, &str)])] = &[
        (
            "rar4-ppmd-restart",
            "7b3dbf08f88f704d882053b3ecf74aaa550d96c71b0354bac5eb0b0045e45ab6",
            &[(
                "rar4_ppm_solid_restart.rar",
                1_238_062,
                "2cbcbeeefe54f68fa47b4731d7d475045e943a02946dc19c7d9be87169f1be04",
            )],
        ),
        (
            "rar4-ppmd-solid-multi-member",
            "a0245fd56b58b5e5566915785000a6fdf31de1e18a46ca00e3a952a69ae0ac4c",
            &[(
                "rar4_ppm_solid_mv.rar",
                720_480,
                "a111aa9dcdd4f3a91f5572d2a388b36eb7c7c6c2b8392c42a680e1cd0b300d29",
            )],
        ),
        (
            "rar4-ppmd-order16-32m",
            "5b31a4461238736adf23733b5a0855dcf4a271ade158f4c34f036215d33a480d",
            &[(
                "rar4_ppm_order16_32m.rar",
                25_408_652,
                "8d07cc3e73d2eb2302fed236b80e8b233755d36f0e0f1f9806beafe23a87c436",
            )],
        ),
        (
            "rar4-ppmd-classic-multivolume",
            "160a828528b96406182b6b54b93335a86f2fa112913bd3d7280a6577b6699103",
            &[
                (
                    "rar4_ppm_oldmv.r00",
                    65_536,
                    "b7c6fba26b733aad9423db4d77eb7ecd0d2e707c97aed243281da90d331c36fd",
                ),
                (
                    "rar4_ppm_oldmv.r01",
                    65_536,
                    "cba4ab0f523840dbf050073708eb0feb12e29572582afc45ab7a4b5271082502",
                ),
                (
                    "rar4_ppm_oldmv.r02",
                    610,
                    "c54e67090514f08ae02767c1d1cb2a48cbef0ad05c8450a2739d968bb12b959a",
                ),
                (
                    "rar4_ppm_oldmv.rar",
                    65_536,
                    "c1bef5c41bc5b7afc1e4c01f3a82dc77ec634aaa561fb00f13520c399b52ba76",
                ),
            ],
        ),
        (
            "par2-heavy-damage-28",
            "29dadba101363b66cb114017edbc28eb208de656e2e4cfa57a5ca3bb03a365d9",
            HEAVY_DAMAGE_FILES,
        ),
        (
            "par2-heavy-damage-250",
            "29dadba101363b66cb114017edbc28eb208de656e2e4cfa57a5ca3bb03a365d9",
            HEAVY_DAMAGE_FILES,
        ),
    ];

    fn frozen(case: &str) -> Option<(&'static str, Vec<SourceFile>)> {
        FROZEN_PINS
            .iter()
            .find(|(id, _, _)| *id == case)
            .map(|(_, pinned, files)| {
                let files = files
                    .iter()
                    .map(|(path, bytes, sha256)| SourceFile {
                        path: (*path).to_owned(),
                        bytes: *bytes,
                        sha256: (*sha256).to_owned(),
                    })
                    .collect();
                (*pinned, files)
            })
    }

    /// The reimplementation, proved against real harness input and output.
    #[test]
    fn the_go_manifest_digest_reproduces_the_pins_it_was_written_against() {
        for (id, pinned, _) in FROZEN_PINS {
            let (_, files) = frozen(id).expect("frozen case");
            let digest = sha256_bytes(go_canonical_manifest(&files).as_bytes());
            assert_eq!(
                digest,
                *pinned,
                "{id}: recomputed {digest} from {} file(s)",
                files.len()
            );
        }
    }

    /// And the live corpus, while it is still the corpus those pins were taken
    /// from. The ledger digests with BLAKE3 and this contract's digest is
    /// SHA-256, so what the ledger can still prove in every lane is the *set*:
    /// the same file names at the same sizes the frozen rows record. A
    /// regeneration replaces the fixtures and moves the pins in the same
    /// reviewed change, so between the two the ledger legitimately disagrees
    /// with `corpus.json`.
    #[test]
    fn the_live_ledger_still_describes_the_sets_the_pins_were_taken_from() {
        let root = workspace();
        let ledger = Ledger::load(&repo_path(&root, LEDGER_FILE)).unwrap();
        let cases = load_cases(&repo_path(&root, BENCH_CORPUS_FILE)).unwrap();
        assert_eq!(cases.len(), 6, "six benchmark cases import a fixture set");
        assert_eq!(cases.len(), FROZEN_PINS.len());
        for case in &cases {
            let sizes = fixture_sizes_from_ledger(&ledger, case).unwrap();
            let (_, frozen_files) = frozen(&case.id)
                .unwrap_or_else(|| panic!("{}: a new importing case needs a frozen row", case.id));
            let expected: Vec<(String, u64)> = frozen_files
                .iter()
                .map(|file| (file.path.clone(), file.bytes))
                .collect();
            if sizes != expected {
                eprintln!(
                    "{}: the corpus was regenerated since these pins were taken; \
                     `test-corpus bench-pins` prints the new ones",
                    case.id
                );
            }
        }
    }

    /// And from the tree, when the bytes are there: the pins are computed the
    /// way `bench-pins` computes them, and an *unchanged* set that produces a
    /// different digest still fails — which is what makes the frozen proof
    /// above transferable to the live corpus.
    #[test]
    fn the_tree_reproduces_the_live_pins_when_the_fixtures_are_hydrated() {
        let root = workspace();
        let cases = load_cases(&repo_path(&root, BENCH_CORPUS_FILE)).unwrap();
        let harness_root = repo_path(&root, BENCH_HARNESS_ROOT);
        for case in &cases {
            let Ok(from_tree) = fixture_files(&harness_root, case) else {
                eprintln!("skipping {}: fixtures not hydrated", case.id);
                continue;
            };
            let (_, frozen_files) = frozen(&case.id)
                .unwrap_or_else(|| panic!("{}: a new importing case needs a frozen row", case.id));
            if from_tree != frozen_files {
                eprintln!(
                    "{}: the corpus was regenerated since these pins were taken; \
                     `test-corpus bench-pins` prints the new ones",
                    case.id
                );
                continue;
            }
            let digest = sha256_bytes(go_canonical_manifest(&from_tree).as_bytes());
            assert_eq!(digest, case.pinned_sha256, "{}", case.id);
        }
    }

    /// The encoding itself, against values `encoding/json` treats specially.
    #[test]
    fn the_encoding_matches_encoding_json() {
        assert_eq!(go_canonical_manifest(&[]), "[]");
        let files = vec![
            SourceFile {
                path: "a<b>&c\"d\\e".to_owned(),
                bytes: 0,
                sha256: "0".repeat(64),
            },
            SourceFile {
                path: "z\u{2028}\u{0001}".to_owned(),
                bytes: 18_446_744_073_709_551_615,
                sha256: String::new(),
            },
        ];
        assert_eq!(
            go_canonical_manifest(&files),
            format!(
                "[{{\"path\":\"a\\u003cb\\u003e\\u0026c\\\"d\\\\e\",\"bytes\":0,\"sha256\":\"{}\"}},\
                 {{\"path\":\"z\\u2028\\u0001\",\"bytes\":18446744073709551615,\"sha256\":\"\"}}]",
                "0".repeat(64)
            )
        );
    }
}
