//! End-to-end wasm PAR3 create + verify + repair harness.
//!
//! PAR3 had never *run* on wasm: the only wasm coverage in CI is a
//! `cargo check` of the library. This harness is the counterpart to
//! `par2-rs`'s `wasm_par2_check`, and it exists for two jobs.
//!
//! **Correctness.** Every phase prints a canonical line, and every line that
//! could differ between builds carries a digest rather than a verdict, so the
//! portable, `+simd128` and `+relaxed-simd` lanes can be diffed against a
//! native reference run instead of each merely saying `PASS`. The GF(2⁸)
//! multiply-accumulate that the Cauchy codec dispatches through has a wasm
//! SIMD tier; a lane that computes different parity bytes changes a digest
//! here, not just a timing.
//!
//! **Measurement.** Each phase reports its own wall time on a `time ` line, so
//! whole-process runs can be alternated between two builds and compared by
//! median. Timings deliberately exclude the fixture copying that precedes
//! them: repair rewrites files in place, so every case works on its own copy.
//!
//! The phases, per case:
//!
//!   1. VERIFY (healthy): assemble the set from its `.par3` files and assert
//!      every protected file comes back complete.
//!   2. DAMAGE: overwrite whole blocks of the case's largest input, keeping a
//!      pristine copy in a stash directory the repairer never scans — so the
//!      damaged blocks are genuinely lost and Reed-Solomon reconstruction is
//!      the only way back, rather than a relocating copy.
//!   3. VERIFY (damaged): assert the set no longer reports complete.
//!   4. REPAIR: repair, then assert the repaired file is byte-identical to the
//!      pristine copy — repair produced the *right* bytes, not merely no error.
//!      The fingerprint of the repaired file is printed for the lane diff.
//!
//! A case with no recovery blocks (`index_only`) runs phase 1 only; it is
//! there to keep the verifier honest about a set that cannot be repaired.
//!
//! Then, once:
//!
//!   5. CREATE: build a fresh set over a fixture input at a block size that
//!      keeps the set in GF(2⁸), and print the fingerprint of every `.par3`
//!      file written. Creation is specified to be invariant across lanes, so
//!      those digests are the byte-identity gate on the encoder.
//!   6. REBUILD: damage that freshly created set's source and repair it from
//!      the volumes just written — the decoder counterpart, and the phase
//!      where the GF(2⁸) kernel does the most work.
//!   7. HASH: report BLAKE3's compiled-in tier and the rate at which this
//!      build fingerprints the largest fixture. Printed next to the verify
//!      times, it is what turns "hashing share of a verify" into a number
//!      rather than an assumption.
//!
//! Build (wasm, SIMD lane):
//!   RUSTFLAGS="-C target-feature=+simd128" cargo build --release --locked \
//!     -p par3-rs --features wasm-simd --target wasm32-wasip1 \
//!     --example wasm_par3_check
//!
//! Run (wasmtime; host::guest preopens):
//!   wasmtime run --dir crates/par3-rs/tests/fixtures::/fixtures \
//!     --dir <writable-scratch>::/scratch \
//!     target/wasm32-wasip1/release/examples/wasm_par3_check.wasm \
//!     /fixtures /scratch
//!
//! Also runs natively, which is what the lane diff compares against:
//!   cargo run --release -p par3-rs --example wasm_par3_check -- \
//!     crates/par3-rs/tests/fixtures <scratch>
//!
//! This is an example, not a tool, and not official PAR3 tooling.

use std::path::{Path, PathBuf};
use std::time::Instant;

use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::hash::{FingerprintHasher, fingerprint};
use par3_rs::repair::{RepairOptions, repair_set};
use par3_rs::{Packet, Par3Set, scan_packets_from_path, verify_set};

type Outcome<T> = std::result::Result<T, String>;

/// One corpus case: its directory name, and whether it carries recovery.
struct Case {
    name: &'static str,
    repairable: bool,
}

const fn case(name: &'static str, repairable: bool) -> Case {
    Case { name, repairable }
}

/// Every published PAR3 corpus case, in a fixed order so reports line up.
/// `index_only` has no recovery blocks: it is verified and never repaired.
const CASES: &[Case] = &[
    case("gf8_packed", true),
    case("tiny_inline", true),
    case("auto_block", true),
    case("tree", true),
    case("index_only", false),
    case("gf16_blocks", true),
    case("gf16_by_recovery", true),
    case("large_stream", true),
];

/// The input the created set protects, and the one the hash probe measures.
///
/// 16 MiB is the largest fixture in the corpus. The block size below leaves it
/// at 103 input blocks, and 20 % recovery adds 21 more: under the 128-input and
/// 256-total thresholds that would otherwise move the field to GF(2¹⁶), so the
/// created set — unlike the corpus's own `large_stream` — exercises GF(2⁸).
const CREATE_CASE: &str = "large_stream";
const CREATE_INPUT: &str = "stream.bin";
const CREATE_BLOCK_BYTES: u64 = 160 * 1024;
const CREATE_RECOVERY_PERCENT: u32 = 20;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (fixtures, scratch) = match args.as_slice() {
        [fixtures, scratch] => (PathBuf::from(fixtures), PathBuf::from(scratch)),
        _ => {
            eprintln!("usage: wasm_par3_check <fixtures-dir> <scratch-dir>");
            return std::process::ExitCode::from(2);
        }
    };

    match run(&fixtures, &scratch) {
        Ok(0) => {
            println!("result OK");
            std::process::ExitCode::SUCCESS
        }
        Ok(failures) => {
            println!("result FAIL {failures}");
            std::process::ExitCode::from(1)
        }
        Err(message) => {
            eprintln!("wasm_par3_check: {message}");
            std::process::ExitCode::from(2)
        }
    }
}

/// The build this artifact is, as the report's header line.
///
/// wasm dispatch is compile-time, so the flavour is a property of the artifact
/// rather than of the run; `wasm-harness-check.sh` reads this to decide which
/// blake3 tier the lane is required to have reached.
fn lane() -> String {
    if cfg!(target_arch = "wasm32") {
        let flavour = if cfg!(target_feature = "relaxed-simd") {
            "relaxed-simd"
        } else if cfg!(target_feature = "simd128") {
            "simd128"
        } else {
            "portable"
        };
        format!("wasm32 {flavour}")
    } else {
        "native".to_string()
    }
}

fn run(fixtures: &Path, scratch: &Path) -> Outcome<usize> {
    println!("lane={}", lane());
    println!(
        "blake3 tier={:?} degree={}",
        blake3::platform::Platform::detect(),
        blake3::platform::MAX_SIMD_DEGREE
    );
    // The lane assertion: a `+simd128` artifact whose blake3 came out portable
    // is the silent regression the feature forwarding exists to prevent. The
    // library carries the same check as a `const` assertion; repeating it here
    // covers the artifact that actually ran rather than the compilation, and
    // `wasm-harness-check.sh` asserts the printed degree from outside as well.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    assert!(
        blake3::platform::MAX_SIMD_DEGREE > 1,
        "this +simd128 wasm artifact linked portable blake3"
    );

    let mut failures = 0usize;
    let mut cases = 0usize;

    for case in CASES {
        cases += 1;
        match case_phases(fixtures, scratch, case) {
            Ok(()) => {}
            Err(message) => {
                failures += 1;
                println!("case {} FAIL {message}", case.name);
            }
        }
    }

    cases += 1;
    match created_set_phases(fixtures, scratch) {
        Ok(()) => {}
        Err(message) => {
            failures += 1;
            println!("case created FAIL {message}");
        }
    }

    cases += 1;
    match hash_probe(fixtures) {
        Ok(()) => {}
        Err(message) => {
            failures += 1;
            println!("case hash FAIL {message}");
        }
    }

    println!("cases={cases} failed={failures}");
    Ok(failures)
}

// ---------------------------------------------------------------------------
// Per-case phases
// ---------------------------------------------------------------------------

fn case_phases(fixtures: &Path, scratch: &Path, case: &Case) -> Outcome<()> {
    let source = fixtures.join(case.name);
    if !source.is_dir() {
        return Err(format!("fixture case {} is not hydrated", case.name));
    }
    let work = scratch.join(case.name);
    let stash = scratch.join("stash").join(case.name);
    remove_tree(&work)?;
    remove_tree(&stash)?;
    copy_tree(&source, &work)?;

    let base = work.join("in");
    let set = load_set(&work)?;
    println!(
        "set {} blocks={} block_bytes={} field={} recovery={}",
        case.name,
        set.block_count(),
        set.block_size(),
        set.galois_field().size,
        set.recovery_blocks().len()
    );

    let started = Instant::now();
    let report = verify_set(&set, &base).map_err(|error| format!("healthy verify: {error}"))?;
    println!("time verify-healthy {} {}", case.name, millis(started));
    if !report.is_complete() {
        return Err(format!(
            "a pristine set did not verify: {} complete, {} damaged, {} missing",
            report.complete_count(),
            report.damaged_count(),
            report.missing_count()
        ));
    }
    println!(
        "verify-healthy {} complete={} damaged={} missing={} files={}",
        case.name,
        report.complete_count(),
        report.damaged_count(),
        report.missing_count(),
        report.files().len()
    );

    if !case.repairable {
        println!(
            "repair {} skipped: the set carries no recovery blocks",
            case.name
        );
        return Ok(());
    }

    let victim = largest_input(&base)?;
    let pristine = stash.join(
        victim
            .strip_prefix(&base)
            .map_err(|error| format!("victim outside the base: {error}"))?,
    );
    copy_file(&victim, &pristine)?;
    let expected = fingerprint_file(&pristine)?;

    // Never ask for more loss than the set can answer for.
    let wanted = set.recovery_blocks().len().min(2);
    let damaged_blocks = damage(&victim, set.block_size(), wanted)?;
    println!("damage {} blocks={damaged_blocks}", case.name);

    let started = Instant::now();
    let report = verify_set(&set, &base).map_err(|error| format!("damaged verify: {error}"))?;
    println!("time verify-damaged {} {}", case.name, millis(started));
    if report.is_complete() {
        return Err("a damaged set still verified as complete".to_string());
    }
    println!(
        "verify-damaged {} complete={} damaged={} missing={}",
        case.name,
        report.complete_count(),
        report.damaged_count(),
        report.missing_count()
    );

    let started = Instant::now();
    let repaired = repair_set(&set, &base, &RepairOptions::default())
        .map_err(|error| format!("repair: {error}"))?;
    println!("time repair {} {}", case.name, millis(started));
    if !repaired.is_complete() {
        return Err("repair did not complete the set".to_string());
    }

    let actual = fingerprint_file(&victim)?;
    if actual != expected {
        return Err("the repaired file does not match the pristine copy".to_string());
    }
    println!(
        "repair {} rebuilt={} fingerprint={}",
        case.name,
        repaired.repaired().len(),
        hex(&actual)
    );

    remove_tree(&work)?;
    remove_tree(&stash)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Create, then rebuild from what was created
// ---------------------------------------------------------------------------

fn created_set_phases(fixtures: &Path, scratch: &Path) -> Outcome<()> {
    let input = fixtures.join(CREATE_CASE).join("in").join(CREATE_INPUT);
    if !input.is_file() {
        return Err(format!("fixture input {CREATE_INPUT} is not hydrated"));
    }
    let work = scratch.join("created");
    let base = work.join("in");
    let stash = scratch.join("stash").join("created");
    remove_tree(&work)?;
    remove_tree(&stash)?;
    std::fs::create_dir_all(&base)
        .map_err(|error| format!("create {}: {error}", base.display()))?;
    copy_file(&input, &base.join(CREATE_INPUT))?;

    let output = work.join("created.par3");
    let options = CreateOptions::default()
        .with_block_size(CREATE_BLOCK_BYTES)
        .with_recovery(RecoveryAmount::Percent(CREATE_RECOVERY_PERCENT));
    let protected = [PathBuf::from(CREATE_INPUT)];
    let spec = InputSpec::new(&base, &protected);

    let started = Instant::now();
    let report = create(&spec, &output, &options).map_err(|error| format!("create: {error}"))?;
    println!("time create {}", millis(started));
    println!(
        "create blocks={} block_bytes={} field={} recovery={} files={}",
        report.block_count,
        report.block_size,
        report.field.size,
        report.recovery_count,
        report.files_written.len()
    );
    // Byte identity of the encoder's output, one line per volume so a lane that
    // diverges says which one.
    let mut written: Vec<PathBuf> = report.files_written.clone();
    written.sort();
    for path in &written {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into(),
        );
        println!(
            "create-file {name} fingerprint={}",
            hex(&fingerprint_file(path)?)
        );
    }

    // Rebuild: damage the source and reconstruct it from the volumes just
    // written. The pristine copy lives outside the scanned base, so the lost
    // blocks are genuinely lost.
    let set = load_set(&work)?;
    let victim = base.join(CREATE_INPUT);
    let pristine = stash.join(CREATE_INPUT);
    copy_file(&victim, &pristine)?;
    let expected = fingerprint_file(&pristine)?;
    // Take the set nearly to its limit: every lost block is a column the
    // decoder has to solve for, and this is where the GF(2^8) kernel earns
    // its place.
    let wanted = set.recovery_blocks().len().saturating_sub(1).max(1);
    let damaged_blocks = damage(&victim, set.block_size(), wanted)?;
    println!("damage created blocks={damaged_blocks}");

    let started = Instant::now();
    let repaired = repair_set(&set, &base, &RepairOptions::default())
        .map_err(|error| format!("rebuild: {error}"))?;
    println!("time rebuild {}", millis(started));
    if !repaired.is_complete() {
        return Err("the created set did not rebuild its own source".to_string());
    }
    let actual = fingerprint_file(&victim)?;
    if actual != expected {
        return Err("the rebuilt file does not match the pristine copy".to_string());
    }
    println!(
        "rebuild damaged={damaged_blocks} fingerprint={}",
        hex(&actual)
    );

    remove_tree(&work)?;
    remove_tree(&stash)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hash probe
// ---------------------------------------------------------------------------

/// Fingerprint the largest fixture and report the rate.
///
/// Verification fingerprints every protected block, so this is the hashing
/// component of a verify of the same bytes, measured on its own. It is
/// reported, never asserted: a rate is not a correctness property.
fn hash_probe(fixtures: &Path) -> Outcome<()> {
    let input = fixtures.join(CREATE_CASE).join("in").join(CREATE_INPUT);
    let bytes =
        std::fs::read(&input).map_err(|error| format!("read {}: {error}", input.display()))?;
    let started = Instant::now();
    let digest = fingerprint(&bytes);
    let elapsed = started.elapsed();
    println!("time hash {}", elapsed.as_micros() as f64 / 1000.0);
    let rate = bytes.len() as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("hash bytes={} fingerprint={}", bytes.len(), hex(&digest));
    println!("hash-rate mib_per_s={rate:.1}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_set(directory: &Path) -> Outcome<Par3Set> {
    let mut sources: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "par3")
        })
        .collect();
    sources.sort();
    if sources.is_empty() {
        return Err(format!("no .par3 file in {}", directory.display()));
    }

    let mut packets: Vec<Packet> = Vec::new();
    for source in &sources {
        let found = scan_packets_from_path(source)
            .map_err(|error| format!("scan {}: {error}", source.display()))?;
        packets.extend(found.into_iter().map(|(_offset, packet)| packet));
    }
    let mut sets =
        Par3Set::from_packets(packets).map_err(|error| format!("assemble a set: {error}"))?;
    if sets.len() != 1 {
        return Err(format!("expected one set, found {}", sets.len()));
    }
    Ok(sets.remove(0))
}

/// The largest regular file under `base`, which is the one worth damaging.
fn largest_input(base: &Path) -> Outcome<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut pending = vec![base.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read an entry: {error}"))?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|error| format!("stat {}: {error}", path.display()))?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && best.as_ref().is_none_or(|(size, _)| metadata.len() > *size)
            {
                best = Some((metadata.len(), path));
            }
        }
    }
    best.map(|(_, path)| path)
        .ok_or_else(|| format!("no input file under {}", base.display()))
}

/// Overwrite up to `wanted` whole blocks of `path` in place, keeping its
/// length, and report how many were actually hit.
///
/// Damage is made here, in memory, on a copy of an input — never by editing a
/// PAR3 packet. Whole blocks from the front, because a partial trailing block
/// can be a tail the set carries inline, and overwriting one of those is not
/// the loss this harness is trying to cause. A file shorter than one block has
/// its single (tail) block overwritten entirely.
///
/// The caller caps `wanted` by the recovery the set has on hand, so a set with
/// one recovery block still comes back.
fn damage(path: &Path, block_size: u64, wanted: usize) -> Outcome<usize> {
    let mut bytes =
        std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let block = usize::try_from(block_size).unwrap_or(usize::MAX).max(1);
    let full = bytes.len() / block;
    let count = wanted.max(1).min(full.max(1));

    for index in 0..count {
        let start = index * block;
        let end = (start + block).min(bytes.len());
        for (offset, byte) in bytes[start..end].iter_mut().enumerate() {
            *byte ^= 0xA5u8.wrapping_add(offset as u8);
        }
    }
    std::fs::write(path, &bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(count)
}

fn fingerprint_file(path: &Path) -> Outcome<[u8; 16]> {
    let mut file =
        std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = FingerprintHasher::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        use std::io::Read;
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}

fn copy_tree(from: &Path, to: &Path) -> Outcome<()> {
    std::fs::create_dir_all(to).map_err(|error| format!("create {}: {error}", to.display()))?;
    let entries =
        std::fs::read_dir(from).map_err(|error| format!("read {}: {error}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read an entry: {error}"))?;
        let path = entry.path();
        let target = to.join(entry.file_name());
        let metadata = entry
            .metadata()
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if metadata.is_dir() {
            copy_tree(&path, &target)?;
        } else if metadata.is_file() {
            copy_file(&path, &target)?;
        }
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Outcome<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|error| format!("copy {} to {}: {error}", from.display(), to.display()))
}

fn remove_tree(path: &Path) -> Outcome<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn millis(started: Instant) -> String {
    format!("{:.3}", started.elapsed().as_micros() as f64 / 1000.0)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
