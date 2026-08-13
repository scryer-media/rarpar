//! End-to-end wasm PAR2 verify + repair harness (Phase-1 runtime de-risk).
//!
//! PAR2 verify and repair had never *run* on wasm. This harness proves they do
//! under `wasmtime`, on the crate's real fixtures, with real WASI file I/O:
//!
//!   1. VERIFY (healthy): scan an undamaged set and assert the repairer reports
//!      `Verified` with zero missing blocks.
//!   2. VERIFY (damaged): corrupt a copy, scan without repairing, and assert the
//!      repairer detects damage (status becomes non-`Verified`, e.g.
//!      `RepairPossible`). The scanner relocates recoverable blocks, so the
//!      whole-set status — not a raw missing-block count — is the damage signal.
//!   3. REPAIR: repair the damaged copy and assert the repaired, PAR2-protected
//!      file is byte-identical to a pristine copy captured before corruption —
//!      i.e. repair produced the correct bytes, not merely "no error". (The
//!      protected payload here is the RAR volume the PAR2 set covers; comparing
//!      it byte-for-byte is a strict content check that does not need a RAR
//!      decoder in the guest.)
//!
//!      SCOPE, precisely: a case's [`ReferenceStash`] decides *which* repair
//!      path it covers, because the repairer scans every file in its base
//!      directory:
//!
//!      * `InsideScan` keeps the pristine copy beside the protected file, so
//!        the scanner finds the damaged slices in it and *relocates* them
//!        (hence `miss=0` on the damaged verify). These cases cover scan,
//!        planning, staged write-back, post-repair readback and atomic install
//!        — but the repair itself is a copy, so no Galois-field arithmetic runs.
//!      * `OutsideScan` keeps the copy in a sibling directory the repairer
//!        never sees, so the damaged slices are genuinely missing (`miss>0`)
//!        and Reed-Solomon *reconstruction* is the only way to get them back.
//!        Those cases are asserted to report `miss>0`, so they cannot silently
//!        decay back into relocation coverage.
//!
//!      Both stashes are exercised over the same fixtures, and every repair
//!      cell prints a digest of the repaired file so the three lanes (native,
//!      `wasm32-wasip1`, `wasm32-wasip1-threads`) can be compared directly
//!      rather than only "PASS".
//!
//! Every fixture is copied out of the read-only `/fixtures` preopen into a
//! writable `/scratch` preopen first, because repair rewrites files in place.
//!
//!   4. CREATE: build a fresh PAR2 set over fixture inputs and report a digest
//!      of the produced `.par2` bytes. The digest is the byte-identity gate:
//!      creation is specified to be invariant across worker counts and across
//!      native/wasm, so every lane and every `WEAVER_PAR2_CREATE_THREADS`
//!      setting must print the same value.
//!   5. I/O CONTRACT: read a whole protected file back through `DiskFileAccess`
//!      in one `read_file_range_into` call and require an exact fill. Every
//!      `FileAccess` consumer treats a short return as end-of-file, so an
//!      implementation that does not loop reports intact slices as damaged —
//!      which is precisely how PAR2 repair failed on `wasm32-wasip1-threads`
//!      while the staged bytes on disk were already byte-perfect. The line also
//!      prints the host's largest single `read`, because that is the property
//!      that differs: wasmtime cannot write host bytes straight into a guest
//!      with *shared* linear memory, so its WASI preview1 `fd_read` stages
//!      through a bounce buffer capped at 64 KiB, while plain `wasm32-wasip1`
//!      serves the whole request. Short reads are legal everywhere, so the cap
//!      is reported, never asserted — only the exact fill is a gate.
//!
//! Build (wasm):
//!   cargo build --release -p par2-rs --no-default-features \
//!     --target wasm32-wasip1 --example wasm_par2_check
//!
//! Run (wasmtime 47; host::guest preopens):
//!   wasmtime run \
//!     --dir crates/weaver-par2/tests/fixtures::/fixtures \
//!     --dir <writable-scratch>::/scratch \
//!     target/wasm32-wasip1/release/examples/wasm_par2_check.wasm /fixtures /scratch
//!
//! On `wasm32-wasip1-threads`, add the runtime's threading flags and state the
//! host width (the guest cannot read it: wasi's `available_parallelism` is 1):
//!   wasmtime run -W threads=y,shared-memory=y \
//!     --env WEAVER_PAR2_CREATE_THREADS=4 ...
//! NOTE: as of wasmtime 47 this `wasm32-wasip1-threads` invocation fails to
//! instantiate ("unknown import: `env::memory` has not been defined"): 47
//! removed wasi-threads/wasi-common outright, and this target's modules still
//! rely on that proposal for the imported shared memory and thread-spawn hook.
//! No flag combination restores it; see the wasm-par2-harness job in
//! `.github/workflows/ci.yml` for the full citation.
//!
//! Also runs natively for parity debugging:
//!   cargo run --release -p par2-rs --example wasm_par2_check -- \
//!     crates/weaver-par2/tests/fixtures <scratch>
//!
//! Environment knobs (all optional):
//!   * `WEAVER_WASM_BENCH=N` — timing mode: run each phase N times and report
//!     the minimum, instead of PASS/FAIL.
//!   * `WEAVER_WASM_MEM_LIMIT=M` — repairer/creator memory budget in MiB
//!     (default 256). Lowering it forces the chunked repair strategy.
//!   * `WEAVER_WASM_RECOVERY=P` — creation recovery percentage (default 5).
//!     Raising it makes creation compute-bound, which is where worker threads
//!     have something to divide.
//!   * `WEAVER_WASM_CASES=a,b` — run only the named case prefixes.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use par2_rs::{
    DiskFileAccess, FileAccess, Par2CreatorOptions, Par2FileSet, Par2RepairStatus, Par2Repairer,
    Par2RepairerOptions, RecoveryAmount,
};

/// Which arithmetic/threading build this binary is, for the report header.
///
/// wasm SIMD selection is entirely compile-time (the artifact is built with a
/// fixed `target_feature` set), so this is a `cfg!` ladder, not a runtime probe.
fn lane_label() -> &'static str {
    if cfg!(all(target_arch = "wasm32", target_feature = "relaxed-simd")) {
        "wasm32 +simd128 +relaxed-simd"
    } else if cfg!(all(target_arch = "wasm32", target_feature = "simd128")) {
        "wasm32 +simd128"
    } else if cfg!(target_arch = "wasm32") {
        "wasm32 portable (no simd128)"
    } else {
        "native"
    }
}

/// FNV-1a-64 with a final avalanche, over length-prefixed byte runs.
///
/// This only ever compares bytes produced by *this* program against bytes
/// produced by another lane of the same program, so a compact non-cryptographic
/// digest is the right tool: it needs to be identical for identical inputs and
/// differ loudly otherwise, nothing more. Length is folded in so truncation
/// cannot alias.
fn digest64(state: u64, bytes: &[u8]) -> u64 {
    let mut hash = state;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= bytes.len() as u64;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^ (hash >> 33)
}

/// Digest a set of files by (name, contents), in sorted-name order, so the
/// result is independent of directory-iteration order across hosts.
fn digest_files(paths: &[PathBuf]) -> io::Result<u64> {
    let mut sorted = paths.to_vec();
    sorted.sort();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for path in &sorted {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        hash = digest64(hash, name.as_bytes());
        hash = digest64(hash, &fs::read(path)?);
    }
    Ok(hash)
}

/// Repairer/creator memory budget, in bytes.
fn memory_limit() -> usize {
    std::env::var("WEAVER_WASM_MEM_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&m| m != 0)
        .unwrap_or(256)
        * 1024
        * 1024
}

/// Recovery percentage for the create workload (default 5).
fn recovery_percent() -> u32 {
    std::env::var("WEAVER_WASM_RECOVERY")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(5)
}

/// Timing-mode iteration count; `0` (the default) means PASS/FAIL mode.
fn bench_iters() -> usize {
    std::env::var("WEAVER_WASM_BENCH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// Optional comma-separated case-prefix filter.
fn case_filter() -> Option<Vec<String>> {
    std::env::var("WEAVER_WASM_CASES").ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn selected(filter: &Option<Vec<String>>, label: &str) -> bool {
    match filter {
        None => true,
        Some(wanted) => {
            let lower = label.to_ascii_lowercase();
            wanted.iter().any(|w| lower.starts_with(w))
        }
    }
}

/// Run `body` `iters` times and return the fastest observed duration.
///
/// Min-of-N, not mean: this machine may be running other work concurrently, so
/// the minimum is the least contaminated estimate of the lane's real cost.
fn best_of<T, F: FnMut() -> Result<T, String>>(
    iters: usize,
    mut body: F,
) -> Result<Duration, String> {
    let mut best = Duration::MAX;
    for _ in 0..iters.max(1) {
        let start = Instant::now();
        body()?;
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
    }
    Ok(best)
}

/// One corruption site inside a protected file.
#[derive(Clone, Copy)]
struct Corruption {
    /// Byte offset into the protected file.
    offset: u64,
    /// Number of bytes to overwrite with a fixed non-matching pattern.
    len: usize,
}

/// Where `run_case` keeps its pristine copy of the protected file — and
/// therefore which repair path the case actually covers.
///
/// The repairer scans every file in its base directory, so a pristine copy left
/// *inside* that directory is itself a source of the damaged slices: the
/// scanner relocates them and repair degrades to a copy. Keeping the copy
/// outside the scanned directory is the only way to make a damaged slice
/// genuinely missing, which is the only way Reed-Solomon reconstruction runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceStash {
    /// Beside the protected file: slices relocate, repair is copy-only
    /// (`miss=0`).
    InsideScan,
    /// In a sibling directory the repairer never scans: slices are missing and
    /// must be reconstructed (`miss>0`, asserted).
    OutsideScan,
}

/// A verify + repair scenario over one fixture directory.
struct Case {
    label: &'static str,
    /// Fixture subdirectory under the fixtures root (copied wholesale).
    dir: &'static str,
    /// Prefix of the `.par2` files to hand the repairer.
    par2_prefix: &'static str,
    /// The PAR2-protected file that gets damaged then repaired.
    protected: &'static str,
    /// Corruption sites applied to `protected` for the damaged/repair passes.
    corruptions: &'static [Corruption],
    /// Relocation coverage (`InsideScan`) or reconstruction coverage
    /// (`OutsideScan`).
    reference: ReferenceStash,
}

impl Case {
    /// Scratch subdirectory for this case. The two stashes run the same fixture
    /// twice, so they must not share a working copy.
    fn work_dir(&self, prefix: &str) -> String {
        match self.reference {
            ReferenceStash::InsideScan => format!("{prefix}{}", self.dir),
            ReferenceStash::OutsideScan => format!("{prefix}{}_reconstruct", self.dir),
        }
    }

    /// Path of the pristine reference copy for this case's stash policy.
    ///
    /// `work` is the scanned base directory; `scratch_root` is its parent, which
    /// the repairer never looks at.
    fn reference_path(&self, work: &Path, scratch_root: &Path) -> io::Result<PathBuf> {
        match self.reference {
            ReferenceStash::InsideScan => Ok(work.join(format!("{}.pristine", self.protected))),
            ReferenceStash::OutsideScan => {
                let dir = scratch_root.join(format!("{}.reference", self.work_dir("")));
                let _ = fs::remove_dir_all(&dir);
                fs::create_dir_all(&dir)?;
                Ok(dir.join(self.protected))
            }
        }
    }
}

const CASES: &[Case] = &[
    // rar5 "lz plain": PAR2 protects a multi-volume RAR set; corrupt one region
    // of the middle-ish volume (well within recovery budget) and repair it.
    Case {
        label: "rar5 lz plain (single-region)",
        dir: "rar5_lz_plain",
        par2_prefix: "fixture_rar5_lz_plain_repair",
        protected: "fixture_rar5_lz_plain.part3.rar",
        corruptions: &[Corruption {
            offset: 4096,
            len: 2048,
        }],
        reference: ReferenceStash::InsideScan,
    },
    // rar4 store, encrypted payload: PAR2 protection is over the ciphertext
    // volume, so repair is a pure byte-reconstruction problem (no crypto here).
    Case {
        label: "rar4 store enc (single-region)",
        dir: "rar4_store_enc",
        par2_prefix: "fixture_rar4_store_enc_repair",
        protected: "fixture_rar4_store_enc.part3.rar",
        corruptions: &[Corruption {
            offset: 8192,
            len: 1024,
        }],
        reference: ReferenceStash::InsideScan,
    },
    // Heavy damage: many corruption sites spread across one large RAR volume,
    // near the recovery ceiling — exercises multi-slice reconstruction at scale
    // through the portable (non-x86) GF reconstruct path on wasm.
    Case {
        label: "rar5 heavy damage (28 regions)",
        dir: "rar5_heavy_damage",
        par2_prefix: "fixture_rar5_heavy_damage_repair",
        protected: "fixture_rar5_heavy_damage.rar",
        corruptions: HEAVY_DAMAGE_SITES,
        reference: ReferenceStash::InsideScan,
    },
    // ── Forced reconstruction ─────────────────────────────────────────────
    // The same three workloads with the pristine copy moved out of the scanned
    // directory. Nothing can relocate the damaged slices now, so the streamed
    // CPU repair controller has to run the Galois-field solve — the path that
    // plain `wasm32-wasip1` could not reach at all while the controller
    // depended on `std::thread::scope`.
    Case {
        label: "rar5 lz plain reconstruct",
        dir: "rar5_lz_plain",
        par2_prefix: "fixture_rar5_lz_plain_repair",
        protected: "fixture_rar5_lz_plain.part3.rar",
        corruptions: &[Corruption {
            offset: 4096,
            len: 2048,
        }],
        reference: ReferenceStash::OutsideScan,
    },
    Case {
        label: "rar4 store enc reconstruct",
        dir: "rar4_store_enc",
        par2_prefix: "fixture_rar4_store_enc_repair",
        protected: "fixture_rar4_store_enc.part3.rar",
        corruptions: &[Corruption {
            offset: 8192,
            len: 1024,
        }],
        reference: ReferenceStash::OutsideScan,
    },
    // 28 missing slices at once: the multi-output, multi-chunk shape of the
    // controller, where batching, backpressure and staging-area rotation all
    // have something to do.
    Case {
        label: "rar5 heavy damage reconstruct",
        dir: "rar5_heavy_damage",
        par2_prefix: "fixture_rar5_heavy_damage_repair",
        protected: "fixture_rar5_heavy_damage.rar",
        corruptions: HEAVY_DAMAGE_SITES,
        reference: ReferenceStash::OutsideScan,
    },
];

/// 28 corruption sites at 64 KiB-slice granularity with varied sizes, mirroring
/// the native `repairs_heavy_damage_28_regions_rar5` integration test.
const HEAVY_DAMAGE_SITES: &[Corruption] = &{
    const SLICE: u64 = 65536;
    // Deterministic stride computed at runtime would need the file size; the
    // native test uses stride = total_slices / 29. The generated fixture is
    // ~73 MiB => ~1128 slices => stride ~= 38. Use a fixed stride that lands
    // each hit in a distinct slice well inside the file.
    const STRIDE: u64 = 38;
    const SIZES: [usize; 28] = [
        1, 16, 64, 256, 512, 1024, 2048, 4096, 1, 16, 64, 256, 512, 1024, 2048, 4096, 1, 16, 64,
        256, 512, 1024, 2048, 4096, 1, 16, 64, 256,
    ];
    let mut sites = [Corruption { offset: 0, len: 0 }; 28];
    let mut i = 0;
    while i < 28 {
        // +100 to avoid landing exactly on a slice boundary, skip slice 0.
        sites[i] = Corruption {
            offset: STRIDE * (i as u64 + 1) * SLICE + 100,
            len: SIZES[i],
        };
        i += 1;
    }
    sites
};

/// Recursively copy a directory's contents.
fn copy_dir(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Collect `.par2` paths in `dir` whose file name starts with `prefix`, sorted.
fn collect_par2(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("par2")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    paths.sort();
    paths
}

/// Overwrite `len` bytes at `offset` in `path` with a fixed pattern that will
/// not match the original data.
fn corrupt(path: &Path, offset: u64, len: usize) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&vec![0xA5u8; len])?;
    f.flush()?;
    Ok(())
}

/// Run the repairer, surfacing failures as `Err` rather than panicking.
///
/// The original harness used `.expect(...)`, which aborts the whole run on the
/// first bad case and hides the results of every later case. Returning the
/// error instead lets one broken lane still report the other cases — which is
/// what makes this harness usable as a diagnostic, not just a gate.
fn run_repairer(
    base: &Path,
    par2_paths: &[PathBuf],
    repair: bool,
) -> Result<par2_rs::Par2RepairOutcome, String> {
    let mut options = Par2RepairerOptions::new(base.to_path_buf(), par2_paths.to_vec());
    options.repair = repair;
    options.memory_limit = Some(memory_limit());
    Par2Repairer::new(options)
        .verify_or_repair()
        .map_err(|e| format!("{e:?}"))
}

/// One PAR2 creation scenario over a fixture directory.
struct CreateCase {
    label: &'static str,
    /// Fixture subdirectory holding the inputs (copied into scratch first).
    dir: &'static str,
    /// Input file names within `dir` that the created set protects.
    inputs: &'static [&'static str],
}

const CREATE_CASES: &[CreateCase] = &[
    // Multi-file input: exercises the parallel source-hashing fan-out (one
    // rayon task per file) as well as banded recovery accumulation.
    CreateCase {
        label: "create rar5 lz plain (6 inputs)",
        dir: "rar5_lz_plain",
        inputs: &[
            "fixture_rar5_lz_plain.part1.rar",
            "fixture_rar5_lz_plain.part2.rar",
            "fixture_rar5_lz_plain.part3.rar",
            "fixture_rar5_lz_plain.part4.rar",
            "fixture_rar5_lz_plain.part5.rar",
            "fixture_rar5_lz_plain.part6.rar",
        ],
    },
    // Single large input (~73 MiB): the banded forward-accumulation workload,
    // where creation-side threading actually has something to divide.
    CreateCase {
        label: "create rar5 heavy (73MiB)",
        dir: "rar5_heavy_damage",
        inputs: &["fixture_rar5_heavy_damage.rar"],
    },
];

/// Create a PAR2 set over `case`'s inputs and digest the produced `.par2`
/// bytes.
///
/// The digest — not merely "it succeeded" — is the byte-identity gate: PAR2
/// creation in this crate is specified to be invariant across worker counts,
/// so the same digest must come back from every thread count and from native
/// and wasm alike.
fn run_create(fixtures_root: &Path, scratch_root: &Path, case: &CreateCase) -> Result<u64, String> {
    let src_dir = fixtures_root.join(case.dir);
    let work = scratch_root.join(format!("create_{}", case.dir));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).map_err(|e| format!("mkdir {}: {e}", work.display()))?;

    // Copy only the declared inputs, so stray fixture `.par2` files cannot be
    // picked up by the output digest below.
    for name in case.inputs {
        fs::copy(src_dir.join(name), work.join(name))
            .map_err(|e| format!("copy input {name}: {e}"))?;
    }

    let inputs: Vec<PathBuf> = case.inputs.iter().map(|n| work.join(n)).collect();
    let mut options = Par2CreatorOptions::new(Some(work.clone()), inputs);
    options.set_output(work.join("created"));
    // Pin every policy the digest depends on, so the gate compares arithmetic
    // and threading — not an incidental difference in automatic sizing.
    // Recovery percentage sets how much GF accumulation creation actually has
    // to do, which is the only part of creation that bands across threads. The
    // 5% default matches a realistic set; raising it via the env knob produces a
    // compute-bound workload where thread scaling is observable rather than
    // buried under I/O and hashing.
    options.recovery_amount = RecoveryAmount::Percent(recovery_percent());
    options.memory_limit = Some(memory_limit());
    options.overwrite = true;

    let creator = par2_rs::Par2Creator::new(options);
    let plan = creator.plan().map_err(|e| format!("plan: {e:?}"))?;
    creator
        .create(&plan)
        .map_err(|e| format!("create: {e:?}"))?;

    let produced: Vec<PathBuf> = fs::read_dir(&work)
        .map_err(|e| format!("read_dir {}: {e}", work.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("par2"))
        .collect();
    if produced.is_empty() {
        return Err("creation produced no .par2 files".to_string());
    }
    digest_files(&produced).map_err(|e| format!("digest outputs: {e}"))
}

/// One whole-file readback scenario over a fixture directory.
struct IoCase {
    label: &'static str,
    /// Fixture subdirectory holding the `.par2` set and the protected file.
    dir: &'static str,
    /// Prefix of the `.par2` files describing the set.
    par2_prefix: &'static str,
    /// The protected file to read back in a single call. Must be larger than
    /// any plausible host single-read cap for the case to mean anything.
    protected: &'static str,
}

const IO_CASES: &[IoCase] = &[
    // 196,608 bytes — three times wasmtime's 64 KiB shared-memory bounce
    // buffer, so a non-looping `read_file_range_into` returns exactly one
    // third of it on `wasm32-wasip1-threads`.
    IoCase {
        label: "io fill rar5 lz plain (192KiB)",
        dir: "rar5_lz_plain",
        par2_prefix: "fixture_rar5_lz_plain_repair",
        protected: "fixture_rar5_lz_plain.part3.rar",
    },
    IoCase {
        label: "io fill rar4 store enc",
        dir: "rar4_store_enc",
        par2_prefix: "fixture_rar4_store_enc_repair",
        protected: "fixture_rar4_store_enc.part3.rar",
    },
];

/// Largest number of bytes this host returns from a single `Read::read`.
///
/// Purely diagnostic: a short read is legal on every platform, so nothing is
/// asserted about the value. It is printed because it is the one environment
/// fact that separates the two wasm targets, and a future readback regression
/// is far easier to place with it on the page than without.
fn single_read_cap(path: &Path, len: usize) -> io::Result<usize> {
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; len];
    file.read(&mut buf)
}

/// Read `case`'s protected file back through `DiskFileAccess` in one call and
/// require the buffer to come back completely filled and byte-correct.
///
/// This is the narrow gate for the contract that `verify.rs` already assumes
/// everywhere: `read_file_range_into` returns less than the buffer length only
/// at end-of-file. When a filesystem-backed implementation breaks that promise
/// the damage surfaces far away — `check_slice_span` marks a whole span invalid
/// when the fill falls short — so failing here instead names the cause.
fn run_io_case(fixtures_root: &Path, scratch_root: &Path, case: &IoCase) -> Result<String, String> {
    let src_dir = fixtures_root.join(case.dir);
    let work = scratch_root.join(format!("io_{}", case.dir));
    let _ = fs::remove_dir_all(&work);
    copy_dir(&src_dir, &work).map_err(|e| format!("copy fixtures: {e}"))?;

    let par2_paths = collect_par2(&work, case.par2_prefix);
    if par2_paths.is_empty() {
        return Err(format!("no .par2 files matching '{}'", case.par2_prefix));
    }
    let set = Par2FileSet::from_paths(&par2_paths).map_err(|e| format!("parse set: {e:?}"))?;

    let protected = work.join(case.protected);
    let expected = fs::read(&protected).map_err(|e| format!("read protected: {e}"))?;
    let len = expected.len();

    let file_id = *set
        .files
        .iter()
        .find(|(_, desc)| desc.filename == case.protected)
        .map(|(file_id, _)| file_id)
        .ok_or_else(|| format!("{} is not described by the set", case.protected))?;

    let access = DiskFileAccess::new(work.clone(), &set);

    let mut dst = vec![0u8; len];
    let filled = access
        .read_file_range_into(&file_id, 0, &mut dst)
        .map_err(|e| format!("read_file_range_into: {e}"))?;
    if filled != len {
        return Err(format!(
            "read_file_range_into filled {filled} of {len} bytes (short read reported as EOF)"
        ));
    }
    if dst != expected {
        return Err("read_file_range_into returned the wrong bytes".to_string());
    }

    let owned = access
        .read_file_range(&file_id, 0, len as u64)
        .map_err(|e| format!("read_file_range: {e}"))?;
    if owned.len() != len {
        return Err(format!(
            "read_file_range returned {} of {len} bytes",
            owned.len()
        ));
    }
    if owned != expected {
        return Err("read_file_range returned the wrong bytes".to_string());
    }

    let cap = single_read_cap(&protected, len).map_err(|e| format!("probe single read: {e}"))?;
    Ok(format!(
        "filled {len}/{len}; host single read={cap}{}",
        if cap < len { " (CAPPED)" } else { "" }
    ))
}

/// Compare two files and describe the difference compactly.
///
/// Reports the first differing offset, the total number of differing bytes, and
/// how many distinct 64 KiB-aligned regions are affected — enough to tell a
/// whole-file mismatch from a handful of unreconstructed slices.
fn diff_summary(actual: &Path, expected: &Path) -> String {
    let (a, b) = match (fs::read(actual), fs::read(expected)) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => return format!("byte-compare unavailable ({a:?} / {b:?})"),
    };
    if a.len() != b.len() {
        return format!("on-disk length differs: {} vs {}", a.len(), b.len());
    }
    let mut first = None;
    let mut differing = 0usize;
    let mut regions = std::collections::BTreeSet::new();
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x != y {
            first.get_or_insert(i);
            differing += 1;
            regions.insert(i / 65536);
        }
    }
    match first {
        None => "on-disk bytes are IDENTICAL to pristine".to_string(),
        Some(offset) => format!(
            "on-disk bytes DIFFER: first@{offset}, {differing} bytes across {} 64KiB regions",
            regions.len()
        ),
    }
}

/// Result of one case's three sub-checks.
struct CaseReport {
    verify_healthy: Result<(), String>,
    verify_damaged: Result<(), String>,
    repair: Result<(), String>,
    /// Repairer status observed on the healthy verify pass (expected `Verified`).
    healthy_status: String,
    /// Repairer status observed on the damaged verify pass (expected non-`Verified`).
    damaged_status: String,
    /// Digest of the repaired file, for cross-lane comparison. Every lane must
    /// print the same value for a given case; `None` means repair never got far
    /// enough to produce bytes.
    repaired_digest: Option<u64>,
}

fn run_case(fixtures_root: &Path, scratch_root: &Path, case: &Case) -> CaseReport {
    let src_dir = fixtures_root.join(case.dir);
    let work = scratch_root.join(case.work_dir(""));
    let _ = fs::remove_dir_all(&work);

    let mut report = CaseReport {
        verify_healthy: Ok(()),
        verify_damaged: Ok(()),
        repair: Ok(()),
        healthy_status: "-".to_string(),
        damaged_status: "-".to_string(),
        repaired_digest: None,
    };

    if let Err(e) = copy_dir(&src_dir, &work) {
        let msg = format!("copy fixtures {}: {e}", src_dir.display());
        report.verify_healthy = Err(msg.clone());
        report.verify_damaged = Err(msg.clone());
        report.repair = Err(msg);
        return report;
    }

    let par2_paths = collect_par2(&work, case.par2_prefix);
    if par2_paths.is_empty() {
        let msg = format!(
            "no .par2 files matching '{}' in {}",
            case.par2_prefix,
            work.display()
        );
        report.verify_healthy = Err(msg.clone());
        report.verify_damaged = Err(msg.clone());
        report.repair = Err(msg);
        return report;
    }
    let protected = work.join(case.protected);

    // Stash a pristine copy of the protected file for the post-repair byte
    // check. Where it goes decides whether repair relocates or reconstructs —
    // see `ReferenceStash`.
    let pristine = match case.reference_path(&work, scratch_root) {
        Ok(path) => path,
        Err(e) => {
            report.repair = Err(format!("prepare reference directory: {e}"));
            return report;
        }
    };
    if let Err(e) = fs::copy(&protected, &pristine) {
        report.repair = Err(format!("stash pristine {}: {e}", protected.display()));
    }

    // (1) VERIFY healthy: undamaged set must be Verified with no missing blocks.
    match run_repairer(&work, &par2_paths, false) {
        Err(e) => report.verify_healthy = Err(format!("repairer error: {e}")),
        Ok(outcome) => {
            report.healthy_status = format!("{:?}", outcome.status);
            if outcome.status != Par2RepairStatus::Verified {
                report.verify_healthy = Err(format!("expected Verified, got {:?}", outcome.status));
            } else if outcome.verification.total_missing_blocks != 0 {
                report.verify_healthy = Err(format!(
                    "healthy set reported {} missing blocks",
                    outcome.verification.total_missing_blocks
                ));
            }
        }
    }

    // Damage the protected file.
    for c in case.corruptions {
        if let Err(e) = corrupt(&protected, c.offset, c.len) {
            let msg = format!("corrupt {} @{}: {e}", protected.display(), c.offset);
            report.verify_damaged = Err(msg.clone());
            report.repair = Err(msg);
            return report;
        }
    }

    // (2) VERIFY damaged: scan WITHOUT repairing; must detect damage. A healthy
    // set returns `Verified`; a damaged (but repairable) set returns
    // `RepairPossible`. The scanner relocates recoverable blocks, so
    // `total_missing_blocks` can legitimately be 0 while the file still fails
    // its whole-file identity check — the authoritative "damage present" signal
    // is therefore `status != Verified`. We report the damaged-file count too.
    match run_repairer(&work, &par2_paths, false) {
        Err(e) => report.verify_damaged = Err(format!("repairer error: {e}")),
        Ok(outcome) => {
            // The missing-block count is what the repair plan is built from: if the
            // scanner reports zero missing blocks on a damaged set, repair has
            // nothing to reconstruct and silently writes nothing.
            report.damaged_status = format!(
                "{:?} miss={} dmg={}",
                outcome.status, outcome.verification.total_missing_blocks, outcome.files_damaged
            );
            let detected_damage = outcome.status != Par2RepairStatus::Verified;
            if !detected_damage {
                report.verify_damaged = Err(format!(
                    "damage not detected: status={:?} (damaged_files={}, missing_files={}, missing_blocks={})",
                    outcome.status,
                    outcome.files_damaged,
                    outcome.files_missing,
                    outcome.verification.total_missing_blocks
                ));
            } else if case.reference == ReferenceStash::OutsideScan
                && outcome.verification.total_missing_blocks == 0
            {
                // Without this the case silently degrades into another
                // relocation test: everything still passes, but the Galois-field
                // reconstruct it exists to cover never runs.
                report.verify_damaged = Err(
                    "reconstruction case reported 0 missing blocks: a relocation source is still \
                     inside the scanned directory"
                        .to_string(),
                );
            }
        }
    }

    // (3) REPAIR: repair in place, then require Repaired + byte-identical output.
    if report.repair.is_ok() {
        let outcome = match run_repairer(&work, &par2_paths, true) {
            Ok(outcome) => outcome,
            Err(e) => {
                // Even when the repairer reports failure, say whether the bytes
                // it left on disk are right. That distinguishes "reconstructed
                // the wrong data" from "reconstructed correctly but the
                // post-repair verification pass misjudged it" — two very
                // different bugs that produce the same error string.
                report.repair = Err(format!(
                    "repairer error: {e}; {}",
                    diff_summary(&protected, &pristine)
                ));
                return report;
            }
        };
        if outcome.status != Par2RepairStatus::Repaired {
            report.repair = Err(format!(
                "expected Repaired, got {:?} (missing_blocks={})",
                outcome.status, outcome.verification.total_missing_blocks
            ));
        } else {
            match (fs::read(&protected), fs::read(&pristine)) {
                (Ok(repaired), Ok(original)) => {
                    // Digest the repaired bytes even when they are correct: it
                    // is what makes "native and both wasm targets produced the
                    // same file" checkable from the three reports side by side.
                    report.repaired_digest = Some(digest64(0xcbf2_9ce4_8422_2325, &repaired));
                    if repaired != original {
                        report.repair = Err(format!(
                            "repaired bytes differ from pristine (len {} vs {})",
                            repaired.len(),
                            original.len()
                        ));
                    }
                }
                (a, b) => {
                    report.repair = Err(format!("re-read after repair failed: {a:?} / {b:?}"));
                }
            }
        }
    }

    report
}

fn main() {
    let mut args = std::env::args().skip(1);
    let fixtures_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/fixtures"));
    let scratch_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/scratch"));

    eprintln!(
        "wasm_par2_check: fixtures={} scratch={}",
        fixtures_root.display(),
        scratch_root.display()
    );

    let mut stdout = io::stdout();
    let filter = case_filter();
    // The header states the lane and the threading inputs, because every number
    // and digest below is only interpretable against them. `available_parallelism`
    // is printed because under wasi it reads `1` no matter how many cores the
    // host has — which is exactly why the env var exists.
    let _ = writeln!(
        stdout,
        "lane={} | WEAVER_PAR2_CREATE_THREADS={} | available_parallelism={:?} | mem_limit={}MiB",
        lane_label(),
        std::env::var("WEAVER_PAR2_CREATE_THREADS").unwrap_or_else(|_| "<unset>".to_string()),
        std::thread::available_parallelism().map(|n| n.get()),
        memory_limit() / (1024 * 1024),
    );

    if bench_iters() > 0 {
        run_bench(&mut stdout, &fixtures_root, &scratch_root, &filter);
        return;
    }

    let _ = writeln!(
        stdout,
        "==== PAR2 verify + repair PASS/FAIL (wasm runtime) ===="
    );
    let _ = writeln!(
        stdout,
        "{:<32} | {:<22} | {:<26} | {:<20}",
        "case", "verify-healthy", "verify-damaged", "repair (byte-exact)"
    );

    let mut failed = 0usize;
    let mut ran = 0usize;
    for case in CASES {
        if !selected(&filter, case.label) {
            continue;
        }
        ran += 1;
        let r = run_case(&fixtures_root, &scratch_root, case);
        let cell = |res: &Result<(), String>| match (res, r.repaired_digest) {
            (Ok(()), Some(digest)) => format!("PASS d={digest:016x}"),
            (Ok(()), None) => "PASS".to_string(),
            (Err(e), _) => format!("FAIL: {e}"),
        };
        if r.verify_healthy.is_err() || r.verify_damaged.is_err() || r.repair.is_err() {
            failed += 1;
        }
        let ok = |res: &Result<(), String>| if res.is_ok() { "PASS" } else { "FAIL" };
        let _ = writeln!(
            stdout,
            "{:<32} | {:<22} | {:<26} | {:<20}",
            case.label,
            format!("{} [{}]", ok(&r.verify_healthy), r.healthy_status),
            format!("{} [{}]", ok(&r.verify_damaged), r.damaged_status),
            cell(&r.repair),
        );
        // Detailed failure lines (the compact table truncates messages).
        for (name, res) in [
            ("verify-healthy", &r.verify_healthy),
            ("verify-damaged", &r.verify_damaged),
            ("repair", &r.repair),
        ] {
            if let Err(e) = res {
                let _ = writeln!(stdout, "    [{}] {} -> {e}", case.label, name);
            }
        }
    }

    // I/O CONTRACT: whole-file readback through `DiskFileAccess`. Runs before
    // CREATE because a failure here explains the repair failures above rather
    // than adding an independent one: every `FileAccess` consumer reads a short
    // return as end-of-file, so an unfilled buffer surfaces as phantom damage
    // in slice verification.
    let _ = writeln!(
        stdout,
        "---- FileAccess readback (must fill; host read cap is informational) ----"
    );
    let _ = stdout.flush();
    for case in IO_CASES {
        if !selected(&filter, case.label) {
            continue;
        }
        ran += 1;
        match run_io_case(&fixtures_root, &scratch_root, case) {
            Ok(detail) => {
                let _ = writeln!(stdout, "{:<32} | PASS | {detail}", case.label);
            }
            Err(e) => {
                failed += 1;
                let _ = writeln!(stdout, "{:<32} | FAIL | {e}", case.label);
            }
        }
        let _ = stdout.flush();
    }

    // CREATE: byte-identity gate. The digest must match across thread counts,
    // across wasm lanes, and against native.
    let _ = writeln!(
        stdout,
        "---- PAR2 create (digest must be identical across lanes/threads) ----"
    );
    // Piped stdout is block-buffered, and a WASI abort discards the buffer, so
    // an abort inside creation would otherwise erase the verify/repair results
    // printed above. Flush at every step boundary from here on.
    let _ = stdout.flush();
    for case in CREATE_CASES {
        if !selected(&filter, case.label) {
            continue;
        }
        ran += 1;
        match run_create(&fixtures_root, &scratch_root, case) {
            Ok(digest) => {
                let _ = writeln!(stdout, "{:<32} | PASS | digest={digest:016x}", case.label);
            }
            Err(e) => {
                failed += 1;
                let _ = writeln!(stdout, "{:<32} | FAIL | {e}", case.label);
            }
        }
        let _ = stdout.flush();
    }

    let _ = writeln!(
        stdout,
        "======================================================="
    );
    let _ = writeln!(stdout, "cases={ran} failed={failed}");
    // WASI aborts do not flush libc stdout; flush explicitly so the report is
    // never lost even if a later change reintroduces a panic mid-run.
    let _ = stdout.flush();

    if failed != 0 {
        std::process::exit(1);
    }
}

/// Timing mode: report min-of-N wall time per workload for this lane.
///
/// Absolute numbers on a shared machine are not trustworthy; ratios between
/// lanes measured in the same session are. Each phase is reported separately so
/// verify (hash/CRC-bound) and repair (GF-bound) can be told apart — they
/// respond very differently to SIMD.
fn run_bench(
    stdout: &mut io::Stdout,
    fixtures_root: &Path,
    scratch_root: &Path,
    filter: &Option<Vec<String>>,
) {
    let iters = bench_iters();
    let _ = writeln!(
        stdout,
        "==== PAR2 timing, min of {iters} (seconds; lower is better) ===="
    );
    let _ = writeln!(
        stdout,
        "{:<32} | {:>12} | {:>12}",
        "workload", "verify", "repair"
    );

    for case in CASES {
        if !selected(filter, case.label) {
            continue;
        }
        let src_dir = fixtures_root.join(case.dir);
        let work = scratch_root.join(case.work_dir("bench_"));
        let _ = fs::remove_dir_all(&work);
        if let Err(e) = copy_dir(&src_dir, &work) {
            let _ = writeln!(stdout, "{:<32} | copy failed: {e}", case.label);
            continue;
        }
        let par2_paths = collect_par2(&work, case.par2_prefix);
        let protected = work.join(case.protected);
        // Same stash policy as the PASS/FAIL run, so the reconstruction rows
        // time reconstruction rather than a relocating copy.
        let pristine = match case.reference_path(&work, scratch_root) {
            Ok(path) => path,
            Err(e) => {
                let _ = writeln!(stdout, "{:<32} | reference dir failed: {e}", case.label);
                continue;
            }
        };
        let _ = fs::copy(&protected, &pristine);

        // VERIFY on the healthy set.
        let verify = best_of(iters, || {
            run_repairer(&work, &par2_paths, false).map(|_| ())
        });

        // REPAIR: each iteration must start from the same damaged state, so the
        // file is re-damaged from the pristine copy before every timed run.
        let repair = best_of(iters, || {
            fs::copy(&pristine, &protected).map_err(|e| format!("restore: {e}"))?;
            for c in case.corruptions {
                corrupt(&protected, c.offset, c.len).map_err(|e| format!("corrupt: {e}"))?;
            }
            run_repairer(&work, &par2_paths, true).map(|_| ())
        });

        let cell = |r: &Result<Duration, String>| match r {
            Ok(d) => format!("{:.4}", d.as_secs_f64()),
            Err(e) => format!("ERR({})", &e[..e.len().min(18)]),
        };
        let _ = writeln!(
            stdout,
            "{:<32} | {:>12} | {:>12}",
            case.label,
            cell(&verify),
            cell(&repair)
        );
        let _ = stdout.flush();
    }

    let _ = writeln!(stdout, "{:<32} | {:>12}", "workload", "create");
    for case in CREATE_CASES {
        if !selected(filter, case.label) {
            continue;
        }
        let create = best_of(iters, || {
            run_create(fixtures_root, scratch_root, case).map(|_| ())
        });
        let cell = match &create {
            Ok(d) => format!("{:.4}", d.as_secs_f64()),
            Err(e) => format!("ERR({e})"),
        };
        let _ = writeln!(stdout, "{:<32} | {:>12}", case.label, cell);
        let _ = stdout.flush();
    }

    let _ = writeln!(
        stdout,
        "======================================================="
    );
    let _ = stdout.flush();
}
