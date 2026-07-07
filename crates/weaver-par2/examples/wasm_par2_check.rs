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
//!      i.e. the reconstruction produced the correct bytes, not merely "no
//!      error". (The protected payload here is the RAR volume the PAR2 set
//!      covers; comparing it byte-for-byte is a strict content check that does
//!      not need a RAR decoder in the guest.)
//!
//! Every fixture is copied out of the read-only `/fixtures` preopen into a
//! writable `/scratch` preopen first, because repair rewrites files in place.
//!
//! Build (wasm):
//!   cargo build --release -p weaver-par2 --no-default-features \
//!     --target wasm32-wasip1 --example wasm_par2_check
//!
//! Run (wasmtime 46; host::guest preopens):
//!   wasmtime run \
//!     --dir crates/weaver-par2/tests/fixtures::/fixtures \
//!     --dir <writable-scratch>::/scratch \
//!     target/wasm32-wasip1/release/examples/wasm_par2_check.wasm /fixtures /scratch
//!
//! Also runs natively for parity debugging:
//!   cargo run --release -p weaver-par2 --example wasm_par2_check -- \
//!     crates/weaver-par2/tests/fixtures <scratch>

use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use weaver_par2::{Par2RepairStatus, Par2Repairer, Par2RepairerOptions};

/// One corruption site inside a protected file.
#[derive(Clone, Copy)]
struct Corruption {
    /// Byte offset into the protected file.
    offset: u64,
    /// Number of bytes to overwrite with a fixed non-matching pattern.
    len: usize,
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

fn run_repairer(
    base: &Path,
    par2_paths: &[PathBuf],
    repair: bool,
) -> weaver_par2::Par2RepairOutcome {
    let mut options = Par2RepairerOptions::new(base.to_path_buf(), par2_paths.to_vec());
    options.repair = repair;
    options.memory_limit = Some(256 * 1024 * 1024);
    Par2Repairer::new(options)
        .verify_or_repair()
        .expect("run par2 repairer")
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
}

fn run_case(fixtures_root: &Path, scratch_root: &Path, case: &Case) -> CaseReport {
    let src_dir = fixtures_root.join(case.dir);
    let work = scratch_root.join(case.dir);
    let _ = fs::remove_dir_all(&work);

    let mut report = CaseReport {
        verify_healthy: Ok(()),
        verify_damaged: Ok(()),
        repair: Ok(()),
        healthy_status: "-".to_string(),
        damaged_status: "-".to_string(),
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

    // Stash a pristine copy of the protected file for the post-repair byte check.
    let pristine = work.join(format!("{}.pristine", case.protected));
    if let Err(e) = fs::copy(&protected, &pristine) {
        report.repair = Err(format!("stash pristine {}: {e}", protected.display()));
    }

    // (1) VERIFY healthy: undamaged set must be Verified with no missing blocks.
    {
        let outcome = run_repairer(&work, &par2_paths, false);
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
    {
        let outcome = run_repairer(&work, &par2_paths, false);
        report.damaged_status = format!("{:?}", outcome.status);
        let detected_damage = outcome.status != Par2RepairStatus::Verified;
        if !detected_damage {
            report.verify_damaged = Err(format!(
                "damage not detected: status={:?} (damaged_files={}, missing_files={}, missing_blocks={})",
                outcome.status,
                outcome.files_damaged,
                outcome.files_missing,
                outcome.verification.total_missing_blocks
            ));
        }
    }

    // (3) REPAIR: repair in place, then require Repaired + byte-identical output.
    if report.repair.is_ok() {
        let outcome = run_repairer(&work, &par2_paths, true);
        if outcome.status != Par2RepairStatus::Repaired {
            report.repair = Err(format!(
                "expected Repaired, got {:?} (missing_blocks={})",
                outcome.status, outcome.verification.total_missing_blocks
            ));
        } else {
            match (fs::read(&protected), fs::read(&pristine)) {
                (Ok(repaired), Ok(original)) => {
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
    for case in CASES {
        let r = run_case(&fixtures_root, &scratch_root, case);
        let cell = |res: &Result<(), String>| match res {
            Ok(()) => "PASS".to_string(),
            Err(e) => format!("FAIL: {e}"),
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

    let _ = writeln!(
        stdout,
        "======================================================="
    );
    let _ = writeln!(stdout, "cases={} failed={}", CASES.len(), failed);
    // WASI aborts do not flush libc stdout; flush explicitly so the report is
    // never lost even if a later change reintroduces a panic mid-run.
    let _ = stdout.flush();

    if failed != 0 {
        std::process::exit(1);
    }
}
