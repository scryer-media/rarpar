//! Bench driver: run the full repairer pipeline (scan → verify → repair →
//! staged install → post-repair verify) the way the weaver server drives it.
//!
//! Usage:
//!   wpar2 [--verify-only] [--mem-mib N] <par2-file-or-dir> [base-dir]
//!
//! Timing and peak RSS are measured externally (e.g. `/usr/bin/time -v` or
//! the Windows `wtime` wrapper); this driver only does the work and prints
//! the outcome so harnesses can assert on it.

use std::path::PathBuf;
use std::process::ExitCode;

use weaver_par2::{Par2Repairer, Par2RepairerOptions};

fn main() -> ExitCode {
    let mut verify_only = false;
    let mut mem_mib: Option<usize> = None;
    let mut positional: Vec<PathBuf> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--verify-only" => verify_only = true,
            "--mem-mib" => {
                let value = args.next().expect("missing value after --mem-mib");
                mem_mib = Some(value.parse().expect("--mem-mib must be an integer"));
            }
            _ => positional.push(PathBuf::from(arg)),
        }
    }

    let Some(input) = positional.first().cloned() else {
        eprintln!("usage: wpar2 [--verify-only] [--mem-mib N] <par2-file-or-dir> [base-dir]");
        return ExitCode::from(2);
    };

    let par2_paths: Vec<PathBuf> = if input.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&input)
            .expect("read par2 dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("par2"))
            })
            .collect();
        paths.sort();
        paths
    } else {
        vec![input.clone()]
    };
    if par2_paths.is_empty() {
        eprintln!("no .par2 files found under {}", input.display());
        return ExitCode::from(2);
    }

    let base_dir = positional.get(1).cloned().unwrap_or_else(|| {
        if input.is_dir() {
            input.clone()
        } else {
            input
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        }
    });

    let mut options = Par2RepairerOptions::new(base_dir, par2_paths);
    options.repair = !verify_only;
    if let Some(mib) = mem_mib {
        options.memory_limit = Some(mib << 20);
    }

    // The production server drives repair from a worker thread it spawns, not
    // the process main thread. On Windows the main thread's default stack is
    // 1 MiB (vs 8 MiB on Linux), too small for the decode-matrix construction
    // on the many-slice single-file shape. Run on an explicitly-sized worker
    // so this driver measures the same code path the server does.
    let worker = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || Par2Repairer::new(options).verify_or_repair())
        .expect("spawn repair worker");
    let result = worker.join().expect("repair worker panicked");

    match result {
        Ok(outcome) => {
            println!(
                "status={:?} complete={} damaged={} missing_files={} missing_blocks={} recovery_used={} reconstructed_bytes={}",
                outcome.status,
                outcome.files_complete,
                outcome.files_damaged,
                outcome.files_missing,
                outcome.missing_blocks,
                outcome.recovery_blocks_used,
                outcome.bytes_reconstructed,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
