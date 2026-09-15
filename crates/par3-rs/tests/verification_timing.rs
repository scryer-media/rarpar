//! What intra-file parallel hashing is worth on this host, measured.
//!
//! The gates in `hash.rs` and `evidence.rs` are admission rules, not a promise
//! of speed. This probe is how the numbers behind them were obtained and how
//! they are re-obtained on another machine: it builds synthetic sets in a temp
//! directory, verifies them serially and with an admitted pool, and prints wall
//! time, process CPU time and throughput for each. Nothing here is asserted as
//! a threshold — a timing assertion on a shared machine is a flake — so the
//! probe is `#[ignore]`d and run deliberately:
//!
//! ```sh
//! cargo test --locked -p par3-rs --test verification_timing -- --ignored --nocapture
//! ```
//!
//! Every byte it measures comes from this crate's own creation engine. No PAR3
//! packet is assembled or edited here.
mod common;

use common::TempTree;
use par3_rs::layout::BlockLayout;
use par3_rs::runtime::{ExecutionOptions, MemoryBudget};
use par3_rs::source::{DiskSourceAccess, SourceId};
use par3_rs::{InputSetId, Par3Set, scan_packets_from_path};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Process CPU time (user + system), the only honest denominator for "did the
/// extra workers do useful work or just spin".
fn cpu_time() -> Duration {
    // SAFETY: `getrusage` writes a plain-old-data struct we own and zeroed.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(ok, 0, "getrusage");
    let total = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
    };
    total(usage.ru_utime) + total(usage.ru_stime)
}

struct Geometry {
    label: &'static str,
    files: usize,
    bytes_per_file: usize,
}

struct Built {
    set: Par3Set,
    /// Input path by protected name, so sources are bound the way a host binds
    /// them rather than by an index that assumes the set's file order.
    sources: BTreeMap<String, PathBuf>,
    bytes: u64,
    #[allow(dead_code)]
    id: InputSetId,
    #[allow(dead_code)]
    tree: TempTree,
}

/// Build one synthetic set on disk: `files` inputs of `bytes_per_file` bytes
/// each, 64 KiB blocks (the corpus's own large-file geometry), one recovery
/// block. The recovery amount is deliberately minimal: this probe measures
/// verification, and encoding more would only lengthen its setup.
fn build(geometry: &Geometry) -> Built {
    use par3_rs::creation::{
        CreationCodec, CreationOptions, CreationPlan, CreationSource, VolumeLayout,
    };
    use par3_rs::source::MemorySourceAccess;

    let tree = TempTree::new("verification-timing");
    let mut access = MemorySourceAccess::default();
    let mut sources = BTreeMap::new();
    let mut inputs = Vec::new();
    for index in 0..geometry.files {
        let mut bytes = vec![0; geometry.bytes_per_file];
        let mut hash = blake3::Hasher::new();
        hash.update(b"PAR3 verification timing probe");
        hash.update(&(index as u64).to_le_bytes());
        hash.finalize_xof().fill(&mut bytes);
        let name = format!("input{index}.bin");
        sources.insert(name.clone(), tree.write(&format!("in/{name}"), &bytes));
        access.insert(SourceId(index as u64 + 1), 1, bytes.into());
        inputs.push(CreationSource {
            name,
            source: SourceId(index as u64 + 1),
        });
    }
    let mut options = CreationOptions {
        block_size: 64 << 10,
        recovery_count: 1,
        volumes: VolumeLayout::Uniform(1),
        codec: CreationCodec::Fft {
            capacity_log2: 0,
            interleave: 0,
        },
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.memory = MemoryBudget::new(1 << 30);
    options.execution.retained_bytes = 512 << 20;
    let plan = CreationPlan::build(Arc::new(access), &inputs, options).unwrap();
    let id = plan.input_set_id();
    let written = plan
        .execute(&tree.path().join("set"), tree.path())
        .expect("a written set");

    let mut packets = Vec::new();
    for path in &written {
        packets.extend(
            scan_packets_from_path(path)
                .expect("scanned")
                .into_iter()
                .map(|(_, packet)| packet),
        );
    }
    let set = Par3Set::from_packets(packets)
        .expect("a set")
        .pop()
        .expect("one set");
    Built {
        set,
        sources,
        bytes: (geometry.files * geometry.bytes_per_file) as u64,
        id,
        tree,
    }
}

/// Verify every file of `built` once, returning wall and CPU time. `sessions`
/// verifications run concurrently against one shared budget.
fn run(built: &Built, workers: usize, budget: usize, sessions: usize) -> (Duration, Duration) {
    let memory = MemoryBudget::new(budget);
    let wall = Instant::now();
    let cpu = cpu_time();
    std::thread::scope(|scope| {
        for session in 0..sessions {
            // Cloning shares the ledger, so concurrent sessions contend for one
            // ceiling exactly as two hosts sharing a budget would.
            let memory = memory.clone();
            scope.spawn(move || {
                let mut options = ExecutionOptions::default();
                options.workers = workers;
                options.memory = memory;
                let layout = Arc::new(BlockLayout::new(&built.set, &options).expect("a layout"));
                let mut access = DiskSourceAccess::with_options(options.clone());
                for (index, file) in layout.files().iter().enumerate() {
                    let path = built.sources.get(&file.path).expect("a bound input");
                    access.insert(SourceId(index as u64 + 1), path.clone());
                }
                for index in 0..layout.files().len() {
                    let proof = par3_rs::evidence::verify_source(
                        Arc::clone(&layout),
                        index,
                        &access,
                        SourceId(index as u64 + 1),
                        &options,
                    )
                    .unwrap_or_else(|error| panic!("session {session} file {index}: {error}"));
                    assert!(proof.protected_complete());
                }
            });
        }
    });
    assert_eq!(memory.used(), 0);
    (wall.elapsed(), cpu_time() - cpu)
}

#[test]
#[ignore = "timing probe: builds 64 MiB and 512 MiB sets and reports measured times"]
fn parallel_verification_timing_on_this_host() {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!(
        "--- verification timing: {} cores, blake3 rayon, 64 KiB blocks ---",
        cores
    );
    println!(
        "a parallel row configures every core; the hash pool itself is capped at \
         four (hash::PARALLEL_HASH_WORKERS)"
    );
    println!(
        "{:<40} {:>7} {:>10} {:>10} {:>10} {:>8}",
        "case", "cfg thr", "wall ms", "cpu ms", "MiB/s", "vs base"
    );

    for geometry in [
        Geometry {
            label: "64 MiB, 1 file",
            files: 1,
            bytes_per_file: 64 << 20,
        },
        Geometry {
            label: "64 MiB, 64 files",
            files: 64,
            bytes_per_file: 1 << 20,
        },
        Geometry {
            label: "512 MiB, 1 file",
            files: 1,
            bytes_per_file: 512 << 20,
        },
        Geometry {
            label: "512 MiB, 64 files",
            files: 64,
            bytes_per_file: 8 << 20,
        },
    ] {
        let built = build(&geometry);
        let mib = built.bytes as f64 / (1 << 20) as f64;
        let mut baseline: Option<f64> = None;
        // `workers` is what a host would configure; `verify_source` caps the
        // width it actually forks across at `PARALLEL_HASH_WORKERS`, so the
        // parallel rows measure the shipped gates, not an unbounded pool.
        for (label, workers, sessions) in [
            ("serial", 1, 1),
            ("parallel", cores, 1),
            ("serial, 2 sessions", 1, 2),
            ("parallel, 2 sessions", cores, 2),
        ] {
            // The first run warms the page cache; only the second is reported.
            run(&built, workers, 256 << 20, sessions);
            let (wall, cpu) = run(&built, workers, 256 << 20, sessions);
            let seconds = wall.as_secs_f64();
            if workers == 1 {
                baseline = Some(seconds);
            }
            let speedup = match (workers, baseline) {
                (1, _) => "1.00x".to_owned(),
                (_, Some(base)) => format!("{:.2}x", base / seconds),
                (_, None) => "-".to_owned(),
            };
            println!(
                "{:<40} {:>7} {:>10.1} {:>10.1} {:>10.1} {:>8}",
                format!("{}: {}", geometry.label, label),
                workers,
                seconds * 1e3,
                cpu.as_secs_f64() * 1e3,
                mib * sessions as f64 / seconds,
                speedup
            );
        }
    }
}
