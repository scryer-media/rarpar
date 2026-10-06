//! What regenerating a recovery carrier costs on this host, measured.
//!
//! Builds (once, under Cargo's per-target temp directory) a 512 MiB single-file
//! Cauchy set with eight recovery rows in one carrier, then restores that
//! carrier with none of its recovery payloads available, so every row is
//! regenerated from the source on disk. It prints wall time, process CPU time
//! and the source reads `execute` issued. Nothing is asserted as a threshold —
//! a timing assertion on a shared machine is a flake — so the probe is
//! `#[ignore]`d and run deliberately, with a release build:
//!
//! ```sh
//! cargo test --locked --release -p par3-rs --test carrier_timing -- --ignored --nocapture
//! ```
//!
//! Every byte it measures comes from this crate's own creation engine. No PAR3
//! packet is assembled or edited here. Unix only, for `getrusage`.
#![cfg(unix)]

use par3_rs::carrier::{CarrierPlan, CarrierRestoration};
use par3_rs::ingest::{IngestedPacket, PacketScanner, ScanEvent};
use par3_rs::runtime::{ExecutionOptions, MemoryBudget};
use par3_rs::source::{DiskSourceAccess, MemorySourceAccess, SourceId};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SOURCE_BYTES: usize = 512 << 20;
const BLOCK_SIZE: u64 = 1 << 20;
const RECOVERY: u64 = 8;

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

fn scan(bytes: Vec<u8>, options: &ExecutionOptions) -> Vec<IngestedPacket> {
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(99), 1, bytes.into());
    let mut scanner = PacketScanner::new(
        Arc::new(source),
        SourceId(99),
        options.clone(),
        par3_rs::ScanLimits::default(),
    )
    .unwrap();
    let mut packets = Vec::new();
    loop {
        match scanner.poll().unwrap() {
            ScanEvent::Packet(packet) => packets.push(packet),
            ScanEvent::End => break,
            ScanEvent::NeedData { .. } => panic!("complete carrier"),
        }
    }
    packets
}

/// The input, index and carrier, built on the first run and reused after.
fn build(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    use par3_rs::creation::{
        CreationCodec, CreationOptions, CreationPlan, CreationSource, VolumeLayout,
    };
    let input = directory.join("input.bin");
    let index = directory.join("set.par3");
    let carrier = directory.join(format!("set.vol0+{RECOVERY}.par3"));
    if input.exists() && index.exists() && carrier.exists() {
        return (input, index, carrier);
    }
    std::fs::create_dir_all(directory).unwrap();
    let mut file = std::io::BufWriter::new(std::fs::File::create(&input).unwrap());
    let mut reader = blake3::Hasher::new()
        .update(b"PAR3 carrier timing probe")
        .finalize_xof();
    let mut chunk = vec![0; 8 << 20];
    for _ in 0..SOURCE_BYTES / chunk.len() {
        reader.fill(&mut chunk);
        file.write_all(&chunk).unwrap();
    }
    file.into_inner().unwrap().sync_all().unwrap();
    let mut options = CreationOptions {
        block_size: BLOCK_SIZE,
        recovery_count: RECOVERY,
        volumes: VolumeLayout::Uniform(RECOVERY),
        codec: CreationCodec::Cauchy,
        ..CreationOptions::default()
    };
    options.execution.memory = MemoryBudget::new(1 << 30);
    let mut access = DiskSourceAccess::with_options(options.execution.clone());
    access.insert(SourceId(1), input.clone());
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options,
    )
    .unwrap();
    let paths = plan
        .execute(&directory.join("set"), directory)
        .expect("a written set");
    assert_eq!(paths, [index.clone(), carrier.clone()]);
    (input, index, carrier)
}

struct Sample {
    wall: Duration,
    cpu: Duration,
    read_calls: u64,
    read_bytes: u64,
    workers: u64,
    tile: u64,
}

fn run(input: &Path, index: &[u8], carrier: &[u8], workers: usize, output: &Path) -> Sample {
    let mut options = ExecutionOptions::default();
    options.workers = workers;
    let packets = scan(carrier.to_vec(), &options);
    let plan = CarrierPlan::capture(&packets, &options).unwrap();
    let mut access = DiskSourceAccess::with_options(options.clone());
    access.insert(SourceId(1), input.to_owned());
    let mut session = par3_rs::Par3RepairSession::new(
        packets[0].input_set_id(),
        Arc::new(access),
        options.clone(),
    )
    .unwrap();
    session.bind_file("input.bin", SourceId(1)).unwrap();
    for packet in scan(index.to_vec(), &options) {
        session.merge(packet).unwrap();
    }
    session.assess().unwrap();
    let _ = std::fs::remove_dir_all(output);
    std::fs::create_dir_all(output).unwrap();
    let before = options.diagnostics.source_io();
    let wall = Instant::now();
    let cpu = cpu_time();
    let report = plan
        .execute(&mut session, &output.join("restored.par3"), output)
        .unwrap();
    let (wall, cpu) = (wall.elapsed(), cpu_time() - cpu);
    let after = options.diagnostics.source_io();
    assert_eq!(report.restoration, CarrierRestoration::Exact);
    assert_eq!(report.recovery_packets as u64, RECOVERY);
    let admission = options.diagnostics.admission();
    std::fs::remove_dir_all(output).unwrap();
    Sample {
        wall,
        cpu,
        read_calls: after.read_calls - before.read_calls,
        read_bytes: after.read_bytes - before.read_bytes,
        workers: admission.workers,
        tile: admission.output_tile,
    }
}

#[test]
#[ignore = "timing probe: builds a 512 MiB set and reports measured carrier regeneration"]
fn carrier_regeneration_timing_on_this_host() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("par3-carrier-timing");
    let (input, index, carrier) = build(&directory);
    let index = std::fs::read(index).unwrap();
    let carrier = std::fs::read(carrier).unwrap();
    let output = directory.join("out");
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!(
        "--- carrier regeneration: 512 MiB source, 1 MiB blocks, {RECOVERY} rows, {cores} cores ---"
    );
    println!(
        "{:<10} {:>4} {:>10} {:>10} {:>12} {:>14} {:>8} {:>5}",
        "workers", "run", "wall ms", "cpu ms", "read calls", "read bytes", "workers", "tile"
    );
    for workers in [1, cores] {
        // The first run warms the page cache and is not reported.
        run(&input, &index, &carrier, workers, &output);
        for attempt in 1..=3 {
            let sample = run(&input, &index, &carrier, workers, &output);
            println!(
                "{:<10} {:>4} {:>10.1} {:>10.1} {:>12} {:>14} {:>8} {:>5}",
                workers,
                attempt,
                sample.wall.as_secs_f64() * 1e3,
                sample.cpu.as_secs_f64() * 1e3,
                sample.read_calls,
                sample.read_bytes,
                sample.workers,
                sample.tile
            );
        }
    }
}
