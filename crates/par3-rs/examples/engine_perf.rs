//! Stage-level native benchmark driver, not a supported CLI.
//!
//! Arguments: OP DATA CARRIERS OUTPUT WORKERS MEMORY_MIB [CODEC BLOCK RECOVERY INTERLEAVE].
//! OP is create, scan, verify, reassess, repair, or placement. Inputs are explicitly
//! generated `.bin` files in DATA; carriers are `.par3` files in CARRIERS.
//! Timing excludes directory discovery. Each invocation is one fresh process.
//! PAR3_BENCH_CREATE_DURABILITY=buffered opts creation into buffered output;
//! the default is sync-files. The selected policy is recorded in metrics.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use par3_rs::ScanLimits;
use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::placement::{PlacementOptions, search_extent};
use par3_rs::runtime::{ExecutionOptions, IoSnapshot, MemoryBudget, Stage};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{DiskSourceAccess, SourceId};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == extension) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn metric(name: &str, started: Instant, before: IoSnapshot, options: &ExecutionOptions) {
    let after = options.diagnostics.source_io();
    println!(
        "{{\"stage\":\"{name}\",\"seconds\":{:.9},\"source_read_bytes\":{},\"source_read_calls\":{},\"reserved_peak\":{},\"handle_peak\":{}}}",
        started.elapsed().as_secs_f64(),
        after.read_bytes - before.read_bytes,
        after.read_calls - before.read_calls,
        options.memory.peak(),
        options.handles.peak(),
    );
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 6 {
        return Err(
            "expected OP DATA CARRIERS OUTPUT WORKERS MEMORY_MIB [CODEC BLOCK RECOVERY INTERLEAVE]"
                .into(),
        );
    }
    let operation = args[0].as_str();
    let data = Path::new(&args[1]);
    let carriers = Path::new(&args[2]);
    let output = Path::new(&args[3]);
    let mut options = ExecutionOptions::default();
    options.workers = args[4].parse()?;
    options.memory = MemoryBudget::new(args[5].parse::<usize>()? * (1 << 20));
    options.retained_bytes = options.retained_bytes.min(options.memory.limit() / 2);
    let mut access = DiskSourceAccess::with_options(options.clone());
    let mut sources = Vec::new();
    for (index, path) in files(data, "bin")?.into_iter().enumerate() {
        let id = SourceId(index as u64);
        sources.push(CreationSource {
            name: path
                .file_name()
                .ok_or("missing filename")?
                .to_str()
                .ok_or("non-UTF8 filename")?
                .to_owned(),
            source: id,
        });
        access.insert(id, path);
    }
    if sources.is_empty() {
        return Err("no benchmark inputs".into());
    }
    if operation == "create" {
        if args.len() != 10 {
            return Err("creation needs CODEC BLOCK RECOVERY INTERLEAVE".into());
        }
        let recovery_count: u64 = args[8].parse()?;
        let interleave: u64 = args[9].parse()?;
        let capacity = recovery_count.div_ceil(interleave + 1).next_power_of_two();
        let codec = match args[6].as_str() {
            "cauchy" => CreationCodec::Cauchy,
            "fft" => CreationCodec::Fft {
                capacity_log2: capacity.ilog2() as i8,
                interleave,
            },
            _ => return Err("unknown codec".into()),
        };
        let settings = CreationOptions {
            block_size: args[7].parse()?,
            recovery_count,
            codec,
            execution: options.clone(),
            ..CreationOptions::default()
        };
        let access = Arc::new(access);
        let before = options.diagnostics.source_io();
        let start = Instant::now();
        let plan = CreationPlan::build(access, &sources, settings)?;
        metric("plan", start, before, &options);
        let requirements = plan.requirements();
        println!(
            "{{\"blocks\":{},\"source_bytes\":{},\"scratch_bytes\":{},\"cohorts\":{},\"field\":\"{:?}\"}}",
            requirements.blocks,
            requirements.source_bytes,
            requirements.scratch_bytes,
            requirements.cohorts,
            requirements.field
        );
        let before = options.diagnostics.source_io();
        let start = Instant::now();
        let durability = match std::env::var("PAR3_BENCH_CREATE_DURABILITY").as_deref() {
            Ok("buffered") => par3_rs::creation::CreationDurability::Buffered,
            Err(std::env::VarError::NotPresent) | Ok("sync-files") => {
                par3_rs::creation::CreationDurability::SyncFiles
            }
            _ => return Err("invalid PAR3_BENCH_CREATE_DURABILITY".into()),
        };
        println!("{{\"creation_durability\":\"{durability:?}\"}}");
        let paths = plan.execute_with_durability(&carriers.join("set"), output, durability)?;
        metric("create", start, before, &options);
        println!("{{\"carriers\":{}}}", paths.len());
    } else {
        let paths = files(carriers, "par3")?;
        let mut carrier_ids = Vec::new();
        for (index, path) in paths.into_iter().enumerate() {
            let id = SourceId(sources.len() as u64 + index as u64);
            access.insert(id, path);
            carrier_ids.push(id);
        }
        let access = Arc::new(access);
        let before = options.diagnostics.source_io();
        let start = Instant::now();
        let mut session = None;
        let mut packets = 0;
        for id in carrier_ids {
            let mut scanner =
                PacketScanner::new(access.clone(), id, options.clone(), ScanLimits::default())?;
            loop {
                match scanner.poll()? {
                    ScanEvent::Packet(packet) => {
                        packets += 1;
                        if operation != "scan" {
                            if session.is_none() {
                                session = Some(Par3RepairSession::new(
                                    packet.input_set_id(),
                                    access.clone(),
                                    options.clone(),
                                )?);
                            }
                            session.as_mut().ok_or("missing session")?.merge(packet)?;
                        }
                    }
                    ScanEvent::End => break,
                    ScanEvent::NeedData { .. } => return Err("incomplete benchmark carrier".into()),
                }
            }
        }
        metric(
            if operation == "scan" {
                "scan"
            } else {
                "ingest"
            },
            start,
            before,
            &options,
        );
        println!("{{\"packets\":{packets}}}");
        if operation == "scan" {
            return Ok(());
        }
        let mut session = session.ok_or("no authenticated packets")?;
        for source in &sources {
            session.bind_file(&source.name, source.source)?;
        }
        if operation == "placement" {
            let layout = session.layout()?.ok_or("incomplete metadata")?;
            let before = options.diagnostics.source_io();
            let start = Instant::now();
            // Search the last full extent so the candidate scan traverses a file.
            let file = &layout.files()[0];
            let extent = file
                .extents
                .iter()
                .rposition(|e| e.range.end - e.range.start == layout.block_size())
                .ok_or("no full extent")?;
            let report = search_extent(
                &layout,
                0,
                extent,
                access.as_ref(),
                &[sources[0].source],
                &PlacementOptions::default(),
                &options,
            )?;
            metric("placement", start, before, &options);
            if report.matches.is_empty() {
                return Err("benchmark placement did not find the expected extent".into());
            }
            println!(
                "{{\"matches\":{},\"placement_read_bytes\":{}}}",
                report.matches.len(),
                report.read_bytes
            );
        } else {
            let before = options.diagnostics.source_io();
            let start = Instant::now();
            let assessment = session.assess()?;
            let status = assessment.status;
            let lost = assessment.lost_blocks.len();
            metric("assess", start, before, &options);
            println!("{{\"status\":\"{status:?}\",\"lost_blocks\":{}}}", lost);
            if operation == "reassess" {
                let before = options.diagnostics.source_io();
                let start = Instant::now();
                for _ in 0..100 {
                    session.assess()?;
                }
                metric("reassess_100", start, before, &options);
                if options.diagnostics.source_io().read_bytes != before.read_bytes {
                    return Err("unchanged reassessment reread sources".into());
                }
            }
            match operation {
                "verify" | "reassess" if status == RepairStatus::Complete => {}
                "repair" if status == RepairStatus::Ready => {
                    let before = options.diagnostics.source_io();
                    let start = Instant::now();
                    let report = session.repair(output, false)?;
                    metric("repair", start, before, &options);
                    println!(
                        "{{\"installed\":{},\"reconstructed_blocks\":{}}}",
                        report.installed.len(),
                        report.reconstructed_blocks
                    );
                }
                _ => return Err("unexpected operation or readiness".into()),
            }
        }
    }
    for stage in [
        Stage::Scan,
        Stage::Metadata,
        Stage::Verify,
        Stage::Assess,
        Stage::Placement,
        Stage::Create,
        Stage::Encode,
        Stage::Decode,
        Stage::Repair,
    ] {
        let snapshot = options.diagnostics.stage(stage);
        println!(
            "{{\"internal_stage\":\"{stage:?}\",\"seconds\":{:.9},\"calls\":{}}}",
            snapshot.elapsed.as_secs_f64(),
            snapshot.calls
        );
    }
    let sync = options.diagnostics.file_sync();
    println!(
        "{{\"internal_stage\":\"Sync\",\"seconds\":{:.9},\"calls\":{}}}",
        sync.elapsed.as_secs_f64(),
        sync.calls
    );
    let io = options.diagnostics.file_io();
    println!(
        "{{\"file_read_bytes\":{},\"file_write_bytes\":{},\"memory_limit\":{},\"workers\":{}}}",
        io.read_bytes,
        io.write_bytes,
        options.memory.limit(),
        options.workers
    );
    Ok(())
}
