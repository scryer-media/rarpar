//! `rarpar par3 inside`: PAR3 recovery embedded in RAR5 archives.

use std::path::{Path, PathBuf};

use par3_rs::creation::{CreationDurability, CreationOptions};
use par3_rs::inside::rar5::{self, Rar5Layout, Rar5Placement, Rar5Set};
use par3_rs::session::RepairStatus;
use rarpar::cli::{
    Cli, Par3InsideArgs, Par3InsideCommand, Par3InsideInsertArgs, Par3InsideLayout,
    Par3InsidePlacement, Par3InsideRemoveArgs, Par3InsideRepairArgs,
};
use serde_json::{Value, json};

use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};

pub fn run(cli: &Cli, command: Par3InsideCommand) -> Result<u8, RarparError> {
    let (success, report) = match command {
        Par3InsideCommand::Insert(args) => insert(cli, &args)?,
        Par3InsideCommand::Verify(args) => verify(cli, &args)?,
        Par3InsideCommand::Repair(args) => repair(cli, &args)?,
        Par3InsideCommand::Remove(args) => remove(cli, &args)?,
    };
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !cli.quiet {
        print_human(&report);
    }
    Ok(if success {
        EXIT_SUCCESS
    } else {
        EXIT_DATA_FAILURE
    })
}

fn print_human(report: &Value) {
    println!(
        "{}: {}",
        report["operation"].as_str().unwrap_or("par3_inside"),
        report["status"].as_str().unwrap_or("")
    );
    for set in report["sets"].as_array().into_iter().flatten() {
        println!(
            "  set {} ({} layout): {}",
            set["set_id"].as_str().unwrap_or(""),
            set["layout"].as_str().unwrap_or(""),
            set["status"].as_str().unwrap_or("")
        );
        for host in set["hosts"].as_array().into_iter().flatten() {
            println!(
                "    {}: data {}, region {} ({}/{} packets){}",
                host["name"].as_str().unwrap_or(""),
                if host["complete"] == true {
                    "verified"
                } else {
                    "damaged or missing"
                },
                if host["region_intact"] == true {
                    "intact"
                } else {
                    "damaged or missing"
                },
                host["packets_found"],
                host["packets_expected"],
                host["path"]
                    .as_str()
                    .map(|path| format!(" at {path}"))
                    .unwrap_or_default()
            );
        }
        if set["additional"].as_u64().unwrap_or(0) != 0 {
            println!("    {} more recovery block(s) needed", set["additional"]);
        }
    }
    for output in report["outputs"].as_array().into_iter().flatten() {
        if let Some(path) = output.as_str() {
            println!("  wrote {path}");
        } else {
            println!("  wrote {}", output["path"].as_str().unwrap_or(""));
        }
    }
}

/// The given archives, widened to every `stem.partN.rar` volume next to a
/// single given volume.
fn volume_set(paths: &[PathBuf]) -> Result<Vec<PathBuf>, RarparError> {
    for path in paths {
        if !path.is_file() {
            return Err(RarparError::MissingInput(path.clone()));
        }
    }
    if paths.len() != 1 {
        return Ok(paths.to_vec());
    }
    let path = &paths[0];
    let Some((stem, _)) = part_number(path) else {
        return Ok(paths.to_vec());
    };
    let directory = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut volumes: Vec<(u64, PathBuf)> = std::fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter_map(|candidate| {
            let (candidate_stem, number) = part_number(&candidate)?;
            (candidate_stem == stem).then_some((number, candidate))
        })
        .collect();
    volumes.sort();
    for (expected, (number, _)) in volumes.iter().enumerate() {
        if *number != expected as u64 + 1 {
            return Err(RarparError::Data(format!(
                "volume {} of {stem} is missing",
                expected + 1
            )));
        }
    }
    Ok(volumes.into_iter().map(|(_, path)| path).collect())
}

/// `(stem, N)` for `stem.partN.rar`.
fn part_number(path: &Path) -> Option<(String, u64)> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let body = lower.strip_suffix(".rar")?;
    let at = body.rfind(".part")?;
    let digits = &body[at + 5..];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((name[..at].to_owned(), digits.parse().ok()?))
}

fn layout(value: Par3InsideLayout) -> Rar5Layout {
    match value {
        Par3InsideLayout::Trailing => Rar5Layout::Trailing,
        Par3InsideLayout::Block => Rar5Layout::Block,
        Par3InsideLayout::Service => Rar5Layout::Service,
    }
}

fn layout_name(value: Rar5Layout) -> &'static str {
    match value {
        Rar5Layout::Trailing => "trailing",
        Rar5Layout::Block => "block",
        Rar5Layout::Service => "service",
    }
}

fn status_name(status: RepairStatus) -> &'static str {
    match status {
        RepairStatus::Complete => "complete",
        RepairStatus::Ready => "repairable",
        RepairStatus::NeedRecovery => "not repairable: more recovery needed",
        RepairStatus::IncompleteMetadata => "not repairable: metadata incomplete",
        RepairStatus::Unsupported => "not repairable: unsupported",
    }
}

fn insert(cli: &Cli, args: &Par3InsideInsertArgs) -> Result<(bool, Value), RarparError> {
    let execution = crate::par3::execution_options(
        cli.par3_memory_mib,
        cli.par3_workers,
        cli.par3_max_lost_blocks,
    )?;
    let paths = volume_set(&args.archives)?;
    let region_layout = layout(args.layout);
    let hosts = rar5::prepare_hosts(&paths, region_layout, &execution)?;
    let total: u64 = hosts.iter().map(|host| host.archive.length).sum();
    let block_size = args.block_size.unwrap_or_else(|| {
        let mut size = 4096u64;
        while total.div_ceil(size) > 32768 {
            size *= 2;
        }
        size
    });
    let blocks_of = |length: u64| length.div_ceil(block_size) + 1;
    let count_for = |blocks: u64| -> u64 {
        args.recovery_count.unwrap_or_else(|| {
            (blocks * u64::from(args.recovery_percent.unwrap_or(5)))
                .div_ceil(100)
                .max(1)
        })
    };
    let placement = match args.placement {
        Par3InsidePlacement::Spread => Rar5Placement::Spread,
        Par3InsidePlacement::Last => Rar5Placement::Last,
        Par3InsidePlacement::Independent => Rar5Placement::Independent,
    };
    let (output_dir, staging) = if args.in_place {
        let directory = paths[0]
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let stage = tempfile::tempdir_in(&directory)?;
        (stage.path().to_owned(), Some(stage))
    } else {
        let directory = args.output_dir.clone().expect("required by clap");
        std::fs::create_dir_all(&directory)?;
        (directory, None)
    };
    let outputs: Vec<PathBuf> = hosts
        .iter()
        .map(|host| output_dir.join(&host.name))
        .collect();
    for output in &outputs {
        if output.exists() {
            return Err(RarparError::Unsafe(format!(
                "output exists: {}",
                output.display()
            )));
        }
    }
    let scratch_holder;
    let scratch = match &args.scratch_dir {
        Some(dir) => dir.clone(),
        None => {
            scratch_holder = tempfile::tempdir_in(&output_dir)?;
            scratch_holder.path().to_owned()
        }
    };
    let durability = if args.buffered {
        CreationDurability::Buffered
    } else {
        CreationDurability::SyncFiles
    };
    let creation = |count: u64| CreationOptions {
        execution: execution.clone(),
        block_size,
        recovery_count: count,
        ..CreationOptions::default()
    };
    let mut inserted = Vec::new();
    if cli.dry_run {
        return Ok((
            true,
            json!({"operation":"par3_inside_insert","status":"planned","dry_run":true,"hosts":hosts.iter().map(|h| &h.name).collect::<Vec<_>>(),"block_size":block_size}),
        ));
    }
    if placement == Rar5Placement::Independent {
        for (host, output) in hosts.iter().zip(&outputs) {
            let count = count_for(blocks_of(host.archive.length));
            inserted.extend(rar5::insert_set(
                std::slice::from_ref(host),
                std::slice::from_ref(output),
                &[count],
                region_layout,
                creation(count),
                &scratch,
                durability,
            )?);
        }
    } else {
        let count = count_for(
            hosts
                .iter()
                .map(|host| blocks_of(host.archive.length))
                .sum(),
        );
        let counts = rar5::placement_counts(placement, hosts.len(), count);
        inserted = rar5::insert_set(
            &hosts,
            &outputs,
            &counts,
            region_layout,
            creation(count),
            &scratch,
            durability,
        )?;
    }
    let mut written = Vec::new();
    for (entry, path) in inserted.iter().zip(&paths) {
        let destination = if args.in_place {
            std::fs::rename(&entry.path, path)?;
            path.clone()
        } else {
            entry.path.clone()
        };
        written.push(json!({"path":destination,"region_bytes":entry.region_bytes,"recovery_packets":entry.recovery_packets,"set_id":entry.set.to_string()}));
    }
    drop(staging);
    Ok((
        true,
        json!({"operation":"par3_inside_insert","status":"inserted","block_size":block_size,"layout":layout_name(region_layout),"outputs":written}),
    ))
}

fn set_report(set: &Rar5Set) -> Value {
    json!({
        "set_id": set.id.to_string(),
        "layout": layout_name(set.layout),
        "status": status_name(set.status),
        "lost_blocks": set.lost_blocks,
        "additional": set.additional,
        "recovery_available": set.recovery_available,
        "hosts": set.hosts.iter().map(|host| json!({
            "name": host.name,
            "path": host.path,
            "matched_by": host.matched_by,
            "complete": host.complete,
            "region_intact": host.region_intact,
            "packets_found": host.packets_found,
            "packets_expected": host.packets_expected,
            "recovery_indices": [host.recovery.start, host.recovery.end],
            "region": [host.gap.start, host.gap.end],
            "damaged_ranges": host.unresolved.iter().map(|range| [range.start, range.end]).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn open(cli: &Cli, args: &Par3InsideArgs) -> Result<Vec<Rar5Set>, RarparError> {
    let execution = crate::par3::execution_options(
        cli.par3_memory_mib,
        cli.par3_workers,
        cli.par3_max_lost_blocks,
    )?;
    for path in &args.archives {
        if !path.is_file() {
            return Err(RarparError::MissingInput(path.clone()));
        }
    }
    Ok(rar5::open(&args.archives, &execution)?)
}

fn verify(cli: &Cli, args: &Par3InsideArgs) -> Result<(bool, Value), RarparError> {
    let sets = open(cli, args)?;
    let healthy = sets.iter().all(|set| set.needs_repair().is_empty());
    let repairable = sets
        .iter()
        .all(|set| matches!(set.status, RepairStatus::Complete | RepairStatus::Ready));
    let status = if healthy {
        "all data and regions intact"
    } else if repairable {
        "damage found; repairable"
    } else {
        "damage found; not repairable"
    };
    Ok((
        healthy,
        json!({"operation":"par3_inside_verify","status":status,"repairable":repairable,"sets":sets.iter().map(set_report).collect::<Vec<_>>()}),
    ))
}

fn repair(cli: &Cli, args: &Par3InsideRepairArgs) -> Result<(bool, Value), RarparError> {
    let mut sets = open(cli, &args.inputs)?;
    let home = args.inputs.archives[0]
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_owned();
    let mut outputs = Vec::new();
    let mut success = true;
    for set in &mut sets {
        let needed = set.needs_repair();
        if needed.is_empty() {
            continue;
        }
        if !matches!(set.status, RepairStatus::Complete | RepairStatus::Ready) {
            success = false;
            continue;
        }
        if cli.dry_run {
            continue;
        }
        let names = set.current_names();
        let finals: Vec<PathBuf> = set
            .hosts
            .iter()
            .zip(&names)
            .map(|(host, name)| match (&args.output_dir, &host.path) {
                (Some(dir), _) => dir.join(name),
                (None, Some(path)) => path.clone(),
                (None, None) => home.join(name),
            })
            .collect();
        let target_dir = args.output_dir.clone().unwrap_or_else(|| home.clone());
        std::fs::create_dir_all(&target_dir)?;
        let stage = tempfile::tempdir_in(&target_dir)?;
        let scratch = args
            .scratch_dir
            .clone()
            .unwrap_or_else(|| stage.path().to_owned());
        let staged: Vec<PathBuf> = names.iter().map(|name| stage.path().join(name)).collect();
        for (index, path) in finals.iter().enumerate() {
            if needed.contains(&index) && args.output_dir.is_some() && path.exists() {
                return Err(RarparError::Unsafe(format!(
                    "output exists: {}",
                    path.display()
                )));
            }
        }
        let report = set.repair(&staged, &scratch)?;
        for (entry, index) in report.iter().zip(&needed) {
            let destination = &finals[*index];
            if args.output_dir.is_none() && destination.exists() && !args.no_backup {
                let backup = numbered_backup(destination);
                std::fs::rename(destination, &backup)?;
            }
            std::fs::rename(&entry.path, destination)?;
            outputs.push(json!({"path":destination,"data_rebuilt":entry.data_rebuilt,"regenerated_packets":entry.regenerated,"restoration":format!("{:?}", entry.restoration)}));
        }
    }
    let status = if !success {
        "some damage is not repairable"
    } else if outputs.is_empty() && !cli.dry_run {
        "nothing to repair"
    } else {
        "repaired"
    };
    Ok((
        success,
        json!({"operation":"par3_inside_repair","status":status,"sets":sets.iter().map(set_report).collect::<Vec<_>>(),"outputs":outputs}),
    ))
}

fn numbered_backup(path: &Path) -> PathBuf {
    (1..)
        .map(|number| {
            let mut name = path.file_name().unwrap_or_default().to_owned();
            name.push(format!(".{number}"));
            path.with_file_name(name)
        })
        .find(|candidate| !candidate.exists())
        .expect("an unused backup name")
}

fn remove(cli: &Cli, args: &Par3InsideRemoveArgs) -> Result<(bool, Value), RarparError> {
    let mut sets = open(cli, &args.inputs)?;
    let mut outputs = Vec::new();
    for set in &mut sets {
        if cli.dry_run {
            continue;
        }
        let names = set.current_names();
        let (directory, stage) = if args.in_place {
            let home = set.hosts[0]
                .path
                .as_deref()
                .and_then(Path::parent)
                .unwrap_or(Path::new("."))
                .to_owned();
            let stage = tempfile::tempdir_in(&home)?;
            (stage.path().to_owned(), Some(stage))
        } else {
            let directory = args.output_dir.clone().expect("required by clap");
            std::fs::create_dir_all(&directory)?;
            (directory, None)
        };
        let destinations: Vec<PathBuf> = names.iter().map(|name| directory.join(name)).collect();
        let written = set.remove(&destinations)?;
        for (path, host) in written.iter().zip(&set.hosts) {
            let destination = if args.in_place {
                let original = host.path.clone().expect("bound host");
                std::fs::rename(path, &original)?;
                original
            } else {
                path.clone()
            };
            outputs.push(json!(destination));
        }
        drop(stage);
    }
    Ok((
        true,
        json!({"operation":"par3_inside_remove","status":"removed","outputs":outputs}),
    ))
}
