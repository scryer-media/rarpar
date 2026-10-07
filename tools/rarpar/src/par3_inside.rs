//! `rarpar par3 inside`: PAR3 recovery embedded in RAR5 archives.

use std::collections::HashSet;
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

/// Printed on stderr by every `par3 inside` run unless `--quiet`.
const EXPERIMENTAL_NOTICE: &str = "rarpar: par3 inside is EXPERIMENTAL: the on-disk layout may change before it is stable, and output from this version may not verify with a later one";

pub fn run(cli: &Cli, command: Par3InsideCommand) -> Result<u8, RarparError> {
    if !cli.quiet {
        eprintln!("{EXPERIMENTAL_NOTICE}");
    }
    let (success, mut report) = match command {
        Par3InsideCommand::Insert(args) => insert(cli, &args)?,
        Par3InsideCommand::Verify(args) => verify(cli, &args)?,
        Par3InsideCommand::Repair(args) => repair(cli, &args)?,
        Par3InsideCommand::Remove(args) => remove(cli, &args)?,
    };
    if let Some(fields) = report.as_object_mut() {
        fields.insert("experimental".to_owned(), Value::Bool(true));
    }
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
    for name in report["unprotected_missing_volumes"]
        .as_array()
        .into_iter()
        .flatten()
    {
        println!(
            "  {} is missing and no embedded set covers it",
            name.as_str().unwrap_or("")
        );
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
            same_stem(&candidate_stem, &stem).then_some((number, candidate))
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

/// A file name or volume family stem as the platform's file names compare:
/// exactly, and on Windows and macOS, whose default volumes ignore case,
/// under simple case folding, so there `set.part1.rar` and `SET.part2.rar`
/// are one family. Each character folds to its one-character uppercase, as
/// NTFS's upcase table does; one with a longer uppercase (`ß`) stays itself.
/// A case-sensitive volume on either platform is rare enough that two
/// families differing only by case are treated as one there too.
fn name_key(stem: &str) -> String {
    if !cfg!(any(windows, target_os = "macos")) {
        return stem.to_owned();
    }
    stem.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        })
        .collect()
}

/// Whether two `.partN.rar` stems name one family, by [`name_key`].
fn same_stem(a: &str, b: &str) -> bool {
    a == b || name_key(a) == name_key(b)
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
        while total.div_ceil(size) > 2048 {
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
    // In place, each output is staged in its own volume's directory, so the
    // final rename never crosses a filesystem.
    let mut staging = Vec::new();
    let outputs: Vec<PathBuf> = if args.in_place {
        let stages = stage_directories(&paths, &mut staging)?;
        hosts
            .iter()
            .zip(&stages)
            .map(|(host, stage)| stage.join(&host.name))
            .collect()
    } else {
        let directory = args.output_dir.clone().expect("required by clap");
        std::fs::create_dir_all(&directory)?;
        hosts
            .iter()
            .map(|host| directory.join(&host.name))
            .collect()
    };
    let output_dir = outputs[0].parent().expect("joined").to_owned();
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
        let counts = rar5::placement_counts(placement, hosts.len(), count)?;
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

/// The names a set's hosts are written under, each refused unless it is one
/// safe path component: a recorded name comes from the set's own packets, so
/// an absolute one or one with `..` would leave the chosen directory.
fn host_names(set: &Rar5Set) -> Result<Vec<String>, RarparError> {
    let names = set.current_names();
    for name in &names {
        check_host_name(name)?;
    }
    Ok(names)
}

fn check_host_name(name: &str) -> Result<(), RarparError> {
    rar5::validate_host_name(name)
        .map_err(|error| RarparError::Unsafe(format!("recorded host name {name:?}: {error}")))
}

/// The directory `path` is in.
fn directory_of(path: &Path) -> PathBuf {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_owned()
}

/// A staging directory beside each of `paths`, one per distinct directory,
/// kept alive in `holders`; the result lists each path's own.
fn stage_directories(
    paths: &[PathBuf],
    holders: &mut Vec<(PathBuf, tempfile::TempDir)>,
) -> Result<Vec<PathBuf>, RarparError> {
    paths
        .iter()
        .map(|path| {
            let directory = directory_of(path);
            if let Some((_, stage)) = holders.iter().find(|(dir, _)| *dir == directory) {
                return Ok(stage.path().to_owned());
            }
            let stage = tempfile::tempdir_in(&directory)?;
            let staged = stage.path().to_owned();
            holders.push((directory, stage));
            Ok(staged)
        })
        .collect()
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
    // Every present volume of a given `.partN.rar` set, so sets embedded per
    // volume are all opened. Each family's directory is listed once however
    // many of its volumes are named.
    let mut paths = args.archives.clone();
    let mut listed: HashSet<PathBuf> = paths.iter().cloned().collect();
    let mut families: HashSet<(PathBuf, String)> = HashSet::new();
    for path in &args.archives {
        let Some((stem, _)) = part_number(path) else {
            continue;
        };
        let directory = directory_of(path);
        if !families.insert((directory.clone(), name_key(&stem))) {
            continue;
        }
        // The directory's own spelling is opened: on Windows a family named
        // in another case is still listed whole.
        let mut siblings: Vec<PathBuf> = std::fs::read_dir(&directory)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|candidate| {
                part_number(candidate).is_some_and(|(found, _)| same_stem(&found, &stem))
            })
            .filter(|candidate| !listed.contains(candidate))
            .collect();
        siblings.sort();
        listed.extend(siblings.iter().cloned());
        paths.extend(siblings);
    }
    Ok(rar5::open(&paths, &execution)?)
}

/// Volumes of the given archives' `.partN.rar` sets that are absent and that
/// no opened set records: a numbering gap, or a missing successor of the
/// highest volume present when its end header says another follows.
///
/// A volume number comes from a file name, which may be renamed to any
/// suffix, so numbers are enumerated only up to a bound the inputs justify:
/// the volumes present and the hosts the opened sets record, plus one. Some
/// number at or under that bound is then always absent, so a family whose
/// suffixes run past it still reports a missing volume and is never healthy.
fn uncovered_volumes(cli: &Cli, args: &Par3InsideArgs, sets: &[Rar5Set]) -> Vec<String> {
    // A set covers its recorded names in the directories its found hosts are
    // in: a same-named volume elsewhere is another family's.
    let mut covered: HashSet<(PathBuf, String)> = HashSet::new();
    for set in sets {
        let names = set.current_names();
        let directories: HashSet<PathBuf> = set
            .hosts
            .iter()
            .filter_map(|host| host.path.as_deref())
            .map(directory_of)
            .collect();
        for directory in directories {
            covered.extend(names.iter().map(|name| (directory.clone(), name_key(name))));
        }
    }
    let recorded: usize = sets.iter().map(|set| set.hosts.len()).sum();
    let mut missing = Vec::new();
    let mut reported: HashSet<String> = HashSet::new();
    let mut families: HashSet<(PathBuf, String)> = HashSet::new();
    for path in &args.archives {
        let Some((stem, _)) = part_number(path) else {
            continue;
        };
        let directory = directory_of(path);
        if !families.insert((directory.clone(), name_key(&stem))) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        let mut present: Vec<(u64, PathBuf, usize, String)> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            // Only a file can be a volume: a directory at a volume's name
            // must not mask that volume as present.
            .filter(|candidate| candidate.is_file())
            .filter_map(|candidate| {
                let (candidate_stem, number) = part_number(&candidate)?;
                let width = candidate.file_name()?.to_str()?.len()
                    - candidate_stem.len()
                    - ".part.rar".len();
                same_stem(&candidate_stem, &stem).then_some((
                    number,
                    candidate,
                    width,
                    candidate_stem,
                ))
            })
            .collect();
        present.sort();
        // A missing volume is named in the family's spelling on disk.
        let Some((highest, last, width, spelling)) = present.last().cloned() else {
            continue;
        };
        let more = crate::par3::execution_options(
            cli.par3_memory_mib,
            cli.par3_workers,
            cli.par3_max_lost_blocks,
        )
        .ok()
        .and_then(|options| {
            let mut disk = par3_rs::source::DiskSourceAccess::with_options(options.clone());
            disk.insert(par3_rs::source::SourceId(0), last.clone());
            rar5::inspect(&disk, par3_rs::source::SourceId(0), &options).ok()
        })
        .is_some_and(|archive| archive.more_volumes);
        let bound = (present.len() + recorded + 1) as u64;
        let end = highest.saturating_add(u64::from(more)).min(bound);
        let numbers: HashSet<u64> = present.iter().map(|(found, ..)| *found).collect();
        for number in 1..=end {
            if numbers.contains(&number) {
                continue;
            }
            let name = format!("{spelling}.part{number:0width$}.rar");
            if !covered.contains(&(directory.clone(), name_key(&name)))
                && reported.insert(name_key(&name))
            {
                missing.push(name);
            }
        }
    }
    missing
}

fn verify(cli: &Cli, args: &Par3InsideArgs) -> Result<(bool, Value), RarparError> {
    let sets = open(cli, args)?;
    // Verifying no set proves nothing, so an archive without one fails.
    if sets.is_empty() {
        return Err(RarparError::Data(
            "no embedded PAR3 set found in the given archives".to_owned(),
        ));
    }
    let uncovered = uncovered_volumes(cli, args, &sets);
    let healthy = uncovered.is_empty() && sets.iter().all(|set| set.needs_repair().is_empty());
    let repairable = uncovered.is_empty()
        && sets
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
        json!({"operation":"par3_inside_verify","status":status,"repairable":repairable,"unprotected_missing_volumes":uncovered,"sets":sets.iter().map(set_report).collect::<Vec<_>>()}),
    ))
}

fn repair(cli: &Cli, args: &Par3InsideRepairArgs) -> Result<(bool, Value), RarparError> {
    let mut sets = open(cli, &args.inputs)?;
    let mut outputs = Vec::new();
    let mut planned = false;
    let uncovered = uncovered_volumes(cli, &args.inputs, &sets);
    let mut success = uncovered.is_empty();
    for set in &mut sets {
        let needed = set.needs_repair();
        if needed.is_empty() {
            continue;
        }
        if !matches!(set.status, RepairStatus::Complete | RepairStatus::Ready) {
            success = false;
            continue;
        }
        let names = host_names(set)?;
        if cli.dry_run {
            planned = true;
            continue;
        }
        // A missing host goes beside this set's surviving hosts.
        let home = set
            .hosts
            .iter()
            .find_map(|host| host.path.as_deref())
            .map(directory_of)
            .unwrap_or_else(|| directory_of(&args.inputs.archives[0]));
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
        if let Some(dir) = &args.output_dir {
            std::fs::create_dir_all(dir)?;
        }
        // Each output is staged in its final directory, so the rename into
        // place never crosses a filesystem.
        let mut holders = Vec::new();
        let stages = stage_directories(&finals, &mut holders)?;
        let scratch = args
            .scratch_dir
            .clone()
            .unwrap_or_else(|| holders[0].1.path().to_owned());
        let staged: Vec<PathBuf> = names
            .iter()
            .zip(&stages)
            .map(|(name, stage)| stage.join(name))
            .collect();
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
    } else if planned {
        "planned"
    } else if outputs.is_empty() {
        "nothing to repair"
    } else {
        "repaired"
    };
    let mut report = json!({"operation":"par3_inside_repair","status":status,"unprotected_missing_volumes":uncovered,"sets":sets.iter().map(set_report).collect::<Vec<_>>(),"outputs":outputs});
    if cli.dry_run {
        report["dry_run"] = json!(true);
    }
    Ok((success, report))
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
        // A dry run makes the checks a removal would, and writes nothing.
        set.removable()?;
        let names = host_names(set)?;
        if cli.dry_run {
            continue;
        }
        let mut stage = Vec::new();
        let directories = if args.in_place {
            // Each host is staged in its own directory, so the rename back
            // over it never crosses a filesystem.
            let hosts: Vec<PathBuf> = set
                .hosts
                .iter()
                .map(|host| host.path.clone().unwrap_or_default())
                .collect();
            stage_directories(&hosts, &mut stage)?
        } else {
            let directory = args.output_dir.clone().expect("required by clap");
            std::fs::create_dir_all(&directory)?;
            vec![directory; names.len()]
        };
        let destinations: Vec<PathBuf> = names
            .iter()
            .zip(&directories)
            .map(|(name, directory)| directory.join(name))
            .collect();
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
    if cli.dry_run {
        return Ok((
            true,
            json!({"operation":"par3_inside_remove","status":"planned","dry_run":true,"outputs":outputs}),
        ));
    }
    Ok((
        true,
        json!({"operation":"par3_inside_remove","status":"removed","outputs":outputs}),
    ))
}

#[cfg(test)]
mod tests {
    use super::{check_host_name, same_stem};
    use crate::error::RarparError;

    /// Family stems compare exactly everywhere, and on Windows also across
    /// case; a character whose uppercase is longer than one never folds.
    #[test]
    fn family_stems_compare_as_the_platform_names_files() {
        assert!(same_stem("plover", "plover"));
        assert!(!same_stem("plover", "plover2"));
        let folds = cfg!(any(windows, target_os = "macos"));
        assert_eq!(same_stem("plover", "PLOVER"), folds);
        assert_eq!(same_stem("\u{e9}t\u{e9}", "\u{c9}T\u{c9}"), folds);
        assert!(!same_stem("stra\u{df}e", "STRASSE"));
    }

    #[test]
    fn a_recorded_host_name_must_be_one_safe_component() {
        assert!(check_host_name("invented_title.part1.rar").is_ok());
        for name in [
            "/var/invented_title.part1.rar",
            "../invented_title.part1.rar",
            "..",
            "nested/invented_title.part1.rar",
            "nested\\invented_title.part1.rar",
            "C:invented_title.part1.rar",
            "",
        ] {
            assert!(
                matches!(check_host_name(name), Err(RarparError::Unsafe(_))),
                "{name:?}"
            );
        }
    }
}
