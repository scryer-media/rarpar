use std::path::{Path, PathBuf};

use crate::cli::{Cli, ParArgs, ParCommand};
use crate::discovery::{ExecutedAction, Par2Set};
use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};

pub struct ParOutcome {
    pub set_id: String,
    pub success: bool,
    pub message: String,
}

impl ParOutcome {
    pub fn action(&self) -> ExecutedAction {
        ExecutedAction {
            set_id: self.set_id.clone(),
            action: "par_verify_repair".to_string(),
            success: self.success,
            message: self.message.clone(),
        }
    }
}

struct ResolvedPar2Input {
    set_id: String,
    par2_paths: Vec<PathBuf>,
    primary_dir: PathBuf,
    search_dirs: Vec<PathBuf>,
}

pub fn run_command(cli: &Cli, command: ParCommand) -> Result<u8, RarparError> {
    match command {
        ParCommand::Verify(args) => {
            let resolved = resolve_input(cli, &args)?;
            let outcome = run_flow(&resolved, false, false, cli.json)?;
            Ok(if outcome.success {
                EXIT_SUCCESS
            } else {
                EXIT_DATA_FAILURE
            })
        }
        ParCommand::Repair(args) => {
            let resolved = resolve_input(cli, &args)?;
            let outcome = run_flow(&resolved, true, cli.dry_run, cli.json)?;
            Ok(if outcome.success {
                EXIT_SUCCESS
            } else {
                EXIT_DATA_FAILURE
            })
        }
    }
}

pub fn repair_set(cli: &Cli, set: &Par2Set) -> Result<ParOutcome, RarparError> {
    let resolved = ResolvedPar2Input {
        set_id: set.id.clone(),
        par2_paths: set.paths.clone(),
        primary_dir: cli
            .working_dir
            .clone()
            .unwrap_or_else(|| set.base_dir.clone()),
        search_dirs: cli.search_dir.clone(),
    };
    run_flow(&resolved, true, false, cli.json)
}

fn run_flow(
    resolved: &ResolvedPar2Input,
    repair: bool,
    dry_run: bool,
    quiet: bool,
) -> Result<ParOutcome, RarparError> {
    let started = std::time::Instant::now();
    validate_directory_path(&resolved.primary_dir, "working directory")?;
    for dir in &resolved.search_dirs {
        validate_directory_path(dir, "search directory")?;
    }

    let par2_set = weaver_par2::Par2FileSet::from_paths(&resolved.par2_paths)?;
    if !quiet {
        print_context(
            if repair { "repair" } else { "verify" },
            resolved,
            &par2_set,
        );
    }

    let (verification, placement_plan) = verify_set(resolved, &par2_set)?;
    if !quiet {
        print_verification_report(&verification, placement_plan.as_ref(), &par2_set);
    }

    if !repair {
        let success = verification.total_missing_blocks == 0;
        return Ok(ParOutcome {
            set_id: resolved.set_id.clone(),
            success,
            message: format!(
                "verify completed in {:.2?}: missing blocks={}",
                started.elapsed(),
                verification.total_missing_blocks
            ),
        });
    }

    match &verification.repairable {
        weaver_par2::Repairability::NotNeeded => {
            return Ok(ParOutcome {
                set_id: resolved.set_id.clone(),
                success: true,
                message: format!("no repair needed; completed in {:.2?}", started.elapsed()),
            });
        }
        weaver_par2::Repairability::Insufficient {
            blocks_needed,
            blocks_available,
            deficit,
        } => {
            return Ok(ParOutcome {
                set_id: resolved.set_id.clone(),
                success: false,
                message: format!(
                    "repair not possible: need {blocks_needed} blocks, have {blocks_available} (deficit {deficit})"
                ),
            });
        }
        weaver_par2::Repairability::ResourceLimited { reason } => {
            return Err(RarparError::Resource(reason.clone()));
        }
        weaver_par2::Repairability::Repairable { .. } => {}
    }

    let repair_plan = weaver_par2::plan_repair(&par2_set, &verification)?;
    if dry_run {
        if let Some(plan) = &placement_plan
            && (!plan.swaps.is_empty() || !plan.renames.is_empty())
            && !quiet
        {
            println!(
                "dry-run: would normalize file placement for {} file(s)",
                plan.swaps.len() + plan.renames.len()
            );
        }
        if !quiet {
            println!(
                "dry-run: would repair {} slice(s) using {} recovery block(s)",
                repair_plan.missing_slices.len(),
                repair_plan.recovery_exponents.len()
            );
        }
        return Ok(ParOutcome {
            set_id: resolved.set_id.clone(),
            success: true,
            message: format!(
                "dry-run: would repair {} slice(s) using {} recovery block(s) in {:.2?}",
                repair_plan.missing_slices.len(),
                repair_plan.recovery_exponents.len(),
                started.elapsed()
            ),
        });
    }

    if let Some(plan) = &placement_plan
        && (!plan.swaps.is_empty() || !plan.renames.is_empty())
    {
        let moved = weaver_par2::apply_placement_plan(&resolved.primary_dir, plan)?;
        if !quiet {
            println!("normalized file placement before repair: moved {moved} file(s)");
        }
    }

    if !quiet {
        println!(
            "repairing {} slice(s) using {} recovery block(s)",
            repair_plan.missing_slices.len(),
            repair_plan.recovery_exponents.len()
        );
    }

    let options = weaver_par2::RepairOptions::default();
    let mut repair_access: Box<dyn weaver_par2::FileAccess> =
        build_repair_access(resolved, &par2_set, placement_plan.as_ref());
    weaver_par2::execute_repair_with_options(
        &repair_plan,
        &par2_set,
        &mut *repair_access,
        &options,
    )?;

    let final_verification = verify_after_repair(resolved, &par2_set)?;
    if !quiet {
        print_verification_report(&final_verification, None, &par2_set);
    }
    let success = final_verification.total_missing_blocks == 0;
    Ok(ParOutcome {
        set_id: resolved.set_id.clone(),
        success,
        message: format!(
            "repair completed in {:.2?}: missing blocks={}",
            started.elapsed(),
            final_verification.total_missing_blocks
        ),
    })
}

fn resolve_input(cli: &Cli, args: &ParArgs) -> Result<ResolvedPar2Input, RarparError> {
    if !args.input.exists() {
        return Err(RarparError::MissingInput(args.input.clone()));
    }

    let par2_paths = if args.input.is_dir() {
        collect_par2_paths_from_dir(&args.input)?
    } else {
        discover_matching_par2_paths(&args.input)?
    };
    let set_id = weaver_par2::Par2FileSet::from_paths(&par2_paths)
        .map(|set| set.recovery_set_id.to_string())
        .unwrap_or_else(|_| format!("par2:{}", args.input.display()));

    let primary_dir = cli.working_dir.clone().unwrap_or_else(|| {
        if args.input.is_dir() {
            args.input.clone()
        } else {
            args.input
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        }
    });
    let mut search_dirs = cli.search_dir.clone();
    search_dirs.extend(args.search_dirs.clone());
    search_dirs.sort();
    search_dirs.dedup();

    Ok(ResolvedPar2Input {
        set_id,
        par2_paths,
        primary_dir,
        search_dirs,
    })
}

fn validate_directory_path(path: &Path, label: &str) -> Result<(), RarparError> {
    if path.exists() && !path.is_dir() {
        return Err(RarparError::Usage(format!(
            "{label} is not a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn collect_par2_paths_from_dir(dir: &Path) -> Result<Vec<PathBuf>, RarparError> {
    let mut par2_paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && is_ext(&entry.path(), "par2") {
            par2_paths.push(entry.path());
        }
    }
    par2_paths.sort();
    if par2_paths.is_empty() {
        return Err(RarparError::Data(format!(
            "no .par2 files found in {}",
            dir.display()
        )));
    }
    Ok(par2_paths)
}

fn discover_matching_par2_paths(input: &Path) -> Result<Vec<PathBuf>, RarparError> {
    let seed_set = weaver_par2::Par2FileSet::from_paths(&[input])?;
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let mut par2_paths = weaver_par2::identify_par2_files(parent, &seed_set.recovery_set_id)?;
    if par2_paths.is_empty() {
        par2_paths.push(input.to_path_buf());
    }
    par2_paths.sort();
    par2_paths.dedup();
    Ok(par2_paths)
}

fn verify_set(
    resolved: &ResolvedPar2Input,
    par2_set: &weaver_par2::Par2FileSet,
) -> Result<
    (
        weaver_par2::VerificationResult,
        Option<weaver_par2::PlacementPlan>,
    ),
    RarparError,
> {
    if resolved.search_dirs.is_empty() {
        let placement_plan = weaver_par2::scan_placement(&resolved.primary_dir, par2_set)?;
        if !placement_plan.conflicts.is_empty() {
            return Err(RarparError::Data(format!(
                "placement scan found ambiguous matches: {}",
                format_conflict_filenames(&placement_plan, par2_set)
            )));
        }
        let access = weaver_par2::PlacementFileAccess::from_plan(
            resolved.primary_dir.clone(),
            par2_set,
            &placement_plan,
        );
        let verification = weaver_par2::verify_all(par2_set, &access);
        Ok((verification, Some(placement_plan)))
    } else {
        let access = weaver_par2::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        );
        let verification = weaver_par2::verify_all(par2_set, &access);
        Ok((verification, None))
    }
}

fn verify_after_repair(
    resolved: &ResolvedPar2Input,
    par2_set: &weaver_par2::Par2FileSet,
) -> Result<weaver_par2::VerificationResult, RarparError> {
    if resolved.search_dirs.is_empty() {
        let access = weaver_par2::DiskFileAccess::new(resolved.primary_dir.clone(), par2_set);
        Ok(weaver_par2::verify_all(par2_set, &access))
    } else {
        let access = weaver_par2::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        );
        Ok(weaver_par2::verify_all(par2_set, &access))
    }
}

fn build_repair_access(
    resolved: &ResolvedPar2Input,
    par2_set: &weaver_par2::Par2FileSet,
    placement_plan: Option<&weaver_par2::PlacementPlan>,
) -> Box<dyn weaver_par2::FileAccess> {
    if resolved.search_dirs.is_empty() {
        if let Some(plan) = placement_plan
            && plan.swaps.is_empty()
            && plan.renames.is_empty()
        {
            return Box::new(weaver_par2::PlacementFileAccess::from_plan(
                resolved.primary_dir.clone(),
                par2_set,
                plan,
            ));
        }
        Box::new(weaver_par2::DiskFileAccess::new(
            resolved.primary_dir.clone(),
            par2_set,
        ))
    } else {
        Box::new(weaver_par2::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        ))
    }
}

fn print_context(action: &str, resolved: &ResolvedPar2Input, par2_set: &weaver_par2::Par2FileSet) {
    println!("rarpar par {action}");
    println!("par2 files: {}", resolved.par2_paths.len());
    println!("working dir: {}", resolved.primary_dir.display());
    if !resolved.search_dirs.is_empty() {
        println!("search dirs: {}", resolved.search_dirs.len());
    }
    println!(
        "par2 set: files={}, slice_size={}, recovery_blocks={}",
        par2_set.files.len(),
        par2_set.slice_size,
        par2_set.recovery_block_count()
    );
}

fn print_verification_report(
    verification: &weaver_par2::VerificationResult,
    placement_plan: Option<&weaver_par2::PlacementPlan>,
    par2_set: &weaver_par2::Par2FileSet,
) {
    if let Some(plan) = placement_plan {
        println!(
            "placement: exact={}, renames={}, swaps={}, unresolved={}, conflicts={}",
            plan.exact.len(),
            plan.renames.len(),
            plan.swaps.len(),
            plan.unresolved.len(),
            plan.conflicts.len()
        );
    }

    let mut complete = 0usize;
    let mut damaged = 0usize;
    let mut missing = 0usize;
    for file in &verification.files {
        match &file.status {
            weaver_par2::FileStatus::Complete => complete += 1,
            weaver_par2::FileStatus::Damaged(bad_slices) => {
                damaged += 1;
                println!("  damaged: {} ({} bad slice(s))", file.filename, bad_slices);
            }
            weaver_par2::FileStatus::Missing => {
                missing += 1;
                println!(
                    "  missing: {} ({} slice(s))",
                    file.filename, file.missing_slice_count
                );
            }
            weaver_par2::FileStatus::Renamed(path) => {
                println!("  renamed: {} -> {}", file.filename, path.display());
            }
        }
    }

    println!(
        "summary: {} complete, {} damaged, {} missing",
        complete, damaged, missing
    );
    println!(
        "missing blocks: {}, recovery blocks available: {}",
        verification.total_missing_blocks, verification.recovery_blocks_available
    );
    match &verification.repairable {
        weaver_par2::Repairability::NotNeeded => println!("repairability: not needed"),
        weaver_par2::Repairability::Repairable {
            blocks_needed,
            blocks_available,
        } => println!(
            "repairability: repairable (need {}, have {})",
            blocks_needed, blocks_available
        ),
        weaver_par2::Repairability::Insufficient {
            blocks_needed,
            blocks_available,
            deficit,
        } => println!(
            "repairability: insufficient (need {}, have {}, deficit {})",
            blocks_needed, blocks_available, deficit
        ),
        weaver_par2::Repairability::ResourceLimited { reason } => {
            println!("repairability: resource-limited ({reason})")
        }
    }

    let _ = par2_set;
}

fn format_conflict_filenames(
    placement_plan: &weaver_par2::PlacementPlan,
    par2_set: &weaver_par2::Par2FileSet,
) -> String {
    let names: Vec<String> = placement_plan
        .conflicts
        .iter()
        .filter_map(|file_id| par2_set.file_description(file_id))
        .map(|desc| desc.filename.clone())
        .collect();
    if names.is_empty() {
        format!("{} file id(s)", placement_plan.conflicts.len())
    } else {
        names.join(", ")
    }
}

fn is_ext(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}
