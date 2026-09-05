use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::discovery::{ExecutedAction, Par2Set};
use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};
use crate::report;
use par2_rs::{
    BlockSizing, CreationBackend, Par2CreateOutcome, Par2CreatePlan, Par2Creator,
    Par2CreatorOptions, RecoveryAmount, VolumeScheme,
};
use rarpar::cli::{
    Cli, ParArgs, ParCommand, ParCreateArgs, ParCreationBackend, ParPlacement, ParVolumeScheme,
};
use serde::Serialize;
use tracing::info;

pub struct ParOutcome {
    pub set_id: String,
    pub success: bool,
    pub message: String,
    pub repaired: bool,
    pub recovery_blocks_needed: Option<u32>,
}

#[derive(Serialize)]
struct ParCommandReport<'a> {
    schema_version: u8,
    command: &'a str,
    success: bool,
    repaired: bool,
    recovery_blocks_needed: Option<u32>,
    message: &'a str,
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
    placement: ParPlacement,
}

pub fn run_command(cli: &Cli, command: ParCommand) -> Result<u8, RarparError> {
    let command = match command {
        ParCommand::Create(args) => return run_create(cli, args),
        ParCommand::Verify(args) => ParCommand::Verify(args),
        ParCommand::Repair(args) => ParCommand::Repair(args),
    };
    let (command_name, repair, args) = match command {
        ParCommand::Verify(args) => ("verify", false, args),
        ParCommand::Repair(args) => ("repair", true, args),
        ParCommand::Create(_) => unreachable!("create handled above"),
    };
    let resolved = resolve_input(cli, &args)?;
    let outcome = run_flow(&resolved, repair, cli.dry_run, cli.quiet || cli.json)?;
    emit_command_outcome(cli, command_name, &outcome)?;
    Ok(if outcome.success {
        EXIT_SUCCESS
    } else {
        EXIT_DATA_FAILURE
    })
}

fn run_create(cli: &Cli, args: ParCreateArgs) -> Result<u8, RarparError> {
    let base_path = args.base_path.clone().unwrap_or_else(|| {
        args.output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    for input in &args.files {
        let candidate = if input.is_absolute() {
            input.clone()
        } else {
            base_path.join(input)
        };
        if !candidate.exists() {
            return Err(RarparError::MissingInput(input.clone()));
        }
        if !candidate.is_file() {
            return Err(RarparError::Usage(format!(
                "par create accepts explicit files only; input is not a regular file: {}",
                input.display()
            )));
        }
    }

    let memory_limit = args
        .memory_mib
        .map(|mib| {
            if mib == 0 {
                Err(RarparError::Usage(
                    "--memory-mib must be greater than zero".into(),
                ))
            } else {
                mib.checked_mul(1024 * 1024).ok_or_else(|| {
                    RarparError::Resource("--memory-mib exceeds the supported memory limit".into())
                })
            }
        })
        .transpose()?;
    let mut options =
        Par2CreatorOptions::with_output(args.output.clone(), Some(base_path), args.files.clone());
    options.block_sizing = match (args.block_size, args.block_count) {
        (Some(bytes), None) => BlockSizing::Bytes(bytes),
        (None, Some(count)) => BlockSizing::Count(count),
        (None, None) => BlockSizing::Auto,
        (Some(_), Some(_)) => unreachable!("clap rejects block-size and block-count together"),
    };
    options.recovery_amount = match (args.recovery_percent, args.recovery_count) {
        (Some(percent), None) => RecoveryAmount::Percent(percent),
        (None, Some(count)) => RecoveryAmount::Count(count),
        (None, None) => RecoveryAmount::default(),
        (Some(_), Some(_)) => {
            unreachable!("clap rejects recovery-percent and recovery-count together")
        }
    };
    options.first_exponent = args.first_exponent;
    options.volume_scheme = match args.volume_scheme {
        ParVolumeScheme::Variable => VolumeScheme::Variable,
        ParVolumeScheme::Uniform => VolumeScheme::Uniform,
        ParVolumeScheme::Limited => VolumeScheme::Limited,
    };
    options.volume_count = args.volume_count;
    options.memory_limit = memory_limit;
    options.backend = match args.backend {
        ParCreationBackend::Cpu => CreationBackend::Cpu,
        ParCreationBackend::Auto => CreationBackend::Auto,
    };
    options.overwrite = cli.overwrite;
    options.dry_run = cli.dry_run;

    let progress_latch = if !cli.json && !cli.quiet {
        let (callback, latch) = create_progress_callback();
        options.progress = Some(callback);
        Some(latch)
    } else {
        None
    };

    let creator = Par2Creator::new(options);
    let plan: Par2CreatePlan = creator.plan()?;
    report::emit_par_create_plan(cli, &plan)?;
    let outcome: Par2CreateOutcome = creator.create(&plan)?;
    // The throttled callback never claims a phase is finished (no update is
    // identifiable as final); flush the latched truth once create returns.
    if let Some(latch) = progress_latch {
        latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .print();
    }
    report::emit_par_create_outcome(cli, &plan, &outcome)?;
    Ok(EXIT_SUCCESS)
}

struct ProgressLatch {
    last: Instant,
    stage: Option<par2_rs::ProgressStage>,
    phase: Option<par2_rs::ProgressPhase>,
    total: u32,
    current: u32,
    bytes: u64,
    printed: Option<PrintedLine>,
}

type PrintedLine = (
    par2_rs::ProgressStage,
    par2_rs::ProgressPhase,
    u32,
    u32,
    u64,
);

impl ProgressLatch {
    /// Print the latched state, unless it is exactly what was printed last.
    ///
    /// The same state reaches this twice at the end of an operation: the
    /// final update is throttle-sampled, then the caller flushes the latch
    /// once the operation returns (that flush is what makes the last line
    /// truthful when the sample is suppressed). Suppressing the repeat here
    /// keeps the tail line single without making the flush conditional on a
    /// race.
    fn print(&mut self) {
        let Some(stage) = self.stage else {
            return;
        };
        let phase = self.phase.unwrap_or_default();
        let current = self.current.saturating_add(1).min(self.total);
        let line = (stage, phase, current, self.total, self.bytes);
        if self.printed == Some(line) {
            return;
        }
        self.printed = Some(line);
        eprintln!(
            "create {stage:?}: {current}/{} ({} bytes)",
            self.total, self.bytes
        );
    }
}

fn create_progress_callback() -> (par2_rs::ProgressCallback, Arc<Mutex<ProgressLatch>>) {
    let state = Arc::new(Mutex::new(ProgressLatch {
        last: Instant::now() - Duration::from_secs(1),
        stage: None,
        phase: None,
        total: 0,
        current: 0,
        bytes: 0,
        printed: None,
    }));
    let latch_handle = Arc::clone(&state);
    let callback: par2_rs::ProgressCallback = Arc::new(move |update| {
        let now = Instant::now();
        let mut latch = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The source scan delivers updates from concurrent hashers, so raw
        // updates are not monotonic. Latch to the maximum seen, and reset
        // the latch when the phase changes (each phase carries its own
        // total: file count while scanning, stripe count while encoding).
        // The phase is read from the update, not inferred from a change in
        // `total`: both creation phases report stage `Creating`, and their
        // totals coincide whenever the set has as many files as the encoder
        // has stripes, which used to swallow the whole encode phase.
        // No update is identifiable as a phase's last, so the outgoing
        // phase's true final values are flushed at the transition and the
        // operation's final values are flushed by the caller after create
        // returns; in between, prints are purely throttle-sampled.
        if latch.phase != Some(update.phase) || update.total != latch.total {
            if latch.total != 0 {
                latch.print();
            }
            latch.total = update.total;
            latch.current = 0;
            latch.bytes = 0;
        }
        latch.stage = Some(update.stage);
        latch.phase = Some(update.phase);
        latch.current = latch.current.max(update.current);
        latch.bytes = latch.bytes.max(update.bytes_processed);
        if now.duration_since(latch.last) < Duration::from_millis(250) {
            return;
        }
        latch.last = now;
        latch.print();
    });
    (callback, latch_handle)
}

fn emit_command_outcome(
    cli: &Cli,
    command: &'static str,
    outcome: &ParOutcome,
) -> Result<(), RarparError> {
    if cli.json {
        let report = ParCommandReport {
            schema_version: 1,
            command,
            success: outcome.success,
            repaired: outcome.repaired,
            recovery_blocks_needed: outcome.recovery_blocks_needed,
            message: &outcome.message,
        };
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

/// Accept a `par2 r [options] PARFILE WILDCARD` invocation directly.
///
/// This is deliberately limited to repair mode; Rarpar's documented `par`
/// subcommands remain the general-purpose interface.
pub fn dispatch_par2cmdline_compat(args: &[OsString]) -> Option<u8> {
    let input = parse_par2cmdline_repair_input(args)?;
    let resolved = match resolve_compat_input(&input.par2_path, input.base_dir, input.wildcard) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("rarpar: {error}");
            println!("Repair Failed.");
            return Some(error.exit_code());
        }
    };

    match run_flow(&resolved, true, false, true) {
        Ok(outcome) => {
            emit_par2cmdline_outcome(&outcome);
            Some(if outcome.success {
                EXIT_SUCCESS
            } else {
                EXIT_DATA_FAILURE
            })
        }
        Err(error) => {
            eprintln!("rarpar: {error}");
            println!("Repair Failed.");
            Some(error.exit_code())
        }
    }
}

struct Par2cmdlineRepairInput {
    par2_path: PathBuf,
    base_dir: Option<PathBuf>,
    wildcard: Option<PathBuf>,
}

fn parse_par2cmdline_repair_input(args: &[OsString]) -> Option<Par2cmdlineRepairInput> {
    if !args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("r"))
    {
        return None;
    }

    let mut base_dir = None;
    let mut par2_path = None;
    let mut wildcard = None;
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy();
        if text == "-B" {
            base_dir = iter.next().map(PathBuf::from);
        } else if let Some(path) = text.strip_prefix("-B").filter(|path| !path.is_empty()) {
            base_dir = Some(PathBuf::from(path));
        } else {
            let path = PathBuf::from(arg);
            if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("par2"))
            {
                par2_path = Some(path);
            } else if par2_path.is_some() && wildcard.is_none() {
                wildcard = Some(path);
            }
        }
    }

    par2_path.map(|par2_path| Par2cmdlineRepairInput {
        par2_path,
        base_dir,
        wildcard,
    })
}

fn resolve_compat_input(
    input: &Path,
    base_dir: Option<PathBuf>,
    wildcard: Option<PathBuf>,
) -> Result<ResolvedPar2Input, RarparError> {
    if !input.exists() {
        return Err(RarparError::MissingInput(input.to_path_buf()));
    }

    let par2_paths = discover_compat_par2_paths(input, wildcard.as_deref())?;
    let set_id = par2_rs::Par2FileSet::from_paths(&par2_paths)
        .map(|set| set.recovery_set_id.to_string())
        .unwrap_or_else(|_| format!("par2:{}", input.display()));
    let primary_dir = base_dir.unwrap_or_else(|| {
        input
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    Ok(ResolvedPar2Input {
        set_id,
        par2_paths,
        primary_dir,
        search_dirs: Vec::new(),
        placement: ParPlacement::Smart,
    })
}

fn emit_par2cmdline_outcome(outcome: &ParOutcome) {
    if outcome.success {
        if outcome.repaired {
            println!("Repair is required");
            println!("Repair is possible");
            println!("Repair complete");
        } else {
            println!("All files are correct");
        }
    } else if let Some(blocks) = outcome.recovery_blocks_needed {
        println!("Repair is required.");
        println!("You need {blocks} more recovery blocks to be able to repair.");
    } else {
        println!("Repair Failed.");
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
        placement: cli.par_placement,
    };
    run_flow(&resolved, true, false, cli.quiet || cli.json)
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
    // A repair flow reads the same payload in its verify, accumulate, and
    // re-verify passes; hold one cache-eviction deferral across all of them
    // so intermediate passes are served from page cache. Verify-only flows
    // keep the immediate-eviction discipline.
    let _cache_retention = repair.then(par2_rs::CacheEvictionDeferral::acquire);

    let load_started = std::time::Instant::now();
    let par2_set = par2_rs::Par2FileSet::from_paths(&resolved.par2_paths)?;
    info!(
        elapsed_ms = load_started.elapsed().as_secs_f64() * 1_000.0,
        "PAR2 set loaded"
    );
    if !quiet {
        print_context(
            if repair { "repair" } else { "verify" },
            resolved,
            &par2_set,
        );
    }

    let verify_started = std::time::Instant::now();
    let (verification, placement_plan) = verify_set(resolved, &par2_set)?;
    info!(
        elapsed_ms = verify_started.elapsed().as_secs_f64() * 1_000.0,
        "initial PAR2 verification complete"
    );
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
            repaired: false,
            recovery_blocks_needed: None,
        });
    }

    match &verification.repairable {
        par2_rs::Repairability::NotNeeded => {
            return Ok(ParOutcome {
                set_id: resolved.set_id.clone(),
                success: true,
                message: format!("no repair needed; completed in {:.2?}", started.elapsed()),
                repaired: false,
                recovery_blocks_needed: None,
            });
        }
        par2_rs::Repairability::Insufficient {
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
                repaired: false,
                recovery_blocks_needed: Some(*deficit),
            });
        }
        par2_rs::Repairability::ResourceLimited { reason } => {
            return Err(RarparError::Resource(reason.clone()));
        }
        par2_rs::Repairability::Repairable { .. } => {}
    }

    let plan_started = std::time::Instant::now();
    let repair_plan = par2_rs::plan_repair(&par2_set, &verification)?;
    info!(
        elapsed_ms = plan_started.elapsed().as_secs_f64() * 1_000.0,
        "PAR2 repair plan complete"
    );
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
            repaired: false,
            recovery_blocks_needed: None,
        });
    }

    if let Some(plan) = &placement_plan
        && (!plan.swaps.is_empty() || !plan.renames.is_empty())
    {
        let moved = par2_rs::apply_placement_plan(&resolved.primary_dir, plan)?;
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

    let options = par2_rs::RepairOptions::default();
    let mut repair_access: Box<dyn par2_rs::FileAccess> =
        build_repair_access(resolved, &par2_set, placement_plan.as_ref());
    let execute_started = std::time::Instant::now();
    par2_rs::execute_repair_with_options(&repair_plan, &par2_set, &mut *repair_access, &options)?;
    info!(
        elapsed_ms = execute_started.elapsed().as_secs_f64() * 1_000.0,
        "PAR2 repair execution complete"
    );

    let post_verify_started = std::time::Instant::now();
    let final_verification = verify_after_repair(resolved, &par2_set, &verification, &repair_plan)?;
    info!(
        elapsed_ms = post_verify_started.elapsed().as_secs_f64() * 1_000.0,
        "post-repair PAR2 verification complete"
    );
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
        repaired: success,
        recovery_blocks_needed: None,
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
    let set_id = par2_rs::Par2FileSet::from_paths(&par2_paths)
        .map(|set| set.recovery_set_id.to_string())
        .unwrap_or_else(|_| format!("par2:{}", args.input.display()));

    let primary_dir = cli.working_dir.clone().unwrap_or_else(|| {
        if args.input.is_dir() {
            args.input.clone()
        } else {
            args.input
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
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
        placement: cli.par_placement,
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

fn discover_compat_par2_paths(
    input: &Path,
    wildcard: Option<&Path>,
) -> Result<Vec<PathBuf>, RarparError> {
    let Some(wildcard) = wildcard else {
        return discover_matching_par2_paths(input);
    };
    let parent = wildcard
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let pattern = wildcard
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let mut par2_paths = std::fs::read_dir(parent)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            (entry.file_type().ok()?.is_file()
                && is_ext(&path, "par2")
                && wildcard_match(&pattern, &entry.file_name().to_string_lossy()))
            .then_some(path)
        })
        .collect::<Vec<_>>();
    par2_paths.sort();
    if par2_paths.is_empty() {
        return discover_matching_par2_paths(input);
    }
    Ok(par2_paths)
}

fn discover_matching_par2_paths(input: &Path) -> Result<Vec<PathBuf>, RarparError> {
    let seed_set = par2_rs::Par2FileSet::from_paths(&[input])?;
    let parent = input
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut par2_paths = par2_rs::identify_par2_files(parent, &seed_set.recovery_set_id)?;
    if par2_paths.is_empty() {
        par2_paths.push(input.to_path_buf());
    }
    par2_paths.sort();
    par2_paths.dedup();
    Ok(par2_paths)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut remainder = text;
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    if !remainder.starts_with(first) {
        return false;
    }
    remainder = &remainder[first.len()..];
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    pattern.ends_with('*') || remainder.is_empty()
}

fn verify_set(
    resolved: &ResolvedPar2Input,
    par2_set: &par2_rs::Par2FileSet,
) -> Result<(par2_rs::VerificationResult, Option<par2_rs::PlacementPlan>), RarparError> {
    if resolved.placement == ParPlacement::Smart && resolved.search_dirs.is_empty() {
        let placement_plan = par2_rs::scan_placement(&resolved.primary_dir, par2_set)?;
        if !placement_plan.conflicts.is_empty() {
            return Err(RarparError::Data(format!(
                "placement scan found ambiguous matches: {}",
                format_conflict_filenames(&placement_plan, par2_set)
            )));
        }
        let access = par2_rs::PlacementFileAccess::from_plan(
            resolved.primary_dir.clone(),
            par2_set,
            &placement_plan,
        );
        // Initial discovery verification is independent per expected file. Use the
        // library's equivalent file-parallel verifier; repair stays content-grounded.
        let verification = par2_rs::verify::verify_selected_file_ids_parallel(
            par2_set,
            &access,
            &par2_set.recovery_file_ids,
        );
        Ok((verification, Some(placement_plan)))
    } else {
        let access = par2_rs::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        );
        // Canonical placement has the same independent-file verification shape.
        let verification = par2_rs::verify::verify_selected_file_ids_parallel(
            par2_set,
            &access,
            &par2_set.recovery_file_ids,
        );
        Ok((verification, None))
    }
}

fn verify_after_repair(
    resolved: &ResolvedPar2Input,
    par2_set: &par2_rs::Par2FileSet,
    initial: &par2_rs::VerificationResult,
    repair_plan: &par2_rs::RepairPlan,
) -> Result<par2_rs::VerificationResult, RarparError> {
    let repaired: std::collections::HashSet<_> = repair_plan
        .missing_slices
        .iter()
        .map(|(file_id, _)| *file_id)
        .collect();
    let repaired_file_ids: Vec<_> = par2_set
        .recovery_file_ids
        .iter()
        .filter(|file_id| repaired.contains(file_id))
        .copied()
        .collect();
    if resolved.search_dirs.is_empty() {
        let access = par2_rs::DiskFileAccess::new(resolved.primary_dir.clone(), par2_set);
        let updated = par2_rs::verify::verify_repaired_file_ids_parallel(
            par2_set,
            &access,
            &repaired_file_ids,
        );
        Ok(par2_rs::verify::merge_verification_results(
            par2_set, initial, updated,
        ))
    } else {
        let access = par2_rs::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        );
        let updated = par2_rs::verify::verify_repaired_file_ids_parallel(
            par2_set,
            &access,
            &repaired_file_ids,
        );
        Ok(par2_rs::verify::merge_verification_results(
            par2_set, initial, updated,
        ))
    }
}

fn build_repair_access(
    resolved: &ResolvedPar2Input,
    par2_set: &par2_rs::Par2FileSet,
    placement_plan: Option<&par2_rs::PlacementPlan>,
) -> Box<dyn par2_rs::FileAccess> {
    if resolved.search_dirs.is_empty() {
        if let Some(plan) = placement_plan
            && plan.swaps.is_empty()
            && plan.renames.is_empty()
        {
            return Box::new(par2_rs::PlacementFileAccess::from_plan(
                resolved.primary_dir.clone(),
                par2_set,
                plan,
            ));
        }
        Box::new(par2_rs::DiskFileAccess::new(
            resolved.primary_dir.clone(),
            par2_set,
        ))
    } else {
        Box::new(par2_rs::MultiDirectoryFileAccess::new(
            resolved.primary_dir.clone(),
            resolved.search_dirs.clone(),
            par2_set,
        ))
    }
}

fn print_context(action: &str, resolved: &ResolvedPar2Input, par2_set: &par2_rs::Par2FileSet) {
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
    verification: &par2_rs::VerificationResult,
    placement_plan: Option<&par2_rs::PlacementPlan>,
    par2_set: &par2_rs::Par2FileSet,
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
            par2_rs::FileStatus::Complete => complete += 1,
            par2_rs::FileStatus::Damaged(bad_slices) => {
                damaged += 1;
                println!("  damaged: {} ({} bad slice(s))", file.filename, bad_slices);
            }
            par2_rs::FileStatus::Missing => {
                missing += 1;
                println!(
                    "  missing: {} ({} slice(s))",
                    file.filename, file.missing_slice_count
                );
            }
            par2_rs::FileStatus::Renamed(path) => {
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
        par2_rs::Repairability::NotNeeded => println!("repairability: not needed"),
        par2_rs::Repairability::Repairable {
            blocks_needed,
            blocks_available,
        } => println!(
            "repairability: repairable (need {}, have {})",
            blocks_needed, blocks_available
        ),
        par2_rs::Repairability::Insufficient {
            blocks_needed,
            blocks_available,
            deficit,
        } => println!(
            "repairability: insufficient (need {}, have {}, deficit {})",
            blocks_needed, blocks_available, deficit
        ),
        par2_rs::Repairability::ResourceLimited { reason } => {
            println!("repairability: resource-limited ({reason})")
        }
    }

    let _ = par2_set;
}

fn format_conflict_filenames(
    placement_plan: &par2_rs::PlacementPlan,
    par2_set: &par2_rs::Par2FileSet,
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
