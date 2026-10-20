#[cfg(feature = "sevenz")]
mod archive;
mod cleanup;
#[cfg(feature = "sevenz")]
mod compat_7z;
mod compat_par3;
mod compat_unrar;
mod discovery;
mod error;
mod par2;
mod par2_stream;
mod par3;
mod par3_inside;
mod par3_pipe;
mod par3_stream;
mod password;
mod rar;
mod report;
mod sidecar;
mod streams;
mod xz;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::discovery::{DiscoveryOptions, DiscoveryReport};
use crate::error::{EXIT_SUCCESS, RarparError};
use crate::password::PasswordResolver;
use rarpar::cli::{Cli, Command, RarCommand};

// Doubly gated on purpose: the `mimalloc` dependency only exists for
// `cfg(target_env = "musl")` targets, and the `cfg` below repeats the
// condition so a mis-specified feature flag cannot swap the allocator on
// glibc, macOS or Windows. Those distributions keep the system allocator.
// The release and CI musl builds compile mimalloc with
// -DMI_DEFAULT_ALLOW_THP=0 in CFLAGS (confirm_native_code.py checks it):
// mimalloc's own default madvises huge pages, which roughly doubles peak RSS
// on THP kernels for no measured speed. MIMALLOC_ALLOW_THP=1 turns it back on.
#[cfg(all(feature = "musl-allocator", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    install_tracing();

    let mut raw_args = std::env::args_os();
    let program = raw_args.next().unwrap_or_default();
    let args: Vec<_> = raw_args.collect();

    if let Some(code) = dispatch_compat(&program, &args) {
        return ExitCode::from(code);
    }

    let parse_args = std::iter::once(program).chain(args).collect::<Vec<_>>();
    let cli = Cli::parse_from(parse_args);
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("rarpar: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn install_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
}

fn run(cli: Cli) -> Result<u8, RarparError> {
    match cli.command.clone() {
        Some(Command::Auto(args)) => run_auto(&cli, args.paths),
        Some(Command::Inspect(args)) => run_inspect(&cli, args.paths),
        Some(Command::Cleanup(args)) => run_cleanup(&cli, args.paths),
        Some(Command::Rar { command }) => run_rar_command(&cli, command),
        Some(Command::Par { command }) => par2::run_command(&cli, command),
        Some(Command::Par3 { command }) => par3::run_command(&cli, command),
        Some(Command::Xz { command }) => xz::run_command(&cli, command),
        None => {
            if cli.paths.is_empty() {
                return Err(RarparError::NoInput);
            }
            run_auto(&cli, cli.paths.clone())
        }
    }
}

fn run_auto(cli: &Cli, mut paths: Vec<std::path::PathBuf>) -> Result<u8, RarparError> {
    let options = DiscoveryOptions::from_cli(cli);
    let mut report = discovery::discover(paths.clone(), &options)?;

    if !cli.dry_run {
        emit_progress(cli, &report)?;
    }

    if report.files.iter().any(|file| {
        file.kind == discovery::DiscoveredKind::Par3
            && !file.diagnostics.is_empty()
            && (report.par3_sets.is_empty() || report.roots.contains(&file.path))
    }) {
        return Err(RarparError::Data(
            "PAR3 carrier has no authenticated packets; inspect its diagnostics".into(),
        ));
    }
    let selected_par3: Vec<_> = report
        .par3_sets
        .iter()
        .filter(|set| discovery::selected_par3_set(set, &report.roots))
        .cloned()
        .collect();
    let had_par3_sets = !selected_par3.is_empty();
    let mut pending_par3 = Vec::new();
    // A dry run assesses each parity step as the real run orders them,
    // records it and runs none; the sets it assesses as repairing, or
    // needing no repair, are those its restore plans credit, by id. A step
    // short of recovery data is deferred when the other parity's passing
    // sets list every file it left damaged, as the real run repairs those
    // first (PAR3) or reassesses after them (PAR2); otherwise it fails, and
    // the run's exit code is the first failing step's, as the real run stops
    // at that step.
    let mut passing_parity = BTreeSet::new();
    let mut dry_run_exit = EXIT_SUCCESS;
    let mut inferred = std::collections::BTreeSet::new();
    for set in selected_par3 {
        let outcome = par3::repair_set(cli, &set)?;
        report.record_action(outcome.action());
        if outcome.success {
            passing_parity.insert(set.id.clone());
        } else {
            pending_par3.push((set, outcome.incomplete_paths));
        }
        for path in outcome.protected_paths {
            if path.is_file() && !inferred.contains(&path.canonicalize()?) {
                for member in discovery::expand_inferred_member(&path, &options)? {
                    if inferred.insert(member.canonicalize()?) {
                        if inferred.len() > options.max_files {
                            return Err(RarparError::Resource(
                                "inferred archive discovery exceeded --max-files".into(),
                            ));
                        }
                        paths.push(member);
                    }
                }
            }
        }
    }
    if had_par3_sets {
        paths.sort();
        paths.dedup();
        rediscover_preserving_history(cli, &paths, &options, &mut report)?;
    }
    let had_par2_sets = !report.par2_sets.is_empty();

    for par_set in report.par2_sets.clone() {
        let outcome = par2::repair_set(cli, &par_set)?;
        let mut action = outcome.action();
        if cli.dry_run && !outcome.success {
            let rebuilt = &outcome.damaged_paths;
            if parity_lists_all(
                rebuilt,
                par3_listing(&report, &passing_parity, cli.working_dir.as_deref()),
            ) {
                action.success = true;
                action.deferred_to = Some("par3");
                action.message = format!(
                    "{}; PAR3 repair runs first for {}",
                    action.message,
                    rar::file_names(rebuilt.iter().map(PathBuf::as_path))
                );
            } else if dry_run_exit == EXIT_SUCCESS {
                dry_run_exit = crate::error::EXIT_DATA_FAILURE;
            }
        }
        let success = action.success;
        report.record_action(action);
        if success {
            passing_parity.insert(par_set.id.clone());
        } else if !cli.dry_run {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_DATA_FAILURE);
        }
    }
    if had_par2_sets && !cli.dry_run {
        rediscover_preserving_history(cli, &paths, &options, &mut report)?;
    }

    // A PAR3 deficit must not prevent an overlapping PAR2 set from repairing
    // the inputs. Reassess only deferred sets, using the retained packets; a
    // dry run, which repaired nothing to reassess, defers the set to the PAR2
    // repairs when they rebuild every file it left incomplete.
    for (set, incomplete) in pending_par3 {
        if cli.dry_run {
            if parity_lists_all(&incomplete, par2_listing(&report, &passing_parity)) {
                report.record_action(discovery::ExecutedAction {
                    set_id: set.id.clone(),
                    action: "par3_verify_repair".into(),
                    success: true,
                    message: format!(
                        "PAR2 repair runs first for {}",
                        rar::file_names(incomplete.iter().map(PathBuf::as_path))
                    ),
                    deferred_to: Some("par2"),
                });
                passing_parity.insert(set.id.clone());
            } else if dry_run_exit == EXIT_SUCCESS {
                dry_run_exit = crate::error::EXIT_DATA_FAILURE;
            }
            continue;
        }
        let outcome = par3::repair_set(cli, &set)?;
        report.record_action(outcome.action());
        if !outcome.success {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_DATA_FAILURE);
        }
    }
    if cli.dry_run {
        let planned = plan_rar_restores(cli, &mut report, &passing_parity);
        report::emit_discovery(cli, &report)?;
        return Ok(if dry_run_exit == EXIT_SUCCESS {
            planned
        } else {
            dry_run_exit
        });
    }
    for set in &mut report.par3_sets {
        set.release_carriers();
    }

    let mut passwords = PasswordResolver::from_cli(cli)?;
    let mut restored_paths = Vec::new();
    for rar_set in report.rar_sets.clone() {
        if !rar_set.recovery_volumes.is_empty() {
            // Restored volumes are intermediate set members. They must stay
            // beside their sibling volumes even when extraction has a separate
            // output directory.
            let mut restore_cli = cli.clone();
            restore_cli.output = None;
            let outcome = rar::restore_volumes(&restore_cli, &rar_set)?;
            restored_paths.extend_from_slice(outcome.restored_paths());
            report.record_action(outcome.action());
            if !outcome.success {
                report::emit_discovery(cli, &report)?;
                return Ok(crate::error::EXIT_DATA_FAILURE);
            }
        }
    }

    if !restored_paths.is_empty() {
        let mut rediscovery_paths = paths.clone();
        rediscovery_paths.extend(restored_paths);
        rediscover_preserving_history(cli, &rediscovery_paths, &options, &mut report)?;
    }

    for rar_set in report.rar_sets.clone() {
        let output_dir = discovery::output_dir_for_rar_set(cli, &rar_set, report.rar_sets.len());
        let outcome = rar::extract_set(cli, &rar_set, &output_dir, &mut passwords)?;
        report.record_action(outcome.action());
        if !outcome.success {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_DATA_FAILURE);
        }

        if cli.delete_sources {
            let mut manifest = cleanup::manifest_for_rar_set(&rar_set, &report.par2_sets);
            cleanup::add_par3_carriers(
                &mut manifest,
                &rar_set,
                &report.par3_sets,
                cli.working_dir.as_deref(),
            );
            let cleanup = cleanup::delete_manifest(cli, &manifest)?;
            report.record_cleanup(cleanup);
        }
    }

    report::emit_discovery(cli, &report)?;
    Ok(EXIT_SUCCESS)
}

/// The restore step of `auto --dry-run`: plan each RAR set's restore as the
/// real run would make it, beside the set's volumes, and record the plan as
/// the step's action. A set whose restore cannot be planned is recorded as a
/// failed step, and the sets after it are still planned. Returns the exit
/// code of the first set that fails, as the real run stops there.
///
/// The real run repairs with PAR3 and PAR2 before it restores. A dry run
/// cannot run those repairs, so it judges each plan with the files the
/// parity sets in `passing`, those it assessed as repairing or needing no
/// repair, would rebuild in mind; see [`rar::ParityCover`]. A set with no
/// `.rev` file on disk is restored only when those repairs rebuild its
/// `.rev` files, so it is deferred to them then and not planned otherwise.
fn plan_rar_restores(cli: &Cli, report: &mut DiscoveryReport, passing: &BTreeSet<String>) -> u8 {
    let mut restore_cli = cli.clone();
    restore_cli.output = None;
    let mut exit_code = EXIT_SUCCESS;
    for rar_set in report.rar_sets.clone() {
        let cover = parity_cover(report, &rar_set, passing, cli.working_dir.as_deref());
        let outcome = if rar_set.recovery_volumes.is_empty() {
            if cover.recovery_volumes.is_empty() {
                continue;
            }
            rar::defer_restore_to_parity(&rar_set.id, &cover)
        } else {
            rar::plan_restore(&restore_cli, &rar_set, &cover)
                .unwrap_or_else(|error| rar::RarRestoreOutcome::unplanned(&rar_set.id, &error))
        };
        if exit_code == EXIT_SUCCESS {
            exit_code = outcome.exit_code;
        }
        report.record_action(outcome.action());
    }
    exit_code
}

/// The files the parity sets a real `auto` run repairs before it restores
/// `rar_set` protect, each resolved as that repair resolves it: a PAR2
/// set's against its own directory, a PAR3 set's against `working_dir` when
/// given, else its own directory. The PAR2 sets are those related to the
/// RAR set, the PAR3 sets those the run repairs, each only among `passing`,
/// the ids of the sets the dry run assessed as repairing or needing no
/// repair. The `.rev` files of the RAR set among them are picked out, as the
/// restore after those repairs reads them.
fn parity_cover(
    report: &DiscoveryReport,
    rar_set: &discovery::RarSet,
    passing: &BTreeSet<String>,
    working_dir: Option<&std::path::Path>,
) -> rar::ParityCover {
    let par2 = discovery::related_par2_sets(rar_set, &report.par2_sets)
        .into_iter()
        .filter(|set| passing.contains(&set.id))
        .flat_map(|set| {
            set.protected_files
                .iter()
                .map(|name| set.base_dir.join(name))
        })
        .collect::<BTreeSet<_>>();
    let par3 = par3_listing(report, passing, working_dir).collect::<BTreeSet<_>>();
    let recovery_volumes = par2
        .iter()
        .chain(&par3)
        .filter(|path| discovery::recovery_volume_of(rar_set, path))
        .cloned()
        .collect();
    rar::ParityCover {
        par2,
        par3,
        recovery_volumes,
    }
}

/// The files the PAR2 sets among `passing` protect, each under its set's
/// directory.
fn par2_listing<'a>(
    report: &'a DiscoveryReport,
    passing: &'a BTreeSet<String>,
) -> impl Iterator<Item = PathBuf> + 'a {
    report
        .par2_sets
        .iter()
        .filter(|set| passing.contains(&set.id))
        .flat_map(|set| {
            set.protected_files
                .iter()
                .map(|name| set.base_dir.join(name))
        })
}

/// The files the PAR3 sets `auto` repairs among `passing` protect, each as
/// the repair under `working_dir` resolves it.
fn par3_listing<'a>(
    report: &'a DiscoveryReport,
    passing: &'a BTreeSet<String>,
    working_dir: Option<&'a std::path::Path>,
) -> impl Iterator<Item = PathBuf> + 'a {
    report
        .par3_sets
        .iter()
        .filter(|set| passing.contains(&set.id) && discovery::selected_par3_set(set, &report.roots))
        .filter_map(move |set| set.member_paths(working_dir).ok())
        .flatten()
}

/// Whether `listed`, a parity's protected files, names every one of
/// `paths`, as [`rar::same_file`] compares them; no path is never rebuilt.
fn parity_lists_all(paths: &[PathBuf], listed: impl Iterator<Item = PathBuf>) -> bool {
    if paths.is_empty() {
        return false;
    }
    let listed = listed.collect::<Vec<_>>();
    paths
        .iter()
        .all(|path| listed.iter().any(|name| rar::same_file(name, path)))
}

fn run_inspect(cli: &Cli, paths: Vec<std::path::PathBuf>) -> Result<u8, RarparError> {
    let report = discovery::discover(paths, &DiscoveryOptions::from_cli(cli))?;
    report::emit_discovery(cli, &report)?;
    Ok(EXIT_SUCCESS)
}

fn run_cleanup(cli: &Cli, mut paths: Vec<std::path::PathBuf>) -> Result<u8, RarparError> {
    let options = DiscoveryOptions::from_cli(cli);
    let mut report = discovery::discover(paths.clone(), &options)?;
    let mut known: std::collections::BTreeSet<_> = report
        .files
        .iter()
        .map(|file| file.path.canonicalize())
        .collect::<Result<_, _>>()?;
    let mut members = std::collections::BTreeSet::new();
    for set in report
        .par3_sets
        .iter()
        .filter(|set| discovery::selected_par3_set(set, &report.roots))
    {
        for path in set.member_paths(cli.working_dir.as_deref())? {
            if path.is_file() && !known.contains(&path.canonicalize()?) {
                for member in discovery::expand_inferred_member(&path, &options)? {
                    if known.insert(member.canonicalize()?) {
                        if known.len() > options.max_files {
                            return Err(RarparError::Resource(
                                "inferred cleanup exceeded --max-files".into(),
                            ));
                        }
                        members.insert(member);
                    }
                }
            }
        }
    }
    if !members.is_empty() {
        paths.extend(members);
        report = discovery::rediscover(paths, &options, &mut report)?;
    }
    for set in &mut report.par3_sets {
        set.release_carriers();
    }
    emit_progress(cli, &report)?;

    if cli.dry_run {
        if cli.json {
            report::emit_discovery(cli, &report)?;
        }
        return Ok(EXIT_SUCCESS);
    }

    let mut passwords = PasswordResolver::from_cli(cli)?;
    for rar_set in report.rar_sets.clone() {
        let output_dir = discovery::output_dir_for_rar_set(cli, &rar_set, report.rar_sets.len());
        cleanup::validate_extracted_outputs(&rar_set, &output_dir, &mut passwords)?;
        let mut manifest = cleanup::manifest_for_rar_set(&rar_set, &report.par2_sets);
        cleanup::add_par3_carriers(
            &mut manifest,
            &rar_set,
            &report.par3_sets,
            cli.working_dir.as_deref(),
        );
        let cleanup = cleanup::delete_manifest(cli, &manifest)?;
        report.record_cleanup(cleanup.clone());
        if !cleanup.success {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_UNSAFE);
        }
    }
    report::emit_discovery(cli, &report)?;
    Ok(EXIT_SUCCESS)
}

fn emit_progress(cli: &Cli, report: &DiscoveryReport) -> Result<(), RarparError> {
    if !cli.json {
        report::emit_discovery(cli, report)?;
    }
    Ok(())
}

fn rediscover_preserving_history(
    cli: &Cli,
    paths: &[std::path::PathBuf],
    options: &DiscoveryOptions,
    report: &mut DiscoveryReport,
) -> Result<(), RarparError> {
    let executed_actions = std::mem::take(&mut report.executed_actions);
    let cleanup_results = std::mem::take(&mut report.cleanup_results);
    *report = discovery::rediscover(paths.to_vec(), options, report)?;
    report.executed_actions = executed_actions;
    report.cleanup_results = cleanup_results;
    emit_progress(cli, report)
}

fn run_rar_command(cli: &Cli, command: RarCommand) -> Result<u8, RarparError> {
    match command {
        RarCommand::List { archive } => {
            let mut passwords = PasswordResolver::from_cli(cli)?;
            rar::list_archive(cli, &archive, &mut passwords)
        }
        RarCommand::Test { archive } => {
            let mut passwords = PasswordResolver::from_cli(cli)?;
            rar::test_archive(cli, &archive, &mut passwords)
        }
        RarCommand::Extract { archive, dest } => {
            let mut passwords = PasswordResolver::from_cli(cli)?;
            let set = discovery::discover_rar_set_for_archive(
                &archive,
                &DiscoveryOptions::from_cli(cli),
            )?;
            let output_dir = dest
                .or_else(|| cli.output.clone())
                .unwrap_or_else(|| set.base_dir.clone());
            let outcome = rar::extract_set(cli, &set, &output_dir, &mut passwords)?;
            if cli.delete_sources && outcome.success {
                let manifest = cleanup::manifest_for_rar_set(&set, &[]);
                let cleanup = cleanup::delete_manifest(cli, &manifest)?;
                if !cleanup.success {
                    return Ok(crate::error::EXIT_UNSAFE);
                }
            }
            Ok(if outcome.success {
                EXIT_SUCCESS
            } else {
                crate::error::EXIT_DATA_FAILURE
            })
        }
        RarCommand::RestoreVolumes { paths } => rar::restore_volume_paths(cli, &paths),
        RarCommand::TestVolumes { paths } => rar::test_volume_paths(cli, &paths),
    }
}

fn dispatch_compat(program: &OsString, args: &[OsString]) -> Option<u8> {
    // Started as `par3`, rarpar is par3cmdline and takes every command line.
    if compat_par3::invoked_as_par3(program) {
        return compat_par3::dispatch(args, true);
    }
    #[cfg(feature = "sevenz")]
    {
        if compat_7z::invoked_as_7z(program) {
            return Some(compat_7z::dispatch(args));
        }
        if args.first().is_some_and(|arg| arg == "7z") {
            return Some(compat_7z::dispatch(&args[1..]));
        }
    }
    compat_par3::dispatch(args, false)
        .or_else(|| par2::dispatch_par2cmdline_compat(args))
        .or_else(|| compat_unrar::dispatch(args))
}
