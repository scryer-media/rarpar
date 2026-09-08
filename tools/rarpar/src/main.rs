mod cleanup;
mod compat_unrar;
mod discovery;
mod error;
mod par2;
mod par3;
mod password;
mod rar;
mod report;

use std::ffi::OsString;
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
#[cfg(all(feature = "musl-allocator", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    install_tracing();

    let mut raw_args = std::env::args_os();
    let program = raw_args.next().unwrap_or_default();
    let args: Vec<_> = raw_args.collect();

    if let Some(code) = dispatch_compat(&args) {
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
    emit_progress(cli, &report)?;

    if cli.dry_run {
        if cli.json {
            report::emit_discovery(cli, &report)?;
        }
        return Ok(EXIT_SUCCESS);
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
    let mut inferred = std::collections::BTreeSet::new();
    for set in selected_par3 {
        let outcome = par3::repair_set(cli, &set)?;
        report.record_action(outcome.action());
        if !outcome.success {
            pending_par3.push(set);
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
    let mut passwords = PasswordResolver::from_cli(cli)?;
    let had_par2_sets = !report.par2_sets.is_empty();

    for par_set in report.par2_sets.clone() {
        let outcome = par2::repair_set(cli, &par_set)?;
        report.record_action(outcome.action());
        if !outcome.success {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_DATA_FAILURE);
        }
    }
    if had_par2_sets {
        rediscover_preserving_history(cli, &paths, &options, &mut report)?;
    }

    // A PAR3 deficit must not prevent an overlapping PAR2 set from repairing
    // the inputs. Reassess only deferred sets, using the retained packets.
    for set in pending_par3 {
        let outcome = par3::repair_set(cli, &set)?;
        report.record_action(outcome.action());
        if !outcome.success {
            report::emit_discovery(cli, &report)?;
            return Ok(crate::error::EXIT_DATA_FAILURE);
        }
    }
    for set in &mut report.par3_sets {
        set.release_carriers();
    }

    let mut restored_paths = Vec::new();
    for rar_set in report.rar_sets.clone() {
        if !rar_set.recovery_volumes.is_empty() {
            // Restored volumes are intermediate set members. They must stay
            // beside their sibling volumes even when extraction has a separate
            // output directory.
            let mut restore_cli = cli.clone();
            restore_cli.output = None;
            let outcome = rar::restore_volumes(&restore_cli, &rar_set)?;
            restored_paths.extend(outcome.restored_paths.clone());
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
        let cached = std::mem::take(&mut report.par3_sets);
        report = discovery::discover_reusing_par3(paths, &options, Some(cached))?;
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
    let par3_sets = std::mem::take(&mut report.par3_sets);
    *report = discovery::discover_reusing_par3(paths.to_vec(), options, Some(par3_sets))?;
    report.executed_actions = executed_actions;
    report.cleanup_results = cleanup_results;
    emit_progress(cli, report)
}

fn run_rar_command(cli: &Cli, command: RarCommand) -> Result<u8, RarparError> {
    match command {
        RarCommand::List { archive } => {
            let mut passwords = PasswordResolver::from_cli(cli)?;
            rar::list_archive(&archive, &mut passwords)
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
    }
}

fn dispatch_compat(args: &[OsString]) -> Option<u8> {
    par2::dispatch_par2cmdline_compat(args).or_else(|| compat_unrar::dispatch(args))
}
