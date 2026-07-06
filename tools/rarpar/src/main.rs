mod cleanup;
mod cli;
mod compat_unrar;
mod discovery;
mod error;
mod par2;
mod password;
mod rar;
mod report;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, RarCommand};
use crate::discovery::{DiscoveryOptions, DiscoveryReport};
use crate::error::{EXIT_SUCCESS, RarparError};
use crate::password::PasswordResolver;

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
        None => {
            if cli.paths.is_empty() {
                return Err(RarparError::NoInput);
            }
            run_auto(&cli, cli.paths.clone())
        }
    }
}

fn run_auto(cli: &Cli, paths: Vec<std::path::PathBuf>) -> Result<u8, RarparError> {
    let options = DiscoveryOptions::from_cli(cli);
    let mut report = discovery::discover(paths.clone(), &options)?;
    emit_progress(cli, &report)?;

    if cli.dry_run {
        if cli.json {
            report::emit_discovery(cli, &report)?;
        }
        return Ok(EXIT_SUCCESS);
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

    let mut restored_paths = Vec::new();
    for rar_set in report.rar_sets.clone() {
        if !rar_set.recovery_volumes.is_empty() {
            let outcome = rar::restore_volumes(cli, &rar_set)?;
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
            let manifest = cleanup::manifest_for_rar_set(&rar_set, &report.par2_sets);
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

fn run_cleanup(cli: &Cli, paths: Vec<std::path::PathBuf>) -> Result<u8, RarparError> {
    let mut report = discovery::discover(paths, &DiscoveryOptions::from_cli(cli))?;
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
        let manifest = cleanup::manifest_for_rar_set(&rar_set, &report.par2_sets);
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
    *report = discovery::discover(paths.to_vec(), options)?;
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
    compat_unrar::dispatch(args)
}
