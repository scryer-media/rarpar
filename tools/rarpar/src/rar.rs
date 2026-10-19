use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::discovery::{ExecutedAction, RarSet};
use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};
use crate::password::PasswordResolver;
use rarpar::cli::Cli;

pub struct RarOutcome {
    pub set_id: String,
    pub action_name: &'static str,
    pub success: bool,
    pub message: String,
}

impl RarOutcome {
    pub fn action(&self) -> ExecutedAction {
        ExecutedAction {
            set_id: self.set_id.clone(),
            action: self.action_name.to_string(),
            success: self.success,
            message: self.message.clone(),
            deferred_to: None,
        }
    }
}

/// What a restore did, or for a dry run what it would do.
pub struct RarRestoreOutcome {
    pub set_id: String,
    pub dry_run: bool,
    /// False only for a dry run whose restore would fail: a real restore that
    /// cannot finish returns an error instead.
    pub success: bool,
    /// The code a command ending on this outcome exits with. A dry run that
    /// fails takes the code of the error the real restore would raise.
    pub exit_code: u8,
    pub message: String,
    /// See [`ExecutedAction::deferred_to`].
    pub deferred_to: Option<&'static str>,
    /// The dry run's plan. A real run does not plan.
    pub plan: Option<unrar_rs::RestorePlan>,
    /// The real run's report.
    pub report: Option<unrar_rs::RecoveryReport>,
}

impl RarRestoreOutcome {
    /// An `auto --dry-run` set whose restore could not be planned, recorded
    /// as a failed step so the report still covers it and the other sets.
    pub fn unplanned(set_id: &str, error: &RarparError) -> Self {
        Self {
            set_id: set_id.to_string(),
            dry_run: true,
            success: false,
            exit_code: error.exit_code(),
            message: format!("cannot plan restore: {error}"),
            deferred_to: None,
            plan: None,
            report: None,
        }
    }

    pub fn action(&self) -> ExecutedAction {
        ExecutedAction {
            set_id: self.set_id.clone(),
            action: "rar_restore_volumes".to_string(),
            success: self.success,
            message: self.message.clone(),
            deferred_to: self.deferred_to,
        }
    }

    /// The volumes a real run rebuilt; none for a dry run.
    pub fn restored_paths(&self) -> &[PathBuf] {
        self.report
            .as_ref()
            .map_or(&[], |report| report.restored_paths.as_slice())
    }
}

pub fn list_archive(
    cli: &Cli,
    archive: &Path,
    passwords: &mut PasswordResolver,
) -> Result<u8, RarparError> {
    let set = archive_set(cli, archive)?;
    let names = with_password_retry(&set, passwords, |archive| {
        Ok(archive
            .member_names()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>())
    })?;
    for name in names {
        println!("{name}");
    }
    Ok(EXIT_SUCCESS)
}

pub fn test_archive(
    cli: &Cli,
    archive: &Path,
    passwords: &mut PasswordResolver,
) -> Result<u8, RarparError> {
    let set = archive_set(cli, archive)?;
    let outcome = test_set(&set, passwords)?;
    Ok(if outcome.success {
        EXIT_SUCCESS
    } else {
        EXIT_DATA_FAILURE
    })
}

pub fn extract_set(
    cli: &Cli,
    set: &RarSet,
    output_dir: &Path,
    passwords: &mut PasswordResolver,
) -> Result<RarOutcome, RarparError> {
    if set.volumes.is_empty() {
        return Ok(RarOutcome {
            set_id: set.id.clone(),
            action_name: "rar_extract",
            success: true,
            message: "no RAR volumes found".to_string(),
        });
    }

    let started = std::time::Instant::now();
    if cli.dry_run {
        return Ok(RarOutcome {
            set_id: set.id.clone(),
            action_name: "rar_extract",
            success: true,
            message: format!("would extract {} volume(s)", set.volumes.len()),
        });
    }

    std::fs::create_dir_all(output_dir)?;
    with_password_retry(set, passwords, |mut archive| {
        // One metadata build per extraction: it walks every member and
        // allocates a name per entry, so the preflight reuses this list.
        let members = archive.metadata().members;
        preflight_outputs(&members, output_dir, cli.overwrite)?;
        for (index, member) in members.iter().enumerate() {
            let out_path = output_dir.join(&member.name);
            if !cli.json && !cli.quiet {
                println!(
                    "{}  {}",
                    if member.is_directory {
                        "Creating"
                    } else {
                        "Extracting"
                    },
                    member.name
                );
            }
            if member.is_directory {
                std::fs::create_dir_all(&out_path)?;
                continue;
            }
            archive.by_index(index)?.unpack_to(&out_path)?;
        }
        Ok(())
    })?;

    Ok(RarOutcome {
        set_id: set.id.clone(),
        action_name: "rar_extract",
        success: true,
        message: format!(
            "extracted {} volume(s) to {} in {:.2?}",
            set.volumes.len(),
            output_dir.display(),
            started.elapsed()
        ),
    })
}

pub fn restore_volumes(cli: &Cli, set: &RarSet) -> Result<RarRestoreOutcome, RarparError> {
    let paths = set.source_paths();
    restore_volume_paths_inner(&set.id, cli, &paths)
}

/// `auto --dry-run`'s restore step for `set`: its plan, judged as if the
/// parity repairs the real run makes first had rebuilt the volumes `cover`
/// names. An error from the planner is returned, not judged.
pub fn plan_restore(
    cli: &Cli,
    set: &RarSet,
    cover: &ParityCover,
) -> Result<RarRestoreOutcome, RarparError> {
    plan_restore_paths(&set.id, cli, &set.source_paths(), cover)
}

pub fn restore_volume_paths(cli: &Cli, paths: &[PathBuf]) -> Result<u8, RarparError> {
    let outcome = restore_volume_paths_inner("rar-restore", cli, paths)?;
    crate::report::emit_rar_restore(cli, &outcome)?;
    Ok(outcome.exit_code)
}

/// `rar test-volumes`: test exactly `paths` as recovery volumes, in order,
/// and fail unless every one tests OK. Nothing beside them is discovered, so
/// a set's missing `.rev` files go unreported unless they are named. A file
/// that cannot be read is a result of its own, `Unreadable`, and the other
/// paths are still tested.
pub fn test_volume_paths(cli: &Cli, paths: &[PathBuf]) -> Result<u8, RarparError> {
    let results = unrar_rs::test_recovery_volumes(paths)?;
    let success = results
        .iter()
        .all(|result| result.status == unrar_rs::RevTestStatus::Ok);
    crate::report::emit_rar_test_volumes(cli, success, &results)?;
    Ok(if success {
        EXIT_SUCCESS
    } else {
        EXIT_DATA_FAILURE
    })
}

pub fn open_set_with_password(
    set: &RarSet,
    password: Option<&str>,
) -> Result<unrar_rs::RarArchive, unrar_rs::RarError> {
    let mut paths = set
        .volumes
        .iter()
        .map(|volume| volume.path.clone())
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| {
        set.volumes
            .iter()
            .find(|volume| volume.path == *path)
            .map(|volume| volume.sort_index)
            .unwrap_or(usize::MAX)
    });
    open_paths_with_password(&paths, password)
}

fn open_paths_with_password(
    paths: &[PathBuf],
    password: Option<&str>,
) -> Result<unrar_rs::RarArchive, unrar_rs::RarError> {
    if paths.is_empty() {
        return Err(unrar_rs::RarError::CorruptArchive {
            detail: "no RAR volumes provided".to_string(),
        });
    }

    let first = File::open(&paths[0]).map_err(unrar_rs::RarError::Io)?;
    let mut archive = if let Some(password) = password {
        unrar_rs::RarArchive::open_with_password(first, password)?
    } else {
        unrar_rs::RarArchive::open(first)?
    };
    archive.set_limits(cli_extraction_limits());
    if let Some(password) = password {
        archive.set_password(password.to_string());
    }

    for (index, path) in paths.iter().enumerate().skip(1) {
        let file = File::open(path).map_err(unrar_rs::RarError::Io)?;
        archive.add_volume(index, Box::new(file) as Box<dyn unrar_rs::ReadSeek>)?;
    }
    Ok(archive)
}

pub fn test_set(set: &RarSet, passwords: &mut PasswordResolver) -> Result<RarOutcome, RarparError> {
    let started = std::time::Instant::now();
    with_password_retry(set, passwords, |mut archive| {
        let tempdir = tempfile::tempdir()?;
        let members = archive.metadata().members;
        for (index, member) in members.iter().enumerate() {
            let out_path = tempdir.path().join(&member.name);
            if member.is_directory {
                std::fs::create_dir_all(&out_path)?;
                continue;
            }
            archive.by_index(index)?.unpack_to(&out_path)?;
        }
        Ok(())
    })?;
    Ok(RarOutcome {
        set_id: set.id.clone(),
        action_name: "rar_test",
        success: true,
        message: format!("archive tested in {:.2?}", started.elapsed()),
    })
}

pub fn with_password_retry<T, F>(
    set: &RarSet,
    passwords: &mut PasswordResolver,
    mut operation: F,
) -> Result<T, RarparError>
where
    F: FnMut(unrar_rs::RarArchive) -> Result<T, RarparError>,
{
    let prompt_reason = match open_set_with_password(set, None) {
        Ok(archive) => match operation(archive) {
            Ok(value) => return Ok(value),
            Err(error) if is_password_error(&error) => Some(error.to_string()),
            Err(error) => return Err(error),
        },
        Err(error) if is_rar_password_error(&error) => Some(error.to_string()),
        Err(error) => return Err(error.into()),
    };

    let candidates = passwords.candidates_with_prompt("RAR password: ")?;
    if candidates.is_empty() {
        let reason = prompt_reason
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default();
        return Err(RarparError::Data(format!(
            "archive requires a password and no password source was available{reason}"
        )));
    }

    let mut last_error = None;
    for candidate in candidates {
        match open_set_with_password(set, Some(&candidate)) {
            Ok(archive) => match operation(archive) {
                Ok(value) => return Ok(value),
                Err(error) if is_password_error(&error) => last_error = Some(error),
                Err(error) => return Err(error),
            },
            Err(error) if is_rar_password_error(&error) => last_error = Some(error.into()),
            Err(error) => return Err(error.into()),
        }
    }

    Err(last_error.unwrap_or_else(|| RarparError::Data("invalid password".to_string())))
}

fn restore_volume_paths_inner(
    set_id: &str,
    cli: &Cli,
    paths: &[PathBuf],
) -> Result<RarRestoreOutcome, RarparError> {
    if paths.is_empty() {
        return Ok(RarRestoreOutcome {
            set_id: set_id.to_string(),
            dry_run: cli.dry_run,
            success: true,
            exit_code: EXIT_SUCCESS,
            message: "no recovery paths found".to_string(),
            deferred_to: None,
            plan: None,
            report: None,
        });
    }
    if cli.dry_run {
        return plan_restore_paths(set_id, cli, paths, &ParityCover::default());
    }
    let report = unrar_rs::restore_volumes_from_paths(paths, &recovery_options(cli))?;
    Ok(RarRestoreOutcome {
        set_id: set_id.to_string(),
        dry_run: false,
        success: true,
        exit_code: EXIT_SUCCESS,
        message: report_message(&report),
        deferred_to: None,
        plan: None,
        report: Some(report),
    })
}

fn plan_restore_paths(
    set_id: &str,
    cli: &Cli,
    paths: &[PathBuf],
    cover: &ParityCover,
) -> Result<RarRestoreOutcome, RarparError> {
    let plan = unrar_rs::plan_volume_restore(paths, &recovery_options(cli))?;
    Ok(judge_plan(set_id, cli.overwrite, plan, cover))
}

/// The options a restore runs with. A dry run plans with the same ones, so
/// its plan names the output and `.bad` paths the restore would use. Whether
/// a file already at one of them would stop the restore the plan does not
/// say; [`foreseen_refusal`] checks that.
fn recovery_options(cli: &Cli) -> unrar_rs::RecoveryOptions {
    unrar_rs::RecoveryOptions {
        output_dir: cli.output.clone(),
        overwrite_existing: cli.overwrite,
        verify_restored: true,
    }
}

/// What a restore with nothing to rebuild reports, dry run or not. The real
/// run's report does not count the set's data volumes, so neither does this.
const NOTHING_TO_RESTORE: &str = "nothing to restore: all data volumes valid";

/// The data volume names that the parity sets `auto` repairs before its RAR
/// restore protect: those of each PAR2 set related to the RAR set and of
/// each PAR3 set the run repairs. A dry run cannot run those repairs, so it
/// counts a damaged or missing volume whose file name one of them lists
/// exactly as rebuilt by then.
#[derive(Debug, Default)]
pub struct ParityCover {
    pub par2: BTreeSet<String>,
    pub par3: BTreeSet<String>,
}

impl ParityCover {
    /// Whether a PAR2 set, and whether a PAR3 set, lists the file name
    /// `volume` is restored to.
    fn lists(&self, volume: &unrar_rs::DataVolumePlan) -> (bool, bool) {
        match volume
            .output_path
            .file_name()
            .and_then(|name| name.to_str())
        {
            Some(name) => (self.par2.contains(name), self.par3.contains(name)),
            None => (false, false),
        }
    }

    fn covers(&self, volume: &unrar_rs::DataVolumePlan) -> bool {
        let (par2, par3) = self.lists(volume);
        par2 || par3
    }

    /// How [`ExecutedAction::deferred_to`] names the parity that rebuilds
    /// `covered`, and how the message says it, PAR3 first as the real run
    /// repairs.
    fn deferral(&self, covered: &[&unrar_rs::DataVolumePlan]) -> (&'static str, &'static str) {
        let par2 = covered.iter().any(|volume| self.lists(volume).0);
        let par3 = covered.iter().any(|volume| self.lists(volume).1);
        match (par2, par3) {
            (true, true) => ("par2+par3", "PAR3 and PAR2 repairs run"),
            (false, true) => ("par3", "PAR3 repair runs"),
            (true, false) | (false, false) => ("par2", "PAR2 repair runs"),
        }
    }
}

/// How a restore would end: the exit code and message of its outcome.
struct Verdict {
    exit_code: u8,
    message: String,
}

impl Verdict {
    fn passes(&self) -> bool {
        self.exit_code == EXIT_SUCCESS
    }
}

/// Judges a dry run's plan. A restore that would stop by itself is deferred,
/// and passes, when the volumes `cover` lists are rebuilt first and the rest
/// fit within the usable recovery volumes with no file in their way. Whether
/// the parity holds enough recovery data for the volumes it lists is not
/// checked.
fn judge_plan(
    set_id: &str,
    overwrite: bool,
    plan: unrar_rs::RestorePlan,
    cover: &ParityCover,
) -> RarRestoreOutcome {
    let rebuild = plan
        .data_volumes
        .iter()
        .filter(|volume| volume.status != unrar_rs::DataVolumeStatus::Valid)
        .collect::<Vec<_>>();
    let alone = verdict(&plan, overwrite, &rebuild);
    let (covered, uncovered): (Vec<_>, Vec<_>) = rebuild
        .iter()
        .copied()
        .partition(|volume| cover.covers(volume));
    let (judged, deferred_to) = if alone.passes() || covered.is_empty() {
        (alone, None)
    } else {
        let (kind, repairs) = cover.deferral(&covered);
        let first = format!(
            "; {repairs} first for {}",
            file_names(covered.iter().map(|volume| volume.output_path.as_path()))
        );
        let after = verdict(&plan, overwrite, &uncovered);
        if after.passes() {
            let message = alone.message + &first;
            (
                Verdict {
                    exit_code: EXIT_SUCCESS,
                    message,
                },
                Some(kind),
            )
        } else {
            let message = after.message + &first;
            (
                Verdict {
                    exit_code: after.exit_code,
                    message,
                },
                None,
            )
        }
    };
    RarRestoreOutcome {
        set_id: set_id.to_string(),
        dry_run: true,
        success: judged.passes(),
        exit_code: judged.exit_code,
        message: judged.message,
        deferred_to,
        plan: Some(plan),
        report: None,
    }
}

/// What restoring `rebuild` would do: nothing, rebuild it, or stop as the
/// real restore stops, short of recovery volumes or refusing a file in its
/// way, with the exit code the real run's error maps to.
fn verdict(
    plan: &unrar_rs::RestorePlan,
    overwrite: bool,
    rebuild: &[&unrar_rs::DataVolumePlan],
) -> Verdict {
    if rebuild.is_empty() {
        return Verdict {
            exit_code: EXIT_SUCCESS,
            message: NOTHING_TO_RESTORE.to_string(),
        };
    }
    let names = file_names(rebuild.iter().map(|volume| volume.output_path.as_path()));
    let needed = rebuild.len();
    let usable = plan.usable_recovery_count();
    if needed > usable {
        return Verdict {
            exit_code: EXIT_DATA_FAILURE,
            message: format!(
                "insufficient recovery volumes: need {needed}, have {usable} for {names}"
            ),
        };
    }
    if !overwrite && let Some(refusal) = foreseen_refusal(rebuild) {
        return refusal;
    }
    let mut message = format!(
        "would restore {needed} volume(s) ({names}) using {needed} of {usable} usable recovery volume(s)"
    );
    let set_aside = rebuild
        .iter()
        .filter(|volume| volume.set_aside_path.is_some())
        .count();
    if set_aside > 0 {
        message.push_str(&format!(
            "; would set aside {set_aside} damaged volume(s) as .bad"
        ));
    }
    Verdict {
        exit_code: EXIT_SUCCESS,
        message,
    }
}

/// The refusal a restore without `--overwrite` would stop on, which the
/// library's plan does not foresee, with the real run's wording and exit
/// code. The restore sets every damaged volume aside before it checks any
/// output path, so an existing `.bad` backup is met first. An output path
/// that exists is refused unless it holds the damaged volume being set
/// aside, which is gone from it by then.
fn foreseen_refusal(rebuild: &[&unrar_rs::DataVolumePlan]) -> Option<Verdict> {
    for volume in rebuild {
        if let Some(backup) = &volume.set_aside_path
            && backup.exists()
        {
            let message = format!(
                "refusing to overwrite existing bad-volume backup {}",
                backup.display()
            );
            let error = std::io::Error::new(std::io::ErrorKind::AlreadyExists, message.clone());
            return Some(refusal(unrar_rs::RarError::Io(error), message));
        }
    }
    for volume in rebuild {
        if volume.set_aside_path.is_none() && volume.output_path.exists() {
            let detail = format!(
                "refusing to overwrite existing restored volume {}",
                volume.output_path.display()
            );
            return Some(refusal(
                unrar_rs::RarError::CorruptArchive {
                    detail: detail.clone(),
                },
                detail,
            ));
        }
    }
    None
}

/// A foreseen refusal: `message`, with the exit code `main` gives the error
/// the real run raises.
fn refusal(error: unrar_rs::RarError, message: String) -> Verdict {
    Verdict {
        exit_code: RarparError::from(error).exit_code(),
        message,
    }
}

/// A real run's result. `used_recovery_paths` is every valid recovery volume
/// the restore read, which can be more than it needed.
fn report_message(report: &unrar_rs::RecoveryReport) -> String {
    if report.restored_paths.is_empty() {
        return NOTHING_TO_RESTORE.to_string();
    }
    format!(
        "restored {} volume(s) ({}) from {} recovery volume(s) read",
        report.restored_paths.len(),
        file_names(report.restored_paths.iter().map(PathBuf::as_path)),
        report.used_recovery_paths.len()
    )
}

/// The file names of `paths`, comma separated, for a message; a path with no
/// file name is shown whole.
fn file_names<'a>(paths: impl Iterator<Item = &'a Path>) -> String {
    paths
        .map(|path| match path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => path.display().to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn preflight_outputs(
    members: &[unrar_rs::MemberInfo],
    output_dir: &Path,
    overwrite: bool,
) -> Result<(), RarparError> {
    if overwrite {
        return Ok(());
    }
    for member in members {
        let path = output_dir.join(&member.name);
        if member.is_directory {
            if path.exists() && !path.is_dir() {
                return Err(RarparError::Unsafe(format!(
                    "output directory path exists and is not a directory: {}",
                    path.display()
                )));
            }
            continue;
        }
        if path.exists() {
            return Err(RarparError::Unsafe(format!(
                "output path exists; pass --overwrite to replace: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// The whole volume set `archive` belongs to, found the way `rar extract`
/// finds it, so `list` and `test` read every member a later volume carries
/// and every member split across volumes in full instead of stopping at the
/// end of the volume named on the command line.
fn archive_set(cli: &Cli, archive: &Path) -> Result<RarSet, RarparError> {
    crate::discovery::discover_rar_set_for_archive(
        archive,
        &crate::discovery::DiscoveryOptions::from_cli(cli),
    )
}

/// Resource limits the CLI applies to every archive it opens.
///
/// The library default caps dictionaries at 256 MiB, which is the right
/// conservative ceiling for an embedder that has not thought about memory. As a
/// tool, rarpar has to match what `unrar 7.20` extracts, and unrar accepts any
/// dictionary the format allows (`UNPACK_MAX_DICT`) unless `-md` narrows it —
/// so the CLI raises the cap to the format ceiling and leaves the library
/// default alone.
pub fn cli_extraction_limits() -> unrar_rs::Limits {
    unrar_rs::Limits {
        max_dict_size: unrar_rs::limits::RAR_UNPACK_MAX_DICT_SIZE,
        ..unrar_rs::Limits::default()
    }
}

fn is_password_error(error: &RarparError) -> bool {
    match error {
        RarparError::Rar(error) => is_rar_password_error(error),
        _ => false,
    }
}

fn is_rar_password_error(error: &unrar_rs::RarError) -> bool {
    matches!(
        error,
        unrar_rs::RarError::EncryptedArchive
            | unrar_rs::RarError::EncryptedMember { .. }
            | unrar_rs::RarError::InvalidPassword
            | unrar_rs::RarError::WrongPassword { .. }
    )
}
