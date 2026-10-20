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

/// `auto --dry-run`'s restore step for a set with no `.rev` file on disk
/// whose `.rev` files `cover` lists: the real run repairs the parity, finds
/// them beside the set and restores with them, so the step is deferred to
/// that repair, with no plan, as there is nothing yet to plan from.
pub fn defer_restore_to_parity(set_id: &str, cover: &ParityCover) -> RarRestoreOutcome {
    let rebuilt = cover
        .recovery_volumes
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    let (kind, repairs) = cover.deferral(&rebuilt);
    RarRestoreOutcome {
        set_id: set_id.to_string(),
        dry_run: true,
        success: true,
        exit_code: EXIT_SUCCESS,
        message: format!(
            "no recovery volumes present to plan with; {repairs} first for {}",
            file_names(rebuilt.iter().copied())
        ),
        deferred_to: Some(kind),
        plan: None,
        report: None,
    }
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

/// The files that the parity sets `auto` repairs before its RAR restore
/// protect: those of each PAR2 set related to the RAR set and of each PAR3
/// set the run repairs, each resolved against its set's directory. A dry
/// run cannot run those repairs, so it counts a damaged or missing volume
/// whose output path one of them lists as rebuilt by then, and a `.rev`
/// file of the set one lists among the usable recovery volumes by then. A
/// set under another directory that lists the same file name does not
/// count; one that lists the name in another case counts where the
/// directory folds case, as [`same_file`] decides.
#[derive(Debug, Default)]
pub struct ParityCover {
    pub par2: BTreeSet<PathBuf>,
    pub par3: BTreeSet<PathBuf>,
    /// The `.rev` files of the RAR set among `par2` and `par3`, present or
    /// not, as [`crate::discovery::recovery_volume_of`] picks them.
    pub recovery_volumes: BTreeSet<PathBuf>,
}

impl ParityCover {
    /// Whether a PAR2 set, and whether a PAR3 set, lists `output`, the path
    /// a volume is restored to.
    fn lists(&self, output: &Path) -> (bool, bool) {
        let listed = |paths: &BTreeSet<PathBuf>| paths.iter().any(|path| same_file(path, output));
        (listed(&self.par2), listed(&self.par3))
    }

    fn covers(&self, volume: &unrar_rs::DataVolumePlan) -> bool {
        let (par2, par3) = self.lists(&volume.output_path);
        par2 || par3
    }

    /// The `.rev` files of the set the parity rebuilds before the restore:
    /// the listed ones at which `plan` found no usable recovery volume,
    /// missing or passed over. Each adds one usable volume by then; which
    /// slot a missing file fills, its name does not say for certain, so the
    /// count is capped at the set's recovery volumes.
    fn rebuilt_recovery_volumes(&self, plan: &unrar_rs::RestorePlan) -> Vec<&Path> {
        self.recovery_volumes
            .iter()
            .map(PathBuf::as_path)
            .filter(|listed| {
                !plan
                    .recovery_volumes
                    .iter()
                    .any(|volume| volume.usable && same_file(&volume.path, listed))
            })
            .collect()
    }

    /// How [`ExecutedAction::deferred_to`] names the parity that rebuilds
    /// the files at `rebuilt`, and how the message says it, PAR3 first as
    /// the real run repairs.
    fn deferral(&self, rebuilt: &[&Path]) -> (&'static str, &'static str) {
        let par2 = rebuilt.iter().any(|path| self.lists(path).0);
        let par3 = rebuilt.iter().any(|path| self.lists(path).1);
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
/// fit within the usable recovery volumes, counting the `.rev` files it
/// lists, with no file in their way. Whether the parity holds enough
/// recovery data for the files it lists is not checked.
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
    let usable = plan.usable_recovery_count();
    let alone = verdict(overwrite, &rebuild, usable);
    let (covered, uncovered): (Vec<_>, Vec<_>) = rebuild
        .iter()
        .copied()
        .partition(|volume| cover.covers(volume));
    let rebuilt_revs = cover.rebuilt_recovery_volumes(&plan);
    let (judged, deferred_to) = if alone.passes() || (covered.is_empty() && rebuilt_revs.is_empty())
    {
        (alone, None)
    } else {
        let rebuilt = covered
            .iter()
            .map(|volume| volume.output_path.as_path())
            .chain(rebuilt_revs.iter().copied())
            .collect::<Vec<_>>();
        let (kind, repairs) = cover.deferral(&rebuilt);
        let first = format!(
            "; {repairs} first for {}",
            file_names(rebuilt.iter().copied())
        );
        let usable_after = usable.max((usable + rebuilt_revs.len()).min(plan.recovery_count));
        let after = verdict(overwrite, &uncovered, usable_after);
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

/// What restoring `rebuild` with `usable` recovery volumes would do:
/// nothing, rebuild it, or stop as the real restore stops, short of
/// recovery volumes or refusing a file in its way, with the exit code the
/// real run's error maps to.
fn verdict(overwrite: bool, rebuild: &[&unrar_rs::DataVolumePlan], usable: usize) -> Verdict {
    if rebuild.is_empty() {
        return Verdict {
            exit_code: EXIT_SUCCESS,
            message: NOTHING_TO_RESTORE.to_string(),
        };
    }
    let names = file_names(rebuild.iter().map(|volume| volume.output_path.as_path()));
    let needed = rebuild.len();
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

/// Whether `left` and `right` name the same file: the same path, or under
/// the same directory the same file name, or one differing from it by case
/// alone where that directory folds case, as
/// [`crate::discovery::same_name_on_disk`] probes it, so that a parity set
/// listing `SET.part05.rar` rebuilds `set.part05.rar` on a volume that
/// ignores case and not on one that keeps it. The file need not exist, as
/// a missing volume's output does not.
fn same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let (Some(left_dir), Some(right_dir)) = (left.parent(), right.parent()) else {
        return false;
    };
    let (Some(left_name), Some(right_name)) = (left.file_name(), right.file_name()) else {
        return false;
    };
    if left_name == right_name {
        return crate::discovery::same_path(left_dir, right_dir);
    }
    let (Some(left_str), Some(right_str)) = (left_name.to_str(), right_name.to_str()) else {
        return false;
    };
    crate::par3_inside::fold_case(left_str) == crate::par3_inside::fold_case(right_str)
        && crate::discovery::same_path(left_dir, right_dir)
        && crate::discovery::same_name_on_disk(left, &left_dir.join(right_name))
}

/// Whether a directory entry holds `path`'s name, as the restore's exclusive
/// create and hard link see it: a symlink counts, even one that points
/// nowhere, which [`Path::exists`] would follow and deny.
fn name_taken(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
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
            && name_taken(backup)
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
        if volume.set_aside_path.is_none() && name_taken(&volume.output_path) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A parity set covers a volume it lists at the volume's own path,
    /// however that path is spelled, and not a volume of the same name under
    /// another directory.
    #[test]
    fn parity_cover_lists_a_volume_by_its_path_not_its_name() {
        let temp = tempfile::tempdir().unwrap();
        let here = temp.path().join("here");
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir_all(&here).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let cover = ParityCover {
            par2: BTreeSet::from([here.join("set.part05.rar")]),
            par3: BTreeSet::from([elsewhere.join("set.part05.rar")]),
            recovery_volumes: BTreeSet::new(),
        };

        assert_eq!(cover.lists(&here.join("set.part05.rar")), (true, false));
        assert_eq!(
            cover.lists(&elsewhere.join("set.part05.rar")),
            (false, true)
        );
        assert_eq!(cover.lists(&here.join("set.part06.rar")), (false, false));
        assert_eq!(
            cover.lists(&temp.path().join("set.part05.rar")),
            (false, false)
        );
        #[cfg(unix)]
        {
            let link = temp.path().join("link");
            std::os::unix::fs::symlink(&here, &link).unwrap();
            assert_eq!(cover.lists(&link.join("set.part05.rar")), (true, false));
        }
    }

    /// A parity set that lists a volume's name in another case covers the
    /// volume exactly where its directory folds case: probed on the
    /// directory's entries for a missing volume, on the files themselves
    /// for a present one. A directory with nothing to probe keeps the
    /// spellings apart, and a name differing by more than case never
    /// matches.
    #[test]
    fn parity_cover_compares_names_as_the_directory_does() {
        let temp = tempfile::tempdir().unwrap();
        let here = temp.path().join("here");
        std::fs::create_dir_all(&here).unwrap();
        let cover = ParityCover {
            par2: BTreeSet::from([here.join("SET.part05.rar")]),
            par3: BTreeSet::new(),
            recovery_volumes: BTreeSet::new(),
        };
        let volume = here.join("set.part05.rar");
        assert_eq!(cover.lists(&volume), (false, false));

        std::fs::write(here.join("set.part01.rar"), b"volume").unwrap();
        let folds = std::fs::metadata(here.join("SET.PART01.RAR")).is_ok();
        assert_eq!(cover.lists(&volume), (folds, false));
        assert_eq!(cover.lists(&here.join("set.part06.rar")), (false, false));
        assert_eq!(cover.lists(&here.join("SET.part05.rar")), (true, false));

        std::fs::write(&volume, b"damaged").unwrap();
        assert_eq!(cover.lists(&volume), (folds, false));
        if !folds {
            std::fs::write(here.join("SET.part05.rar"), b"other").unwrap();
            assert_eq!(cover.lists(&volume), (false, false));
        }
    }
}
