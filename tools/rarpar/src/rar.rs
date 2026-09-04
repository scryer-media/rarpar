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
        }
    }
}

pub struct RarRestoreOutcome {
    pub set_id: String,
    pub success: bool,
    pub message: String,
    pub restored_paths: Vec<PathBuf>,
}

impl RarRestoreOutcome {
    pub fn action(&self) -> ExecutedAction {
        ExecutedAction {
            set_id: self.set_id.clone(),
            action: "rar_restore_volumes".to_string(),
            success: self.success,
            message: self.message.clone(),
        }
    }
}

pub fn list_archive(archive: &Path, passwords: &mut PasswordResolver) -> Result<u8, RarparError> {
    let set = single_archive_set(archive)?;
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
    _cli: &Cli,
    archive: &Path,
    passwords: &mut PasswordResolver,
) -> Result<u8, RarparError> {
    let set = single_archive_set(archive)?;
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

pub fn restore_volume_paths(cli: &Cli, paths: &[PathBuf]) -> Result<u8, RarparError> {
    let outcome = restore_volume_paths_inner("rar-restore", cli, paths)?;
    Ok(if outcome.success {
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
            success: true,
            message: "no recovery paths found".to_string(),
            restored_paths: Vec::new(),
        });
    }
    if cli.dry_run {
        return Ok(RarRestoreOutcome {
            set_id: set_id.to_string(),
            success: true,
            message: format!("would restore using {} path(s)", paths.len()),
            restored_paths: Vec::new(),
        });
    }
    let options = unrar_rs::RecoveryOptions {
        output_dir: cli.output.clone(),
        overwrite_existing: cli.overwrite,
        verify_restored: true,
    };
    let report = unrar_rs::restore_volumes_from_paths(paths, &options)?;
    Ok(RarRestoreOutcome {
        set_id: set_id.to_string(),
        success: true,
        message: format!(
            "restored {} volume(s); missing volume numbers before restore: {:?}",
            report.restored_paths.len(),
            report.missing_volume_numbers
        ),
        restored_paths: report.restored_paths,
    })
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

fn single_archive_set(archive: &Path) -> Result<RarSet, RarparError> {
    if !archive.exists() {
        return Err(RarparError::MissingInput(archive.to_path_buf()));
    }
    Ok(RarSet {
        id: format!("rar:{}", archive.display()),
        label: archive
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("archive")
            .to_string(),
        base_dir: archive
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        volumes: vec![crate::discovery::RarVolume {
            path: archive.to_path_buf(),
            volume_number: Some(0),
            sort_index: 0,
            is_first_volume: true,
        }],
        recovery_volumes: Vec::new(),
    })
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
