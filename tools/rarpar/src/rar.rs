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
        preflight_outputs(&archive, output_dir, cli.overwrite)?;
        let options = extract_options(archive_password(&archive));
        let members = archive.metadata().members;
        for (index, member) in members.iter().enumerate() {
            let out_path = output_dir.join(&member.name);
            if !cli.json {
                println!("Extracting  {}", member.name);
            }
            archive.extract_member_to_file(index, &options, None, &out_path)?;
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
) -> Result<weaver_unrar::RarArchive, weaver_unrar::RarError> {
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
) -> Result<weaver_unrar::RarArchive, weaver_unrar::RarError> {
    if paths.is_empty() {
        return Err(weaver_unrar::RarError::CorruptArchive {
            detail: "no RAR volumes provided".to_string(),
        });
    }

    let first = File::open(&paths[0]).map_err(weaver_unrar::RarError::Io)?;
    let mut archive = if let Some(password) = password {
        weaver_unrar::RarArchive::open_with_password(first, password)?
    } else {
        weaver_unrar::RarArchive::open(first)?
    };
    if let Some(password) = password {
        archive.set_password(password.to_string());
    }

    for (index, path) in paths.iter().enumerate().skip(1) {
        let file = File::open(path).map_err(weaver_unrar::RarError::Io)?;
        archive.add_volume(index, Box::new(file) as Box<dyn weaver_unrar::ReadSeek>)?;
    }
    Ok(archive)
}

pub fn test_set(set: &RarSet, passwords: &mut PasswordResolver) -> Result<RarOutcome, RarparError> {
    let started = std::time::Instant::now();
    with_password_retry(set, passwords, |mut archive| {
        let tempdir = tempfile::tempdir()?;
        let options = extract_options(archive_password(&archive));
        let members = archive.metadata().members;
        for (index, member) in members.iter().enumerate() {
            let out_path = tempdir.path().join(&member.name);
            archive.extract_member_to_file(index, &options, None, &out_path)?;
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
    F: FnMut(weaver_unrar::RarArchive) -> Result<T, RarparError>,
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
    let options = weaver_unrar::RecoveryOptions {
        output_dir: cli.output.clone(),
        overwrite_existing: cli.overwrite,
        verify_restored: true,
    };
    let report = weaver_unrar::restore_volumes_from_paths(paths, &options)?;
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
    archive: &weaver_unrar::RarArchive,
    output_dir: &Path,
    overwrite: bool,
) -> Result<(), RarparError> {
    if overwrite {
        return Ok(());
    }
    for member in archive.metadata().members {
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

fn extract_options(password: Option<String>) -> weaver_unrar::ExtractOptions {
    weaver_unrar::ExtractOptions {
        verify: true,
        password,
        restore_owners: false,
    }
}

fn archive_password(_archive: &weaver_unrar::RarArchive) -> Option<String> {
    None
}

fn is_password_error(error: &RarparError) -> bool {
    match error {
        RarparError::Rar(error) => is_rar_password_error(error),
        _ => false,
    }
}

fn is_rar_password_error(error: &weaver_unrar::RarError) -> bool {
    matches!(
        error,
        weaver_unrar::RarError::EncryptedArchive
            | weaver_unrar::RarError::EncryptedMember { .. }
            | weaver_unrar::RarError::InvalidPassword
            | weaver_unrar::RarError::WrongPassword { .. }
    )
}
