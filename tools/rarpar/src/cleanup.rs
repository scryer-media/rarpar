use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::Cli;
use crate::discovery::{Par2Set, RarSet, related_par2_sets};
use crate::error::RarparError;
use crate::password::PasswordResolver;

#[derive(Debug, Clone, Serialize)]
pub struct CleanupManifest {
    pub candidates: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupResult {
    pub success: bool,
    pub permanent: bool,
    pub candidates: Vec<PathBuf>,
    pub message: String,
}

pub fn manifest_for_rar_set(rar: &RarSet, par2_sets: &[Par2Set]) -> CleanupManifest {
    let mut candidates = rar.source_paths();
    for par in related_par2_sets(rar, par2_sets) {
        candidates.extend(par.paths.clone());
    }
    candidates.sort();
    candidates.dedup();
    CleanupManifest { candidates }
}

pub fn validate_extracted_outputs(
    rar: &RarSet,
    output_dir: &Path,
    passwords: &mut PasswordResolver,
) -> Result<(), RarparError> {
    crate::rar::with_password_retry(rar, passwords, |mut archive| {
        let tempdir = tempfile::tempdir()?;
        let options = weaver_unrar::ExtractOptions {
            verify: true,
            password: None,
            restore_owners: false,
        };
        let members = archive.metadata().members;
        for (index, member) in members.iter().enumerate() {
            let output_path = output_dir.join(&member.name);
            let metadata = std::fs::symlink_metadata(&output_path).map_err(|error| {
                RarparError::Data(format!(
                    "expected extracted output {} is unavailable: {error}",
                    output_path.display()
                ))
            })?;

            if member.is_directory {
                if !metadata.is_dir() {
                    return Err(RarparError::Data(format!(
                        "expected extracted directory is not a directory: {}",
                        output_path.display()
                    )));
                }
                continue;
            }

            if member.is_symlink {
                if !metadata.file_type().is_symlink() {
                    return Err(RarparError::Data(format!(
                        "expected extracted symlink is not a symlink: {}",
                        output_path.display()
                    )));
                }
                if let Some(target) = &member.link_target {
                    let actual = std::fs::read_link(&output_path)?;
                    if actual != Path::new(target) {
                        return Err(RarparError::Data(format!(
                            "extracted symlink target mismatch for {}: expected {}, got {}",
                            output_path.display(),
                            target,
                            actual.display()
                        )));
                    }
                }
                continue;
            }

            if member.is_hardlink || member.is_file_copy {
                if !metadata.is_file() {
                    return Err(RarparError::Data(format!(
                        "expected extracted link/file-copy is not a regular file: {}",
                        output_path.display()
                    )));
                }
                continue;
            }

            if !metadata.is_file() {
                return Err(RarparError::Data(format!(
                    "expected extracted file is not a regular file: {}",
                    output_path.display()
                )));
            }
            if let Some(size) = member.unpacked_size
                && metadata.len() != size
            {
                return Err(RarparError::Data(format!(
                    "extracted file size mismatch for {}: expected {}, got {}",
                    output_path.display(),
                    size,
                    metadata.len()
                )));
            }

            let expected_path = tempdir.path().join(format!("member-{index}"));
            archive.extract_member_to_file(index, &options, None, &expected_path)?;
            if !files_equal(&expected_path, &output_path)? {
                return Err(RarparError::Data(format!(
                    "extracted file content mismatch for {}",
                    output_path.display()
                )));
            }
        }
        Ok(())
    })
}

pub fn delete_manifest(
    cli: &Cli,
    manifest: &CleanupManifest,
) -> Result<CleanupResult, RarparError> {
    if manifest.candidates.is_empty() {
        return Ok(CleanupResult {
            success: true,
            permanent: cli.permanent_delete,
            candidates: Vec::new(),
            message: "no cleanup candidates".to_string(),
        });
    }

    for path in &manifest.candidates {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            RarparError::Unsafe(format!(
                "cleanup candidate cannot be inspected before deletion: {} ({error})",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(RarparError::Unsafe(format!(
                "cleanup candidate is not a file: {}",
                path.display()
            )));
        }
    }

    if cli.dry_run {
        return Ok(CleanupResult {
            success: true,
            permanent: cli.permanent_delete,
            candidates: manifest.candidates.clone(),
            message: "dry-run: no files deleted".to_string(),
        });
    }

    if cli.permanent_delete {
        for path in &manifest.candidates {
            std::fs::remove_file(path)?;
        }
        return Ok(CleanupResult {
            success: true,
            permanent: true,
            candidates: manifest.candidates.clone(),
            message: "deleted source files permanently".to_string(),
        });
    }

    move_to_trash(&manifest.candidates)?;
    Ok(CleanupResult {
        success: true,
        permanent: false,
        candidates: manifest.candidates.clone(),
        message: "moved source files to trash".to_string(),
    })
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, RarparError> {
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];
    loop {
        let left_read = left.read(&mut left_buf)?;
        let right_read = right.read(&mut right_buf)?;
        if left_read != right_read {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
        if left_buf[..left_read] != right_buf[..right_read] {
            return Ok(false);
        }
    }
}

fn move_to_trash(paths: &[PathBuf]) -> Result<(), RarparError> {
    let trash_dir = trash_dir().ok_or_else(|| {
        RarparError::Unsafe(
            "OS trash is unavailable; pass --permanent-delete to delete irreversibly".to_string(),
        )
    })?;
    std::fs::create_dir_all(&trash_dir).map_err(|error| {
        RarparError::Unsafe(format!(
            "OS trash is unavailable at {}: {error}",
            trash_dir.display()
        ))
    })?;

    let mut moves = Vec::new();
    for path in paths {
        let dest = unique_trash_path(&trash_dir, path)?;
        moves.push((path.clone(), dest));
    }

    for (source, dest) in moves {
        std::fs::rename(&source, &dest).map_err(|error| {
            RarparError::Unsafe(format!(
                "failed to move {} to trash: {error}; no further files were moved",
                source.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn trash_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".Trash"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn trash_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .map(|base| base.join("Trash/files"))
}

#[cfg(not(unix))]
fn trash_dir() -> Option<PathBuf> {
    None
}

fn unique_trash_path(trash_dir: &Path, source: &Path) -> Result<PathBuf, RarparError> {
    let file_name = source.file_name().ok_or_else(|| {
        RarparError::Unsafe(format!(
            "cleanup candidate has no file name: {}",
            source.display()
        ))
    })?;
    let base = file_name.to_string_lossy();
    for index in 0..10_000 {
        let name = if index == 0 {
            base.to_string()
        } else {
            format!("{base}.{index}")
        };
        let candidate = trash_dir.join(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(RarparError::Unsafe(format!(
        "could not allocate a unique trash path for {}",
        source.display()
    )))
}
