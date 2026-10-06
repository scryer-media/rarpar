//! WASI repair staging under the runtime's preopened-directory capability.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{File as StdFile, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_normalization::UnicodeNormalization;

use crate::runtime::{EngineError, EngineFile, EngineResult, ExecutionOptions};
use crate::session_repair::RepairDurability;

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Destination {
    pub(crate) relative: PathBuf,
    pub(crate) display: PathBuf,
}

pub(crate) struct RepairTree {
    base: PathBuf,
    stage_component: OsString,
    stage: PathBuf,
}

impl RepairTree {
    pub(crate) fn new<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
    ) -> io::Result<Self> {
        let reserved: HashSet<String> = protected_paths
            .into_iter()
            .filter_map(|path| path.split('/').next())
            .map(canonical_key)
            .collect();
        for _ in 0..128 {
            let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = format!(".par3-stage-{sequence}");
            if reserved.contains(&canonical_key(&candidate)) {
                continue;
            }
            let stage = base.join(&candidate);
            match std::fs::create_dir(&stage) {
                Ok(()) => {
                    return Ok(Self {
                        base: base.to_owned(),
                        stage_component: candidate.into(),
                        stage,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "repair staging directory names exhausted",
        ))
    }

    pub(crate) fn new_budgeted<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
        _options: &ExecutionOptions,
    ) -> io::Result<Self> {
        Self::new(base, protected_paths)
    }

    pub(crate) fn sanitize_temporary_outputs(&self, _outputs: &mut Vec<PathBuf>) -> io::Result<()> {
        // WASI paths are resolved within the runtime's preopened capability.
        Ok(())
    }

    pub(crate) fn destination(&self, relative: &str) -> io::Result<Destination> {
        let destination = self.unresolved_destination(relative)?;
        let _ = relative_parent(&self.base, &destination.relative, true)?;
        Ok(destination)
    }

    pub(crate) fn unresolved_destination(&self, relative: &str) -> io::Result<Destination> {
        crate::paths::validate_relative_path(relative)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let relative = PathBuf::from(relative);
        Ok(Destination {
            display: self.base.join(&relative),
            relative,
        })
    }

    pub(crate) fn check_existing_destination(&self, destination: &Destination) -> io::Result<()> {
        check_existing_destination(&self.base, &destination.relative)
    }

    #[cfg(test)]
    pub(crate) fn create_stage(
        &self,
        index: usize,
        len: u64,
        options: &ExecutionOptions,
    ) -> EngineResult<(OsString, PathBuf)> {
        self.create_stage_registered(index, len, options, &mut Vec::new())
    }

    pub(crate) fn create_stage_registered(
        &self,
        index: usize,
        len: u64,
        options: &ExecutionOptions,
        outputs: &mut Vec<PathBuf>,
    ) -> EngineResult<(OsString, PathBuf)> {
        let name = format!(".par3-repair-{index}.tmp");
        let display = self.stage.join(&name);
        let file = EngineFile::open_with(options, || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&display)
        })?;
        outputs.push(display.clone());
        if let Err(error) = file.set_len(len) {
            drop(file);
            if std::fs::remove_file(&display).is_ok() {
                outputs.retain(|path| path != &display);
            }
            return Err(error.into());
        }
        Ok((name.into(), display))
    }

    /// WASI has no file clones; every output is created and written.
    pub(crate) fn create_stage_from(
        &self,
        index: usize,
        len: u64,
        options: &ExecutionOptions,
        outputs: &mut Vec<PathBuf>,
        _clone_from: Option<(&Destination, crate::source::SourceSnapshot)>,
    ) -> EngineResult<(OsString, PathBuf, bool)> {
        let (name, display) = self.create_stage_registered(index, len, options, outputs)?;
        Ok((name, display, false))
    }

    pub(crate) fn create_stage_file(
        &self,
        index: usize,
    ) -> io::Result<(OsString, PathBuf, StdFile)> {
        let name = format!(".par3-repair-{index}.tmp");
        let display = self.stage.join(&name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&display)?;
        Ok((name.into(), display, file))
    }

    pub(crate) fn open_stage(
        &self,
        name: &OsStr,
        read: bool,
        write: bool,
        options: &ExecutionOptions,
    ) -> EngineResult<EngineFile> {
        EngineFile::open_with(options, || {
            OpenOptions::new()
                .read(read)
                .write(write)
                .open(self.stage.join(name))
        })
    }

    pub(crate) fn open_stage_file(
        &self,
        name: &OsStr,
        read: bool,
        write: bool,
    ) -> io::Result<StdFile> {
        OpenOptions::new()
            .read(read)
            .write(write)
            .open(self.stage.join(name))
    }

    pub(crate) fn open_destination(&self, destination: &Destination) -> io::Result<StdFile> {
        StdFile::open(&destination.display)
    }

    pub(crate) fn install(
        &self,
        stage_name: &OsStr,
        destination: &Destination,
        backup: bool,
        _durability: RepairDurability,
    ) -> EngineResult<Option<PathBuf>> {
        // A plain rename never copies, so there is no destination-local file
        // for the policy to synchronize.
        let (parent, filename) = relative_parent(&self.base, &destination.relative, true)?;
        let target = parent.join(&filename);
        let mut saved = None;
        match std::fs::symlink_metadata(&target) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(EngineError::InvalidState(
                    "destination is not a regular file",
                ));
            }
            Ok(_) if backup => {
                for index in 1..=100_000 {
                    let mut backup_name = filename.to_os_string();
                    backup_name.push(format!(".{index}"));
                    let backup_path = parent.join(backup_name);
                    match std::fs::hard_link(&target, &backup_path) {
                        Ok(()) => {
                            saved = Some(backup_path);
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => return Err(error.into()),
                    }
                }
                if saved.is_none() {
                    return Err(EngineError::resource_limit("backup names"));
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::rename(self.stage.join(stage_name), target)?;
        Ok(saved)
    }

    pub(crate) fn install_with_moved_backup(
        &self,
        stage_name: &OsStr,
        destination: &Destination,
        backup: bool,
    ) -> io::Result<Option<PathBuf>> {
        let (parent, filename) = relative_parent(&self.base, &destination.relative, true)?;
        let target = parent.join(&filename);
        let mut saved = None;
        match std::fs::symlink_metadata(&target) {
            Ok(_) if backup => {
                for index in 1..10_000u32 {
                    let mut backup_name = filename.to_os_string();
                    backup_name.push(format!(".{index}"));
                    let backup_path = parent.join(backup_name);
                    match std::fs::symlink_metadata(&backup_path) {
                        Ok(_) => continue,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    std::fs::rename(&target, &backup_path)?;
                    saved = Some(backup_path);
                    break;
                }
                if saved.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "every backup name from .1 to .9999 is taken",
                    ));
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::rename(self.stage.join(stage_name), target)?;
        Ok(saved)
    }

    pub(crate) fn paths_alias(&self, first: &str, second: &str) -> io::Result<bool> {
        let (first_parent, mut first_name) = relative_parent(&self.base, Path::new(first), true)?;
        let (second_parent, mut second_name) =
            relative_parent(&self.base, Path::new(second), true)?;
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!(".par3-alias-{sequence}");
        first_name.push(&suffix);
        second_name.push(&suffix);
        // Probe the actual parent directories: directory-local case folding
        // need not match a freshly created child of the repair root.
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(first_parent.join(&first_name))?,
        );
        let result = match std::fs::symlink_metadata(second_parent.join(&second_name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        };
        let cleanup = std::fs::remove_file(first_parent.join(&first_name));
        match (result, cleanup) {
            (Ok(aliases), Ok(())) => Ok(aliases),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl Drop for RepairTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.base.join(&self.stage_component));
    }
}

pub(crate) const MIN_REPAIR_HANDLES: usize = 2;

pub(crate) fn normalization_key(path: &str) -> String {
    path.nfc().collect()
}

pub(crate) fn case_normalization_key(path: &str) -> String {
    path.nfc().flat_map(char::to_lowercase).nfc().collect()
}

fn canonical_key(path: &str) -> String {
    case_normalization_key(path)
}

fn check_existing_destination(root: &Path, relative: &Path) -> io::Result<()> {
    let (parents, filename) = split_relative(relative)?;
    let mut directory = root.to_owned();
    for component in parents {
        directory.push(component);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repair destination traverses a symbolic link",
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "repair destination parent is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    match std::fs::symlink_metadata(directory.join(filename)) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination is a symbolic link",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn relative_parent(root: &Path, relative: &Path, create: bool) -> io::Result<(PathBuf, OsString)> {
    let (parents, filename) = split_relative(relative)?;
    let mut directory = root.to_owned();
    for component in parents {
        directory.push(component);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repair destination traverses a symbolic link",
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "repair destination parent is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((directory, filename))
}

fn split_relative(relative: &Path) -> io::Result<(Vec<OsString>, OsString)> {
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repair destination is not relative",
                ));
            }
        }
    }
    let filename = components
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "repair path is empty"))?;
    Ok((components, filename))
}
