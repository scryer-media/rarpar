//! Capability-relative destination and staging operations for repair.

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::File as StdFile;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_normalization::UnicodeNormalization;

use crate::runtime::{EngineError, EngineFile, EngineResult, ExecutionOptions};

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Destination {
    pub(crate) relative: PathBuf,
    pub(crate) display: PathBuf,
}

pub(crate) struct RepairTree {
    base: PathBuf,
    root: Dir,
    stage_component: OsString,
    stage: Dir,
}

impl RepairTree {
    pub(crate) fn new<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
    ) -> io::Result<Self> {
        let root = Dir::open_ambient_dir(base, ambient_authority())?;
        let reserved: HashSet<String> = protected_paths
            .into_iter()
            .filter_map(|path| path.split('/').next())
            .map(canonical_key)
            .collect();
        for _ in 0..128 {
            let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = format!(".par3-stage-{}-{sequence}", std::process::id());
            if reserved.contains(&canonical_key(&candidate)) {
                continue;
            }
            match root.create_dir(&candidate) {
                Ok(()) => {
                    let stage = match root.open_dir(&candidate) {
                        Ok(stage) => stage,
                        Err(error) => {
                            let _ = root.remove_dir(&candidate);
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        base: base.to_owned(),
                        root,
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

    pub(crate) fn destination(&self, relative: &str) -> io::Result<Destination> {
        let destination = self.unresolved_destination(relative)?;
        let _ = self.destination_parent(&destination.relative, true)?;
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
        let mut components: Vec<_> = destination
            .relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(component) => Some(component.to_os_string()),
                _ => None,
            })
            .collect();
        let filename = components
            .pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "repair path is empty"))?;
        let mut directory = self.root.try_clone()?;
        for component in components {
            match directory.symlink_metadata(&component) {
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
                Ok(_) => directory = directory.open_dir(&component)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        match directory.symlink_metadata(filename) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repair destination is a symbolic link",
            )),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn create_stage(
        &self,
        index: usize,
        len: u64,
        options: &ExecutionOptions,
    ) -> EngineResult<(OsString, PathBuf)> {
        let name = format!(".par3-repair-{index}.tmp");
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        let file = EngineFile::open_with(options, || {
            self.stage
                .open_with(&name, &open)
                .map(cap_std::fs::File::into_std)
        })?;
        file.set_len(len)?;
        let display = self.base.join(&self.stage_component).join(&name);
        Ok((name.into(), display))
    }

    pub(crate) fn create_stage_file(
        &self,
        index: usize,
    ) -> io::Result<(OsString, PathBuf, StdFile)> {
        let name = format!(".par3-repair-{index}.tmp");
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        let file = self.stage.open_with(&name, &open)?.into_std();
        let display = self.base.join(&self.stage_component).join(&name);
        Ok((name.into(), display, file))
    }

    pub(crate) fn open_stage(
        &self,
        name: &OsStr,
        read: bool,
        write: bool,
        options: &ExecutionOptions,
    ) -> EngineResult<EngineFile> {
        let mut open = OpenOptions::new();
        open.read(read).write(write);
        EngineFile::open_with(options, || {
            self.stage
                .open_with(name, &open)
                .map(cap_std::fs::File::into_std)
        })
    }

    pub(crate) fn open_stage_file(
        &self,
        name: &OsStr,
        read: bool,
        write: bool,
    ) -> io::Result<StdFile> {
        let mut open = OpenOptions::new();
        open.read(read).write(write);
        self.stage
            .open_with(name, &open)
            .map(cap_std::fs::File::into_std)
    }

    pub(crate) fn open_destination(&self, destination: &Destination) -> io::Result<StdFile> {
        self.root
            .open(&destination.relative)
            .map(cap_std::fs::File::into_std)
    }

    pub(crate) fn install(
        &self,
        stage_name: &OsStr,
        destination: &Destination,
        backup: bool,
    ) -> EngineResult<Option<PathBuf>> {
        let (parent, filename) = self.destination_parent(&destination.relative, true)?;
        let mut saved = None;
        match parent.symlink_metadata(&filename) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(EngineError::InvalidState(
                    "destination is not a regular file",
                ));
            }
            Ok(_) if backup => {
                for index in 1..=100_000 {
                    let mut backup_name = filename.to_os_string();
                    backup_name.push(format!(".{index}"));
                    match parent.hard_link(&filename, &parent, &backup_name) {
                        Ok(()) => {
                            let mut display = destination.display.as_os_str().to_os_string();
                            display.push(format!(".{index}"));
                            saved = Some(PathBuf::from(display));
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
        self.stage.rename(stage_name, &parent, &filename)?;
        Ok(saved)
    }

    pub(crate) fn install_with_moved_backup(
        &self,
        stage_name: &OsStr,
        destination: &Destination,
        backup: bool,
    ) -> io::Result<Option<PathBuf>> {
        let (parent, filename) = self.destination_parent(&destination.relative, true)?;
        let mut saved = None;
        match parent.symlink_metadata(&filename) {
            Ok(_) if backup => {
                for index in 1..10_000u32 {
                    let mut backup_name = filename.to_os_string();
                    backup_name.push(format!(".{index}"));
                    match parent.symlink_metadata(&backup_name) {
                        Ok(_) => continue,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    parent.rename(&filename, &parent, &backup_name)?;
                    let mut display = destination.display.as_os_str().to_os_string();
                    display.push(format!(".{index}"));
                    saved = Some(PathBuf::from(display));
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
        self.stage.rename(stage_name, &parent, &filename)?;
        Ok(saved)
    }

    pub(crate) fn paths_alias(&self, first: &str, second: &str) -> io::Result<bool> {
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let probe_name = format!("alias-probe-{sequence}");
        self.stage.create_dir(&probe_name)?;
        let result = (|| {
            let probe = self.stage.open_dir(&probe_name)?;
            let first = Path::new(first);
            let (parent, filename) = relative_parent(&probe, first, true)?;
            let mut open = OpenOptions::new();
            open.write(true).create_new(true);
            drop(parent.open_with(&filename, &open)?);
            match probe.symlink_metadata(second) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        })();
        let cleanup = self.stage.remove_dir_all(&probe_name);
        match (result, cleanup) {
            (Ok(aliases), Ok(())) => Ok(aliases),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn destination_parent(&self, relative: &Path, create: bool) -> io::Result<(Dir, OsString)> {
        relative_parent(&self.root, relative, create)
    }
}

impl Drop for RepairTree {
    fn drop(&mut self) {
        // A successful repair leaves the private directory empty. Interrupted
        // output remains available at the reported paths for host cleanup.
        let _ = self.root.remove_dir(&self.stage_component);
    }
}

pub(crate) fn normalization_key(path: &str) -> String {
    path.nfc().collect()
}

pub(crate) fn case_normalization_key(path: &str) -> String {
    path.nfc().flat_map(char::to_lowercase).nfc().collect()
}

fn canonical_key(path: &str) -> String {
    case_normalization_key(path)
}

fn relative_parent(root: &Dir, relative: &Path, create: bool) -> io::Result<(Dir, OsString)> {
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
    let (filename, parents) = components
        .split_last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "repair path is empty"))?;
    let mut directory = root.try_clone()?;
    for component in parents {
        match directory.symlink_metadata(component) {
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
                directory.create_dir(component)?;
            }
            Err(error) => return Err(error),
        }
        directory = directory.open_dir(component)?;
    }
    Ok((directory, filename.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            for _ in 0..128 {
                let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "par3-repair-tree-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("test directory could not be created: {error}"),
                }
            }
            panic!("test directory names exhausted");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_destination_named_like_a_stage_file_cannot_replace_it() {
        let root = TestRoot::new("stage-name");
        let tree = RepairTree::new(root.path(), [".par3-repair-0.tmp"]).unwrap();
        let destination = tree.unresolved_destination(".par3-repair-0.tmp").unwrap();
        let (stage_name, _, mut output) = tree.create_stage_file(0).unwrap();
        output.write_all(b"verified output").unwrap();
        drop(output);

        tree.install_with_moved_backup(&stage_name, &destination, false)
            .unwrap();

        assert_eq!(
            std::fs::read(root.path().join(".par3-repair-0.tmp")).unwrap(),
            b"verified output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacing_the_root_path_cannot_redirect_installation() {
        use std::os::unix::fs::symlink;

        let outer = TestRoot::new("root-replacement");
        let base = outer.path().join("base");
        let moved = outer.path().join("held-root");
        let outside = outer.path().join("outside");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let tree = RepairTree::new(&base, ["nested/file.bin"]).unwrap();
        let destination = tree.unresolved_destination("nested/file.bin").unwrap();
        let (stage_name, _, mut output) = tree.create_stage_file(0).unwrap();
        output.write_all(b"contained").unwrap();
        drop(output);

        std::fs::rename(&base, &moved).unwrap();
        symlink(&outside, &base).unwrap();
        tree.install_with_moved_backup(&stage_name, &destination, false)
            .unwrap();

        assert_eq!(
            std::fs::read(moved.join("nested/file.bin")).unwrap(),
            b"contained"
        );
        assert!(!outside.join("nested/file.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_parent_with_a_link_is_refused() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("parent-replacement");
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let tree = RepairTree::new(root.path(), ["nested/file.bin"]).unwrap();
        let destination = tree.destination("nested/file.bin").unwrap();
        let (stage_name, _, mut output) = tree.create_stage_file(0).unwrap();
        output.write_all(b"contained").unwrap();
        drop(output);

        std::fs::rename(root.path().join("nested"), root.path().join("old-parent")).unwrap();
        symlink(&outside, root.path().join("nested")).unwrap();
        let error = tree
            .install_with_moved_backup(&stage_name, &destination, false)
            .expect_err("a replaced parent must not be followed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("file.bin").exists());
        assert!(!root.path().join("old-parent/file.bin").exists());
    }
}
