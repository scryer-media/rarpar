//! Capability-relative destination and staging operations for repair.

use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, OpenOptions};
#[cfg(windows)]
#[path = "repair_tree_windows.rs"]
#[allow(unsafe_code)]
mod windows;
#[cfg(unix)]
use cap_std::fs::DirBuilderExt;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::File as StdFile;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_normalization::UnicodeNormalization;

use crate::runtime::{EngineError, EngineFile, EngineResult, ExecutionOptions};

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Directory capabilities consume the same budget as data files. Field order
// closes the OS handle before its reservation is returned.
struct BudgetedDir {
    dir: Dir,
    _lease: Option<crate::runtime::HandleLease>,
    options: Option<ExecutionOptions>,
}

impl std::ops::Deref for BudgetedDir {
    type Target = Dir;
    fn deref(&self) -> &Dir {
        &self.dir
    }
}

impl BudgetedDir {
    fn lease(
        options: Option<&ExecutionOptions>,
    ) -> io::Result<Option<crate::runtime::HandleLease>> {
        let Some(options) = options else {
            return Ok(None);
        };
        // Cleanup and identity checks still need capabilities after cancellation.
        // Their leases obey the ceiling without restarting canceled data work.
        let lease = options.handles.acquire().map_err(io::Error::other)?;
        if options.handles.used() > options.open_handles {
            return Err(io::Error::other(EngineError::resource_limit(
                "open handles",
            )));
        }
        Ok(Some(lease))
    }

    fn acquire(&self) -> io::Result<Option<crate::runtime::HandleLease>> {
        Self::lease(self.options.as_ref())
    }

    fn open(
        options: Option<ExecutionOptions>,
        open: impl FnOnce() -> io::Result<Dir>,
    ) -> io::Result<Self> {
        let lease = Self::lease(options.as_ref())?;
        Ok(Self {
            dir: open()?,
            _lease: lease,
            options,
        })
    }

    fn try_clone(&self) -> io::Result<Self> {
        Self::open(self.options.clone(), || self.dir.try_clone())
    }

    fn open_dir(&self, path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(self.options.clone(), || self.dir.open_dir(path))
    }

    fn create_private_dir(&self, name: &OsStr) -> io::Result<Self> {
        Self::open(self.options.clone(), || {
            #[cfg(windows)]
            {
                windows::create_private_dir(&self.dir, name)
            }
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt;
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                self.dir.create_dir_with(name, &builder)?;
                let stage = self.dir.open_dir(name)?;
                if stage.dir_metadata()?.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "staging directory is not private",
                    ));
                }
                Ok(stage)
            }
        })
    }
}

pub(crate) struct Destination {
    pub(crate) relative: PathBuf,
    pub(crate) display: PathBuf,
}

pub(crate) struct RepairTree {
    base: PathBuf,
    root: BudgetedDir,
    stage_component: OsString,
    stage: Option<BudgetedDir>,
}

impl RepairTree {
    pub(crate) fn new<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
    ) -> io::Result<Self> {
        Self::with_options(base, protected_paths, None)
    }

    pub(crate) fn new_budgeted<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
        options: &ExecutionOptions,
    ) -> io::Result<Self> {
        Self::with_options(base, protected_paths, Some(options.clone()))
    }

    fn with_options<'a>(
        base: &Path,
        protected_paths: impl IntoIterator<Item = &'a str>,
        options: Option<ExecutionOptions>,
    ) -> io::Result<Self> {
        let root = BudgetedDir::open(options, || Dir::open_ambient_dir(base, ambient_authority()))?;
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
            match root.create_private_dir(OsStr::new(&candidate)) {
                Ok(stage) => {
                    return Ok(Self {
                        base: base.to_owned(),
                        root,
                        stage_component: candidate.into(),
                        stage: Some(stage),
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
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        let file = EngineFile::open_with(options, || {
            self.stage()
                .open_with(&name, &open)
                .map(cap_std::fs::File::into_std)
        })?;
        let display = self.base.join(&self.stage_component).join(&name);
        outputs.push(display.clone());
        if let Err(error) = file.set_len(len) {
            drop(file);
            if self.stage().remove_file(&name).is_ok() {
                outputs.retain(|path| path != &display);
            }
            return Err(error.into());
        }
        Ok((name.into(), display))
    }

    pub(crate) fn create_stage_file(
        &self,
        index: usize,
    ) -> io::Result<(OsString, PathBuf, StdFile)> {
        let name = format!(".par3-repair-{index}.tmp");
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        let file = self.stage().open_with(&name, &open)?.into_std();
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
            self.stage()
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
        self.stage()
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
        if let Err(error) = self.move_stage(stage_name, &parent, &filename) {
            if let Some(path) = &saved {
                parent.remove_file(path.file_name().expect("backup filename"))?;
            }
            return Err(error.into());
        }
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
        if let Err(error) = self.move_stage(stage_name, &parent, &filename) {
            if let Some(path) = &saved {
                parent.rename(
                    path.file_name().expect("backup filename"),
                    &parent,
                    &filename,
                )?;
            }
            return Err(error);
        }
        Ok(saved)
    }

    fn move_stage(&self, name: &OsStr, parent: &BudgetedDir, filename: &OsStr) -> io::Result<()> {
        match self.stage().rename(name, parent, filename) {
            Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
                self.copy_stage(name, parent, filename)
            }
            outcome => outcome,
        }
    }

    // A nested mount needs a destination-local temporary before atomic rename.
    // Re-read its bytes against the copied source digest before publishing it.
    fn copy_stage(&self, name: &OsStr, parent: &BudgetedDir, filename: &OsStr) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let local = PrivateInstall::new(parent, filename)?;
        let options = self.root.options.clone().unwrap_or_default();
        let _memory = options
            .memory
            .reserve_as(
                crate::runtime::MemoryCategory::OutputStaging,
                8192 + 2 * size_of::<blake3::Hasher>(),
            )
            .map_err(io::Error::other)?;
        let mut source = self
            .open_stage(name, true, false, &options)
            .map_err(io::Error::other)?;
        let mut open = OpenOptions::new();
        open.read(true).write(true).create_new(true);
        let mut output = EngineFile::open_with(&options, || {
            local
                .dir()
                .open_with("output", &open)
                .map(cap_std::fs::File::into_std)
        })
        .map_err(io::Error::other)?;
        let mut buffer = [0u8; 8192];
        let mut expected = blake3::Hasher::new();
        loop {
            options.cancel.check().map_err(io::Error::other)?;
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            expected.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        drop(source);
        output.sync_all()?;
        output.seek(SeekFrom::Start(0))?;
        let mut actual = blake3::Hasher::new();
        loop {
            options.cancel.check().map_err(io::Error::other)?;
            let read = output.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            actual.update(&buffer[..read]);
        }
        if actual.finalize() != expected.finalize() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "destination-local staging verification failed",
            ));
        }
        drop(output);
        // The verified local copy now owns the rebuilt bytes. Remove the
        // original before installation so a cleanup error cannot hide an
        // already-installed output from the repair report.
        self.stage().remove_file(name)?;
        local.dir().rename("output", parent, filename)
    }

    pub(crate) fn paths_alias(&self, first: &str, second: &str) -> io::Result<bool> {
        let (first_parent, mut first_name) = self.destination_parent(Path::new(first), true)?;
        let (second_parent, mut second_name) = self.destination_parent(Path::new(second), true)?;
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!(".par3-alias-{sequence}");
        first_name.push(&suffix);
        second_name.push(&suffix);
        // Probe the actual parent directories: directory-local case folding
        // need not match a freshly created child of the repair root.
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        {
            let _lease = first_parent.acquire()?;
            drop(first_parent.open_with(&first_name, &open)?);
        }
        let result = match second_parent.symlink_metadata(&second_name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        };
        let cleanup = first_parent.remove_file(&first_name);
        match (result, cleanup) {
            (Ok(aliases), Ok(())) => Ok(aliases),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    // A stale ambient spelling must never be returned as a cleanup target.
    // Keep all removal relative to the original staging capability.
    pub(crate) fn sanitize_temporary_outputs(&self, outputs: &mut Vec<PathBuf>) -> io::Result<()> {
        let display = self.base.join(&self.stage_component);
        let matches = (|| {
            let current = BudgetedDir::open(self.root.options.clone(), || {
                Dir::open_ambient_dir(&display, ambient_authority())
            })?;
            same_directory(&self.stage().dir, &current.dir)
        })()
        .unwrap_or(false);
        if matches {
            return Ok(());
        }
        let paths = std::mem::take(outputs);
        for path in paths {
            if let Some(name) = path.file_name() {
                match self.stage().remove_file(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn stage(&self) -> &BudgetedDir {
        self.stage.as_ref().expect("staging directory is open")
    }

    fn destination_parent(
        &self,
        relative: &Path,
        create: bool,
    ) -> io::Result<(BudgetedDir, OsString)> {
        relative_parent(&self.root, relative, create)
    }
}

impl Drop for RepairTree {
    fn drop(&mut self) {
        // A successful repair leaves the private directory empty. Interrupted
        // output remains available at the reported paths for host cleanup.
        drop(self.stage.take());
        let _ = self.root.remove_dir(&self.stage_component);
    }
}

struct PrivateInstall<'a> {
    parent: &'a BudgetedDir,
    name: OsString,
    dir: Option<BudgetedDir>,
}

impl<'a> PrivateInstall<'a> {
    fn new(parent: &'a BudgetedDir, destination: &OsStr) -> io::Result<Self> {
        for _ in 0..128 {
            let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(".par3-install-{}-{sequence}", std::process::id()));
            if name == destination {
                continue;
            }
            match parent.create_private_dir(&name) {
                Ok(dir) => {
                    return Ok(Self {
                        parent,
                        name,
                        dir: Some(dir),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "installation staging names exhausted",
        ))
    }
    fn dir(&self) -> &BudgetedDir {
        self.dir.as_ref().expect("installation directory is open")
    }
}

impl Drop for PrivateInstall<'_> {
    fn drop(&mut self) {
        let _ = self.dir().remove_file("output");
        drop(self.dir.take());
        let _ = self.parent.remove_dir(&self.name);
    }
}

pub(crate) const MIN_REPAIR_HANDLES: usize = 5;

fn same_directory(first: &Dir, second: &Dir) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        let first = first.dir_metadata()?;
        let second = second.dir_metadata()?;
        Ok(first.dev() == second.dev() && first.ino() == second.ino())
    }
    #[cfg(windows)]
    {
        windows::same_directory(first, second)
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

fn relative_parent(
    root: &BudgetedDir,
    relative: &Path,
    create: bool,
) -> io::Result<(BudgetedDir, OsString)> {
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

    #[test]
    fn unsuccessful_sizing_removes_the_unreported_stage() {
        let root = TestRoot::new("failed-sizing");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let error = tree.create_stage(0, u64::MAX, &ExecutionOptions::default());
        assert!(error.is_err(), "an unrepresentable file length must fail");
        assert_eq!(tree.stage().entries().unwrap().count(), 0);
        drop(tree);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_empty_stage_is_removed_after_its_handle_is_closed() {
        let root = TestRoot::new("empty-stage");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let stage = root.path().join(&tree.stage_component);
        assert!(stage.is_dir());
        drop(tree);
        assert!(!stage.exists());
    }

    #[test]
    fn capability_handles_share_the_data_file_budget() {
        let root = TestRoot::new("handle-budget");
        let options = ExecutionOptions {
            handles: crate::runtime::HandleBudget::new(5),
            open_handles: 5,
            ..ExecutionOptions::default()
        };
        let tree =
            RepairTree::new_budgeted(root.path(), ["nested/deeper/file.bin"], &options).unwrap();
        assert_eq!(options.handles.used(), 2);
        tree.destination("nested/deeper/file.bin").unwrap();
        assert_eq!(options.handles.used(), 2);
        assert_eq!(options.handles.peak(), 4);
        let (stage, path) = tree.create_stage(0, 1, &options).unwrap();
        let file = tree.open_stage(&stage, true, false, &options).unwrap();
        assert_eq!(options.handles.used(), 3);
        let held1 = options.handles.acquire().unwrap();
        let held2 = options.handles.acquire().unwrap();
        assert!(tree.destination("another/file.bin").is_err());
        assert!(!root.path().join("another").exists());
        drop((file, held1, held2));
        assert_eq!(options.handles.used(), 2);
        std::fs::remove_file(path).unwrap();
        drop(tree);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.handles.peak(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn staging_permissions_exclude_group_and_other_access() {
        use std::os::unix::fs::PermissionsExt;
        let root = TestRoot::new("private-stage");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let permissions = std::fs::metadata(root.path().join(&tree.stage_component))
            .unwrap()
            .permissions();
        assert_eq!(permissions.mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn alias_probes_refuse_links_in_the_actual_destination_parent() {
        use std::os::unix::fs::symlink;
        let root = TestRoot::new("alias-parent");
        let outside = TestRoot::new("alias-outside");
        symlink(outside.path(), root.path().join("nested")).unwrap();
        let tree = RepairTree::new(root.path(), ["nested/Readme", "nested/README"]).unwrap();
        assert_eq!(
            tree.paths_alias("nested/Readme", "nested/README")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_cleanup_never_reports_a_replacement_roots_file() {
        let outer = TestRoot::new("cleanup-root");
        let base = outer.path().join("base");
        let moved = outer.path().join("held-root");
        std::fs::create_dir(&base).unwrap();
        let tree = RepairTree::new(&base, ["file.bin"]).unwrap();
        let (_, temporary) = tree
            .create_stage(0, 4, &ExecutionOptions::default())
            .unwrap();
        std::fs::rename(&base, &moved).unwrap();
        std::fs::create_dir_all(temporary.parent().unwrap()).unwrap();
        std::fs::write(&temporary, b"unrelated replacement").unwrap();
        let mut reported = vec![temporary.clone()];
        tree.sanitize_temporary_outputs(&mut reported).unwrap();
        assert!(reported.is_empty());
        assert_eq!(std::fs::read(&temporary).unwrap(), b"unrelated replacement");
        assert!(
            !moved
                .join(&tree.stage_component)
                .join(temporary.file_name().unwrap())
                .exists()
        );
        let old_stage = moved.join(&tree.stage_component);
        drop(tree);
        assert!(!old_stage.exists());
        assert_eq!(std::fs::read(&temporary).unwrap(), b"unrelated replacement");
    }

    #[test]
    fn destination_local_copy_is_verified_and_installed_without_leaving_staging() {
        let root = TestRoot::new("local-copy");
        let options = ExecutionOptions {
            handles: crate::runtime::HandleBudget::new(6),
            open_handles: 6,
            ..ExecutionOptions::default()
        };
        let tree = RepairTree::new_budgeted(root.path(), ["nested/file.bin"], &options).unwrap();
        let destination = tree.destination("nested/file.bin").unwrap();
        let (name, path) = tree.create_stage(0, 32769, &options).unwrap();
        let bytes: Vec<u8> = (0..32769).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let (parent, filename) = tree
            .destination_parent(&destination.relative, true)
            .unwrap();
        tree.copy_stage(&name, &parent, &filename).unwrap();
        assert_eq!(std::fs::read(&destination.display).unwrap(), bytes);
        assert!(!path.exists());
        assert_eq!(parent.entries().unwrap().count(), 1);
        assert_eq!(options.handles.peak(), 6);
        drop((parent, tree));
        assert_eq!(options.handles.used(), 0);
    }

    #[test]
    fn failed_destination_local_copy_leaves_the_original_and_cleans_its_private_directory() {
        let root = TestRoot::new("local-copy-budget");
        let options = ExecutionOptions {
            handles: crate::runtime::HandleBudget::new(5),
            open_handles: 5,
            ..ExecutionOptions::default()
        };
        let tree = RepairTree::new_budgeted(root.path(), ["nested/file.bin"], &options).unwrap();
        let destination = tree.destination("nested/file.bin").unwrap();
        let (name, path) = tree.create_stage(0, 4, &options).unwrap();
        std::fs::write(&path, b"safe").unwrap();
        let (parent, filename) = tree
            .destination_parent(&destination.relative, true)
            .unwrap();
        assert!(tree.copy_stage(&name, &parent, &filename).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"safe");
        assert_eq!(parent.entries().unwrap().count(), 0);
        assert_eq!(options.handles.used(), 3);
        std::fs::remove_file(path).unwrap();
        drop((parent, tree));
        assert_eq!(options.handles.used(), 0);
    }

    #[test]
    fn failed_install_removes_a_new_backup_and_preserves_the_original() {
        let root = TestRoot::new("backup-failure");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let destination = tree.destination("file.bin").unwrap();
        std::fs::write(&destination.display, b"original").unwrap();
        assert!(
            tree.install(OsStr::new("missing-stage"), &destination, true)
                .is_err()
        );
        assert_eq!(std::fs::read(&destination.display).unwrap(), b"original");
        assert!(!root.path().join("file.bin.1").exists());
        assert!(
            tree.install_with_moved_backup(OsStr::new("missing-stage"), &destination, true)
                .is_err()
        );
        assert_eq!(std::fs::read(&destination.display).unwrap(), b"original");
        assert!(!root.path().join("file.bin.1").exists());
    }

    #[cfg(windows)]
    #[test]
    fn staging_has_a_protected_owner_only_windows_acl() {
        let root = TestRoot::new("private-acl");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        assert_eq!(
            windows::dacl_string(&tree.stage().dir).unwrap(),
            "D:P(A;OICI;FA;;;OW)"
        );
    }

    #[test]
    fn cancellation_keeps_valid_cleanup_paths_available_for_inspection() {
        let root = TestRoot::new("canceled-cleanup");
        let options = ExecutionOptions::default();
        let tree = RepairTree::new_budgeted(root.path(), ["file.bin"], &options).unwrap();
        let (_, path) = tree.create_stage(0, 4, &options).unwrap();
        let mut outputs = vec![path.clone()];
        options.cancel.cancel();
        tree.sanitize_temporary_outputs(&mut outputs).unwrap();
        assert_eq!(outputs, vec![path.clone()]);
        assert!(path.exists());
        std::fs::remove_file(path).unwrap();
        drop(tree);
        assert_eq!(options.handles.used(), 0);
    }

    #[test]
    fn directory_identity_distinguishes_a_clone_from_another_directory() {
        let root = TestRoot::new("directory-identity");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let clone = tree.stage().try_clone().unwrap();
        let reopened =
            Dir::open_ambient_dir(tree.base.join(&tree.stage_component), ambient_authority())
                .unwrap();
        assert!(same_directory(&tree.stage().dir, &clone.dir).unwrap());
        assert!(same_directory(&tree.stage().dir, &reopened).unwrap());
        assert!(!same_directory(&tree.stage().dir, &tree.root.dir).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn a_live_staging_capability_prevents_directory_rename() {
        let root = TestRoot::new("stage-rename");
        let tree = RepairTree::new(root.path(), ["file.bin"]).unwrap();
        let stage = tree.base.join(&tree.stage_component);
        let renamed = root.path().join("renamed-stage");
        let error = std::fs::rename(&stage, &renamed).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32)); // ERROR_SHARING_VIOLATION
        assert!(stage.is_dir());
        assert!(!renamed.exists());
        drop(tree);
        assert!(!stage.exists());
    }
}
