//! Filesystem-backed implementation of [`FileAccess`].

use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use crate::par2_set::Par2FileSet;
use crate::placement::PlacementPlan;
use crate::types::FileId;
use crate::verify::{FileAccess, FileRangeReader};

fn repair_path_components(path: &Path) -> io::Result<Vec<&std::ffi::OsStr>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => components.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "repair destination must remain relative to the working directory: {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination has no filename",
        ));
    }
    Ok(components)
}

#[cfg(unix)]
fn c_component(component: &OsStr) -> io::Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination contains a NUL byte",
        )
    })
}

#[cfg(unix)]
fn open_directory_at(parent: &File, component: &OsStr, create: bool) -> io::Result<File> {
    let component = c_component(component)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let open = || {
        // SAFETY: `parent` and `component` stay alive for the call, and the
        // returned descriptor is immediately adopted by `File` on success.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `openat` returned a new, owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    };

    match open() {
        Ok(directory) => Ok(directory),
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            // SAFETY: the directory descriptor and C string are valid for the
            // call. The process umask restricts the requested mode as usual.
            let result = unsafe {
                libc::mkdirat(
                    parent.as_raw_fd(),
                    component.as_ptr(),
                    0o777 as libc::mode_t,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            open()
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn open_repair_output(base_dir: &Path, destination: &Path) -> io::Result<File> {
    let relative = destination.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination is outside the working directory",
        )
    })?;
    let components = repair_path_components(relative)?;
    let (filename, parent_components) = components.split_last().expect("checked non-empty");

    // Following a symlink supplied as the base directory is intentional: the
    // caller chooses that root. Every PAR2-controlled component below it is
    // opened relative to the resulting descriptor without following links.
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base_dir)?;
    for component in parent_components {
        directory = open_directory_at(&directory, component, true)?;
    }

    let filename = c_component(filename)?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: the directory descriptor and C string are valid for the call,
    // and the returned descriptor is immediately adopted by `File`.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            filename.as_ptr(),
            flags,
            0o666 as libc::c_uint,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn unix_repair_parent(
    mut directory: File,
    components: &[&OsStr],
    create: bool,
) -> io::Result<(File, CString)> {
    let (filename, parent_components) = components.split_last().expect("checked non-empty");
    for component in parent_components {
        directory = open_directory_at(&directory, component, create)?;
    }
    Ok((directory, c_component(filename)?))
}

#[cfg(unix)]
pub(crate) fn rename_within_base(base_dir: &Path, from: &Path, to: &Path) -> io::Result<()> {
    let from_relative = from.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename source is outside the working directory",
        )
    })?;
    let to_relative = to.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename destination is outside the working directory",
        )
    })?;
    let from_components = repair_path_components(from_relative)?;
    let to_components = repair_path_components(to_relative)?;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base_dir)?;
    let (from_parent, from_name) = unix_repair_parent(root.try_clone()?, &from_components, false)?;
    let (to_parent, to_name) = unix_repair_parent(root, &to_components, true)?;

    // SAFETY: both directory descriptors and C strings remain valid for the
    // call. `renameat` operates on the link entries themselves and therefore
    // does not follow either final path component.
    let result = unsafe {
        libc::renameat(
            from_parent.as_raw_fd(),
            from_name.as_ptr(),
            to_parent.as_raw_fd(),
            to_name.as_ptr(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn remove_file_within_base(base_dir: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair removal target is outside the working directory",
        )
    })?;
    let components = repair_path_components(relative)?;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base_dir)?;
    let (parent, filename) = unix_repair_parent(root, &components, false)?;

    // SAFETY: the directory descriptor and C string remain valid for the
    // call. With no removal flags, `unlinkat` removes a file or symlink entry
    // without following the final component.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), filename.as_ptr(), 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn open_repair_output(base_dir: &Path, destination: &Path) -> io::Result<File> {
    use cap_std::ambient_authority;
    use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};

    let relative = destination.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination is outside the working directory",
        )
    })?;
    let components = repair_path_components(relative)?;
    let (filename, parent_components) = components.split_last().expect("checked non-empty");
    let mut directory = Dir::open_ambient_dir(base_dir, ambient_authority())?;

    for component in parent_components {
        match directory.symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "repair destination traverses a link: {}",
                        destination.display()
                    ),
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!(
                        "repair destination parent is not a directory: {}",
                        destination.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                directory.create_dir(component)?;
            }
            Err(error) => return Err(error),
        }
        // cap-std resolves each component relative to the held directory
        // handle and refuses any link traversal that would escape the root.
        directory = directory.open_dir(component)?;
    }

    match directory.symlink_metadata(filename) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("repair destination is a link: {}", destination.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = CapOpenOptions::new();
    options.write(true).create(true).truncate(false);
    directory
        .open_with(filename, &options)
        .map(cap_std::fs::File::into_std)
}

#[cfg(windows)]
pub(crate) fn rename_within_base(base_dir: &Path, from: &Path, to: &Path) -> io::Result<()> {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    let from_relative = from.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename source is outside the working directory",
        )
    })?;
    let to_relative = to.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename destination is outside the working directory",
        )
    })?;
    repair_path_components(from_relative)?;
    repair_path_components(to_relative)?;
    let directory = Dir::open_ambient_dir(base_dir, ambient_authority())?;
    if let Some(parent) = to_relative.parent() {
        directory.create_dir_all(parent)?;
    }
    directory.rename(from_relative, &directory, to_relative)
}

#[cfg(windows)]
pub(crate) fn remove_file_within_base(base_dir: &Path, path: &Path) -> io::Result<()> {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    let relative = path.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair removal target is outside the working directory",
        )
    })?;
    repair_path_components(relative)?;
    Dir::open_ambient_dir(base_dir, ambient_authority())?.remove_file(relative)
}

#[cfg(not(any(unix, windows)))]
fn open_repair_output(base_dir: &Path, destination: &Path) -> io::Result<File> {
    let relative = destination.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair destination is outside the working directory",
        )
    })?;
    let components = repair_path_components(relative)?;
    let mut current = base_dir.to_path_buf();
    for component in &components[..components.len() - 1] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("repair destination traverses a link: {}", current.display()),
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!(
                        "repair destination parent is not a directory: {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("repair destination parent changed: {}", current.display()),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }

    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("repair destination is a link: {}", destination.display()),
        )),
        Ok(_) | Err(_) => OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(destination),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn rename_within_base(base_dir: &Path, from: &Path, to: &Path) -> io::Result<()> {
    let from_relative = from.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename source is outside the working directory",
        )
    })?;
    let to_relative = to.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair rename destination is outside the working directory",
        )
    })?;
    repair_path_components(from_relative)?;
    repair_path_components(to_relative)?;
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(from, to)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn remove_file_within_base(base_dir: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(base_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "repair removal target is outside the working directory",
        )
    })?;
    repair_path_components(relative)?;
    fs::remove_file(path)
}

/// A [`FileAccess`] implementation that reads and writes files on disk.
///
/// Files are located by combining a base directory with the filename from the
/// PAR2 file descriptions. The mapping from [`FileId`] to filename is built
/// from the [`Par2FileSet`] at construction time.
pub struct DiskFileAccess {
    /// Base directory where files are located.
    base_dir: PathBuf,
    /// Map from FileId to filename (populated from Par2FileSet).
    file_map: HashMap<FileId, String>,
    /// Repair outputs stay open for the accessor lifetime so a multi-slice
    /// repair does not reopen the same destination for every block.
    write_files: HashMap<FileId, File>,
}

impl DiskFileAccess {
    /// Create a new `DiskFileAccess` from a base directory and a PAR2 file set.
    ///
    /// Builds the internal file map from the file descriptions in the PAR2 set.
    pub fn new(base_dir: PathBuf, par2_set: &Par2FileSet) -> Self {
        let mut file_map = HashMap::new();
        for (file_id, desc) in &par2_set.files {
            file_map.insert(*file_id, desc.filename.clone());
        }
        Self {
            base_dir,
            file_map,
            write_files: HashMap::new(),
        }
    }

    /// Resolve the full path for a given file ID.
    fn path_for(&self, file_id: &FileId) -> Option<PathBuf> {
        self.file_map
            .get(file_id)
            .map(|name| self.base_dir.join(name))
    }
}

impl FileAccess for DiskFileAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(dst)
    }

    fn open_sequential_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn Read>>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        Ok(Some(Box::new(crate::file_cache::CacheAdvisedReader::open(
            &path,
        )?)))
    }

    fn open_range_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn FileRangeReader>>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        Ok(Some(Box::new(File::open(path)?)))
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        self.path_for(file_id).map(|p| p.exists()).unwrap_or(false)
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        let path = self.path_for(file_id)?;
        fs::metadata(&path).ok().map(|m| m.len())
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        crate::file_cache::read_to_vec(&path)
    }

    fn write_file_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> io::Result<()> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let file = if let Some(file) = self.write_files.get_mut(file_id) {
            file
        } else {
            let file = open_repair_output(&self.base_dir, &path)?;
            self.write_files.entry(*file_id).or_insert(file)
        };
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }
}

/// A [`FileAccess`] that reads files through placement overrides.
///
/// Verification can use this to resolve a PAR2 file ID to the file currently
/// holding that content without mutating filenames on disk.
pub struct PlacementFileAccess {
    base_dir: PathBuf,
    file_map: HashMap<FileId, String>,
    overrides: HashMap<FileId, String>,
    write_files: HashMap<FileId, File>,
}

impl PlacementFileAccess {
    pub fn new(
        base_dir: PathBuf,
        par2_set: &Par2FileSet,
        overrides: HashMap<FileId, String>,
    ) -> Self {
        let mut file_map = HashMap::new();
        for (file_id, desc) in &par2_set.files {
            file_map.insert(*file_id, desc.filename.clone());
        }
        Self {
            base_dir,
            file_map,
            overrides,
            write_files: HashMap::new(),
        }
    }

    pub fn from_plan(base_dir: PathBuf, par2_set: &Par2FileSet, plan: &PlacementPlan) -> Self {
        let mut overrides = HashMap::new();

        for (a, b) in &plan.swaps {
            overrides.insert(a.file_id, a.current_name.clone());
            overrides.insert(b.file_id, b.current_name.clone());
        }
        for entry in &plan.renames {
            overrides.insert(entry.file_id, entry.current_name.clone());
        }

        Self::new(base_dir, par2_set, overrides)
    }

    fn path_for(&self, file_id: &FileId) -> Option<PathBuf> {
        let name = self
            .overrides
            .get(file_id)
            .or_else(|| self.file_map.get(file_id))?;
        Some(self.base_dir.join(name))
    }
}

impl FileAccess for PlacementFileAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(dst)
    }

    fn open_sequential_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn Read>>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        Ok(Some(Box::new(crate::file_cache::CacheAdvisedReader::open(
            &path,
        )?)))
    }

    fn open_range_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn FileRangeReader>>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        Ok(Some(Box::new(File::open(path)?)))
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        self.path_for(file_id).map(|p| p.exists()).unwrap_or(false)
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        let path = self.path_for(file_id)?;
        fs::metadata(&path).ok().map(|m| m.len())
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        crate::file_cache::read_to_vec(&path)
    }

    fn write_file_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> io::Result<()> {
        let path = self
            .path_for(file_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))?;
        let file = if let Some(file) = self.write_files.get_mut(file_id) {
            file
        } else {
            let file = open_repair_output(&self.base_dir, &path)?;
            self.write_files.entry(*file_id).or_insert(file)
        };
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }
}

/// A [`FileAccess`] that searches multiple directories for files.
///
/// When reading a file, directories are searched in order: primary first, then
/// each additional search directory. The first directory containing the file wins.
/// Writes always go to the primary directory.
pub struct MultiDirectoryFileAccess {
    primary: DiskFileAccess,
    search_dirs: Vec<DiskFileAccess>,
}

impl MultiDirectoryFileAccess {
    /// Create a new multi-directory accessor.
    ///
    /// `primary_dir` is the main directory for reads and writes.
    /// `search_dirs` are additional directories to search when a file isn't found
    /// in the primary (e.g., directories from duplicate NZB downloads).
    pub fn new(primary_dir: PathBuf, search_dirs: Vec<PathBuf>, par2_set: &Par2FileSet) -> Self {
        let primary = DiskFileAccess::new(primary_dir, par2_set);
        let search = search_dirs
            .into_iter()
            .map(|dir| DiskFileAccess::new(dir, par2_set))
            .collect();
        Self {
            primary,
            search_dirs: search,
        }
    }

    /// Find which accessor can provide a given file.
    fn find_reader(&self, file_id: &FileId) -> Option<&DiskFileAccess> {
        if self.primary.file_exists(file_id) {
            return Some(&self.primary);
        }
        self.search_dirs.iter().find(|d| d.file_exists(file_id))
    }
}

impl FileAccess for MultiDirectoryFileAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        match self.find_reader(file_id) {
            Some(accessor) => accessor.read_file_range(file_id, offset, len),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found in any directory",
            )),
        }
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        match self.find_reader(file_id) {
            Some(accessor) => accessor.read_file_range_into(file_id, offset, dst),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found in any directory",
            )),
        }
    }

    fn open_sequential_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn Read>>> {
        match self.find_reader(file_id) {
            Some(accessor) => accessor.open_sequential_reader(file_id),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found in any directory",
            )),
        }
    }

    fn open_range_reader(&self, file_id: &FileId) -> io::Result<Option<Box<dyn FileRangeReader>>> {
        match self.find_reader(file_id) {
            Some(accessor) => accessor.open_range_reader(file_id),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found in any directory",
            )),
        }
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        self.find_reader(file_id).is_some()
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        self.find_reader(file_id)?.file_length(file_id)
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        match self.find_reader(file_id) {
            Some(accessor) => accessor.read_file(file_id),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found in any directory",
            )),
        }
    }

    fn write_file_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> io::Result<()> {
        self.primary.write_file_range(file_id, offset, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::checksum::SliceChecksumState;
    use crate::packet::header;
    use crate::par2_set::Par2FileSet;
    use crate::placement::scan_placement;
    use crate::types::SliceChecksum;
    use crate::verify::{FileStatus, verify_all};
    use md5::{Digest, Md5};
    use tempfile::TempDir;

    /// Helper to build a complete valid packet (header + body).
    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (header::HEADER_SIZE + body.len()) as u64;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);
        let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

        let mut data = Vec::new();
        data.extend_from_slice(header::MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    /// Build a Par2FileSet for testing with a known filename.
    fn setup_par2_set(file_data: &[u8], slice_size: u64, filename: &str) -> (Par2FileSet, FileId) {
        let file_length = file_data.len() as u64;
        let hash_full = checksum::md5(file_data);
        let hash_16k_data = &file_data[..file_data.len().min(16384)];
        let hash_16k = checksum::md5(hash_16k_data);

        let mut id_input = Vec::new();
        id_input.extend_from_slice(&hash_16k);
        id_input.extend_from_slice(&file_length.to_le_bytes());
        id_input.extend_from_slice(filename.as_bytes());
        let file_id_bytes: [u8; 16] = Md5::digest(&id_input).into();
        let file_id = FileId::from_bytes(file_id_bytes);

        let num_slices = if file_length == 0 {
            0
        } else {
            file_length.div_ceil(slice_size) as usize
        };

        let mut checksums = Vec::new();
        for i in 0..num_slices {
            let offset = i as u64 * slice_size;
            let end = ((offset + slice_size) as usize).min(file_data.len());
            let slice_data = &file_data[offset as usize..end];
            let mut state = SliceChecksumState::new();
            state.update(slice_data);
            let pad_to = if (slice_data.len() as u64) < slice_size {
                Some(slice_size)
            } else {
                None
            };
            let (crc, md5) = state.finalize(pad_to);
            checksums.push(SliceChecksum { crc32: crc, md5 });
        }

        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&1u32.to_le_bytes());
        main_body.extend_from_slice(&file_id_bytes);
        let rsid: [u8; 16] = Md5::digest(&main_body).into();

        let mut fd_body = Vec::new();
        fd_body.extend_from_slice(&file_id_bytes);
        fd_body.extend_from_slice(&hash_full);
        fd_body.extend_from_slice(&hash_16k);
        fd_body.extend_from_slice(&file_length.to_le_bytes());
        fd_body.extend_from_slice(filename.as_bytes());
        while fd_body.len() % 4 != 0 {
            fd_body.push(0);
        }

        let mut ifsc_body = Vec::new();
        ifsc_body.extend_from_slice(&file_id_bytes);
        for cs in &checksums {
            ifsc_body.extend_from_slice(&cs.md5);
            ifsc_body.extend_from_slice(&cs.crc32.to_le_bytes());
        }

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_IFSC, &ifsc_body, rsid));

        let set = Par2FileSet::from_files(&[&stream]).unwrap();
        (set, file_id)
    }

    fn setup_par2_set_multi(
        files: &[(&[u8], &str)],
        slice_size: u64,
    ) -> (Par2FileSet, Vec<FileId>) {
        let mut file_ids = Vec::new();
        let mut fd_bodies = Vec::new();
        let mut ifsc_bodies = Vec::new();

        for &(file_data, filename) in files {
            let file_length = file_data.len() as u64;
            let hash_full = checksum::md5(file_data);
            let hash_16k = checksum::md5(&file_data[..file_data.len().min(16384)]);

            let mut id_input = Vec::new();
            id_input.extend_from_slice(&hash_16k);
            id_input.extend_from_slice(&file_length.to_le_bytes());
            id_input.extend_from_slice(filename.as_bytes());
            let file_id_bytes: [u8; 16] = Md5::digest(&id_input).into();
            file_ids.push(FileId::from_bytes(file_id_bytes));

            let num_slices = if file_length == 0 {
                0
            } else {
                file_length.div_ceil(slice_size) as usize
            };

            let mut checksums = Vec::new();
            for i in 0..num_slices {
                let offset = i as u64 * slice_size;
                let end = ((offset + slice_size) as usize).min(file_data.len());
                let slice_data = &file_data[offset as usize..end];
                let mut state = SliceChecksumState::new();
                state.update(slice_data);
                let pad_to = if (slice_data.len() as u64) < slice_size {
                    Some(slice_size)
                } else {
                    None
                };
                let (crc, md5) = state.finalize(pad_to);
                checksums.push(SliceChecksum { crc32: crc, md5 });
            }

            let mut fd_body = Vec::new();
            fd_body.extend_from_slice(&file_id_bytes);
            fd_body.extend_from_slice(&hash_full);
            fd_body.extend_from_slice(&hash_16k);
            fd_body.extend_from_slice(&file_length.to_le_bytes());
            fd_body.extend_from_slice(filename.as_bytes());
            while fd_body.len() % 4 != 0 {
                fd_body.push(0);
            }
            fd_bodies.push(fd_body);

            let mut ifsc_body = Vec::new();
            ifsc_body.extend_from_slice(&file_id_bytes);
            for cs in &checksums {
                ifsc_body.extend_from_slice(&cs.md5);
                ifsc_body.extend_from_slice(&cs.crc32.to_le_bytes());
            }
            ifsc_bodies.push(ifsc_body);
        }

        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&(file_ids.len() as u32).to_le_bytes());
        for file_id in &file_ids {
            main_body.extend_from_slice(file_id.as_bytes());
        }
        let rsid: [u8; 16] = Md5::digest(&main_body).into();

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        for fd_body in &fd_bodies {
            stream.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, fd_body, rsid));
        }
        for ifsc_body in &ifsc_bodies {
            stream.extend_from_slice(&make_full_packet(header::TYPE_IFSC, ifsc_body, rsid));
        }

        let set = Par2FileSet::from_files(&[&stream]).unwrap();
        (set, file_ids)
    }

    #[test]
    fn disk_access_read_write_exists_length() {
        let dir = TempDir::new().unwrap();
        let file_data = b"Hello, PAR2 world!";
        let filename = "test.dat";

        // Write test file to tempdir
        std::fs::write(dir.path().join(filename), file_data).unwrap();

        let (par2_set, file_id) = setup_par2_set(file_data, 1024, filename);
        let mut access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        // file_exists
        assert!(access.file_exists(&file_id));

        // file_length
        assert_eq!(access.file_length(&file_id), Some(file_data.len() as u64));

        // read_file
        let read_all = access.read_file(&file_id).unwrap();
        assert_eq!(read_all, file_data);

        // read_file_range
        let range = access.read_file_range(&file_id, 7, 4).unwrap();
        assert_eq!(&range, b"PAR2");

        // write_file_range
        access.write_file_range(&file_id, 7, b"par2").unwrap();
        access.write_file_range(&file_id, 11, b"!").unwrap();
        assert_eq!(access.write_files.len(), 1);
        let after_write = access.read_file_range(&file_id, 7, 4).unwrap();
        assert_eq!(&after_write, b"par2");
    }

    #[test]
    fn disk_access_missing_file() {
        let dir = TempDir::new().unwrap();
        let file_data = b"data";
        let filename = "missing.dat";

        let (par2_set, file_id) = setup_par2_set(file_data, 1024, filename);
        let access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        assert!(!access.file_exists(&file_id));
        assert_eq!(access.file_length(&file_id), None);
        assert!(access.read_file(&file_id).is_err());
    }

    #[test]
    fn disk_access_unknown_file_id() {
        let dir = TempDir::new().unwrap();
        let file_data = b"data";
        let filename = "test.dat";

        let (par2_set, _) = setup_par2_set(file_data, 1024, filename);
        let access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        let unknown_id = FileId::from_bytes([0xFF; 16]);
        assert!(!access.file_exists(&unknown_id));
        assert_eq!(access.file_length(&unknown_id), None);
        assert!(access.read_file(&unknown_id).is_err());
    }

    #[test]
    fn disk_access_create_on_write() {
        let dir = TempDir::new().unwrap();
        let file_data = b"original";
        let filename = "newfile.dat";

        let (par2_set, file_id) = setup_par2_set(file_data, 1024, filename);
        let mut access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        // File does not exist yet
        assert!(!access.file_exists(&file_id));

        // Write creates the file
        access.write_file_range(&file_id, 0, b"created").unwrap();
        assert!(access.file_exists(&file_id));

        let content = access.read_file(&file_id).unwrap();
        assert_eq!(&content, b"created");
    }

    #[cfg(unix)]
    #[test]
    fn disk_access_rejects_symlink_destination() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_path = outside.path().join("outside.dat");
        std::fs::write(&outside_path, b"outside stays unchanged").unwrap();
        std::os::unix::fs::symlink(&outside_path, dir.path().join("victim.dat")).unwrap();

        let (par2_set, file_id) = setup_par2_set(b"repaired data", 1024, "victim.dat");
        let mut access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        assert!(
            access
                .write_file_range(&file_id, 0, b"repaired data")
                .is_err()
        );
        assert_eq!(
            std::fs::read(&outside_path).unwrap(),
            b"outside stays unchanged"
        );
        assert!(
            std::fs::symlink_metadata(dir.path().join("victim.dat"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn disk_access_rejects_symlink_parent() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_path = outside.path().join("victim.dat");
        std::fs::write(&outside_path, b"outside stays unchanged").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("nested")).unwrap();

        let (par2_set, file_id) = setup_par2_set(b"repaired data", 1024, "nested/victim.dat");
        let mut access = DiskFileAccess::new(dir.path().to_path_buf(), &par2_set);

        assert!(
            access
                .write_file_range(&file_id, 0, b"repaired data")
                .is_err()
        );
        assert_eq!(
            std::fs::read(&outside_path).unwrap(),
            b"outside stays unchanged"
        );
        assert!(
            std::fs::symlink_metadata(dir.path().join("nested"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rename_within_base_rejects_symlink_parent() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let source = dir.path().join("source.dat");
        let outside_target = outside.path().join("victim.dat");
        std::fs::write(&source, b"repaired data").unwrap();
        std::fs::write(&outside_target, b"outside stays unchanged").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("nested")).unwrap();

        assert!(
            rename_within_base(dir.path(), &source, &dir.path().join("nested/victim.dat")).is_err()
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"repaired data");
        assert_eq!(
            std::fs::read(&outside_target).unwrap(),
            b"outside stays unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn disk_access_allows_caller_selected_symlink_base() {
        let parent = TempDir::new().unwrap();
        let base = TempDir::new().unwrap();
        let base_link = parent.path().join("base-link");
        std::os::unix::fs::symlink(base.path(), &base_link).unwrap();

        let (par2_set, file_id) = setup_par2_set(b"repaired data", 1024, "created.dat");
        let mut access = DiskFileAccess::new(base_link, &par2_set);

        access
            .write_file_range(&file_id, 0, b"repaired data")
            .unwrap();
        assert_eq!(
            std::fs::read(base.path().join("created.dat")).unwrap(),
            b"repaired data"
        );
    }

    #[test]
    fn multi_dir_finds_file_in_secondary() {
        let primary = TempDir::new().unwrap();
        let secondary = TempDir::new().unwrap();
        let file_data = b"found in secondary";
        let filename = "target.dat";

        let (par2_set, file_id) = setup_par2_set(file_data, 1024, filename);

        // File only in secondary
        std::fs::write(secondary.path().join(filename), file_data).unwrap();

        let access = MultiDirectoryFileAccess::new(
            primary.path().to_path_buf(),
            vec![secondary.path().to_path_buf()],
            &par2_set,
        );

        assert!(access.file_exists(&file_id));
        assert_eq!(access.read_file(&file_id).unwrap(), file_data);
    }

    #[test]
    fn multi_dir_primary_wins() {
        let primary = TempDir::new().unwrap();
        let secondary = TempDir::new().unwrap();
        let filename = "target.dat";

        let (par2_set, file_id) = setup_par2_set(b"primary", 1024, filename);

        std::fs::write(primary.path().join(filename), b"primary").unwrap();
        std::fs::write(secondary.path().join(filename), b"secondary").unwrap();

        let access = MultiDirectoryFileAccess::new(
            primary.path().to_path_buf(),
            vec![secondary.path().to_path_buf()],
            &par2_set,
        );

        let content = access.read_file(&file_id).unwrap();
        assert_eq!(&content, b"primary");
    }

    #[test]
    fn multi_dir_write_goes_to_primary() {
        let primary = TempDir::new().unwrap();
        let secondary = TempDir::new().unwrap();
        let filename = "target.dat";

        let (par2_set, file_id) = setup_par2_set(b"data", 1024, filename);

        let mut access = MultiDirectoryFileAccess::new(
            primary.path().to_path_buf(),
            vec![secondary.path().to_path_buf()],
            &par2_set,
        );

        access.write_file_range(&file_id, 0, b"written").unwrap();
        assert!(primary.path().join(filename).exists());
        assert!(!secondary.path().join(filename).exists());
    }

    #[test]
    fn multi_dir_not_found_anywhere() {
        let primary = TempDir::new().unwrap();
        let secondary = TempDir::new().unwrap();

        let (par2_set, file_id) = setup_par2_set(b"data", 1024, "missing.dat");

        let access = MultiDirectoryFileAccess::new(
            primary.path().to_path_buf(),
            vec![secondary.path().to_path_buf()],
            &par2_set,
        );

        assert!(!access.file_exists(&file_id));
        assert!(access.read_file(&file_id).is_err());
    }

    #[test]
    fn placement_access_verifies_swapped_valid_names() {
        let dir = TempDir::new().unwrap();
        let data_a = b"placement-aware file A data";
        let data_b = b"placement-aware file B data";

        let (par2_set, _ids) =
            setup_par2_set_multi(&[(data_a, "file_a.rar"), (data_b, "file_b.rar")], 1024);

        std::fs::write(dir.path().join("file_a.rar"), data_b).unwrap();
        std::fs::write(dir.path().join("file_b.rar"), data_a).unwrap();

        let plan = scan_placement(dir.path(), &par2_set).unwrap();
        let access = PlacementFileAccess::from_plan(dir.path().to_path_buf(), &par2_set, &plan);
        let result = verify_all(&par2_set, &access);

        assert_eq!(result.total_missing_blocks, 0);
        assert!(
            result
                .files
                .iter()
                .all(|file| matches!(file.status, FileStatus::Complete))
        );
    }
}
