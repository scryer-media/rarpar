//! The output tree an extraction writes into, reached through directory
//! handles.
//!
//! On Unix the output folder is opened once, and every folder under it is
//! opened from its parent's handle without following a link (`openat` with
//! `O_NOFOLLOW`). Members are created, inspected, renamed and removed
//! relative to the handle of the folder they are in, so replacing a folder
//! on the way with a link after it was checked cannot redirect a write
//! outside the output folder. Elsewhere the same operations work on paths,
//! with each folder checked as it is reached.

#[cfg(unix)]
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::extract::FolderError;

/// What a directory entry is, as `lstat` sees it.
pub(super) struct Entry {
    pub dir: bool,
    pub link: bool,
    pub len: u64,
    /// Seconds since the Unix epoch.
    pub modified: Option<i64>,
}

/// The output folder and the folder handle last reached under it.
pub(super) struct OutTree {
    base: PathBuf,
    create_base: bool,
    root: Option<Folder>,
    last: Option<(Vec<String>, Folder)>,
}

impl OutTree {
    /// The tree under `base` (the current folder when empty), which is the
    /// caller's own and is trusted. Nothing is opened until it is used.
    pub fn new(base: &Path) -> Self {
        let create_base = !base.as_os_str().is_empty();
        Self {
            base: if create_base {
                base.to_path_buf()
            } else {
                PathBuf::from(".")
            },
            create_base,
            root: None,
            last: None,
        }
    }

    /// Drop the remembered folder handle: an entry under it was removed or
    /// renamed.
    pub fn forget(&mut self) {
        self.last = None;
    }

    /// The folder `parts` names under the output folder, each one reached
    /// from its parent's handle and never through a link. With `create`,
    /// missing folders are made.
    pub fn folder(&mut self, parts: &[String], create: bool) -> Result<&Folder, FolderError> {
        if self
            .last
            .as_ref()
            .is_none_or(|(cached, _)| cached.as_slice() != parts)
        {
            if self.root.is_none() {
                if self.create_base {
                    std::fs::create_dir_all(&self.base).map_err(FolderError::Io)?;
                }
                self.root = Some(Folder::open_root(&self.base).map_err(FolderError::Io)?);
            }
            let root = self.root.as_ref().expect("opened above");
            let mut current: Option<Folder> = None;
            for part in parts {
                let parent = current.as_ref().unwrap_or(root);
                current = Some(step(parent, part, create)?);
            }
            let folder = match current {
                Some(folder) => folder,
                None => root.try_clone().map_err(FolderError::Io)?,
            };
            self.last = Some((parts.to_vec(), folder));
        }
        Ok(&self.last.as_ref().expect("set above").1)
    }
}

/// The folder `part` in `parent`, made when missing and `create` is set.
fn step(parent: &Folder, part: &str, create: bool) -> Result<Folder, FolderError> {
    if let Ok(folder) = parent.open_dir(part) {
        return Ok(folder);
    }
    let not_dir = || {
        FolderError::Io(io::Error::from_raw_os_error(
            #[cfg(unix)]
            libc::ENOTDIR,
            #[cfg(not(unix))]
            267, // ERROR_DIRECTORY
        ))
    };
    let judge = |error: io::Error| match parent.stat(part) {
        Ok(entry) if entry.link => FolderError::Link,
        Ok(entry) if !entry.dir => not_dir(),
        _ => FolderError::Io(error),
    };
    match parent.stat(part) {
        Ok(entry) if entry.link => return Err(FolderError::Link),
        Ok(entry) if !entry.dir => return Err(not_dir()),
        Ok(_) => return parent.open_dir(part).map_err(judge),
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {}
        Err(error) => return Err(FolderError::Io(error)),
    }
    match parent.make_dir(part) {
        // Raced: whatever is there now is judged as it is opened.
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(FolderError::Io(error)),
    }
    parent.open_dir(part).map_err(judge)
}

#[cfg(unix)]
pub(super) use unix::Folder;

#[cfg(not(unix))]
pub(super) use paths::Folder;

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::Entry;

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    fn c_text(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// An open folder.
    pub(in super::super) struct Folder(OwnedFd);

    impl Folder {
        pub fn open_root(path: &Path) -> io::Result<Self> {
            let path = c_text(path.as_os_str().as_bytes())?;
            // SAFETY: `path` is a NUL-terminated string that outlives the call.
            let fd = check(unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            // SAFETY: `open` returned a new descriptor this value now owns.
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }

        /// `openat` relative to this folder, never following a link at
        /// `name`.
        fn open_at(
            &self,
            name: &CStr,
            flags: libc::c_int,
            mode: libc::c_uint,
        ) -> io::Result<OwnedFd> {
            // SAFETY: the descriptor is open for as long as `self` is, and
            // `name` is a NUL-terminated string that outlives the call.
            let fd = check(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    mode,
                )
            })?;
            // SAFETY: `openat` returned a new descriptor this value now owns.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }

        pub fn open_dir(&self, name: &str) -> io::Result<Self> {
            let name = c_text(name.as_bytes())?;
            self.open_at(&name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map(Self)
        }

        pub fn make_dir(&self, name: &str) -> io::Result<()> {
            let name = c_text(name.as_bytes())?;
            // SAFETY: as for `open_at`.
            check(unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o777) })?;
            Ok(())
        }

        pub fn stat(&self, name: &str) -> io::Result<Entry> {
            let name = c_text(name.as_bytes())?;
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: as for `open_at`; `stat` is written in full on success.
            check(unsafe {
                libc::fstatat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            // SAFETY: `fstatat` succeeded.
            let stat = unsafe { stat.assume_init() };
            let kind = stat.st_mode & libc::S_IFMT;
            // `time_t` is narrower than 64 bits on some targets.
            #[allow(clippy::useless_conversion)]
            let modified = i64::from(stat.st_mtime);
            Ok(Entry {
                dir: kind == libc::S_IFDIR,
                link: kind == libc::S_IFLNK,
                len: stat.st_size as u64,
                modified: Some(modified),
            })
        }

        /// A new or truncated file at `name`, never written through a link.
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            let name = c_text(name.as_bytes())?;
            self.open_at(&name, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o666)
                .map(File::from)
        }

        pub fn remove(&self, name: &str, dir: bool) -> io::Result<()> {
            let name = c_text(name.as_bytes())?;
            let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
            // SAFETY: as for `open_at`.
            check(unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), flags) })?;
            Ok(())
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            let (from, to) = (c_text(from.as_bytes())?, c_text(to.as_bytes())?);
            let fd = self.0.as_raw_fd();
            // SAFETY: as for `open_at`, for both names.
            check(unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) })?;
            Ok(())
        }

        pub fn symlink(&self, target: &Path, name: &str) -> io::Result<()> {
            let target = c_text(target.as_os_str().as_bytes())?;
            let name = c_text(name.as_bytes())?;
            // SAFETY: as for `open_at`, for both strings.
            check(unsafe { libc::symlinkat(target.as_ptr(), self.0.as_raw_fd(), name.as_ptr()) })?;
            Ok(())
        }

        /// Set a link's own access and modification times.
        pub fn set_link_times(&self, name: &str, time: filetime::FileTime) -> io::Result<()> {
            let name = c_text(name.as_bytes())?;
            let spec = libc::timespec {
                tv_sec: time.unix_seconds() as libc::time_t,
                tv_nsec: libc::c_long::from(time.nanoseconds() as i32),
            };
            let times = [spec, spec];
            // SAFETY: as for `open_at`; `times` holds the two entries
            // `utimensat` reads.
            check(unsafe {
                libc::utimensat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            Ok(())
        }

        /// The folder itself, as a file whose times and mode can be set.
        pub fn handle(&self) -> io::Result<File> {
            self.0.try_clone().map(File::from)
        }
    }
}

#[cfg(not(unix))]
mod paths {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    use super::Entry;

    /// A folder, by path; each one is checked as it is reached.
    pub(in super::super) struct Folder(PathBuf);

    impl Folder {
        pub fn open_root(path: &Path) -> io::Result<Self> {
            if fs::metadata(path)?.is_dir() {
                Ok(Self(path.to_path_buf()))
            } else {
                Err(io::Error::from_raw_os_error(267))
            }
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            Ok(Self(self.0.clone()))
        }

        pub fn open_dir(&self, name: &str) -> io::Result<Self> {
            let path = self.0.join(name);
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(io::Error::from_raw_os_error(267));
            }
            Ok(Self(path))
        }

        pub fn make_dir(&self, name: &str) -> io::Result<()> {
            fs::create_dir(self.0.join(name))
        }

        pub fn stat(&self, name: &str) -> io::Result<Entry> {
            let meta = fs::symlink_metadata(self.0.join(name))?;
            let modified =
                meta.modified()
                    .ok()
                    .map(|time| match time.duration_since(std::time::UNIX_EPOCH) {
                        Ok(after) => after.as_secs() as i64,
                        Err(before) => -(before.duration().as_secs() as i64),
                    });
            Ok(Entry {
                dir: meta.is_dir(),
                link: meta.file_type().is_symlink(),
                len: meta.len(),
                modified,
            })
        }

        pub fn create_file(&self, name: &str) -> io::Result<File> {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.0.join(name))
        }

        pub fn remove(&self, name: &str, dir: bool) -> io::Result<()> {
            let path = self.0.join(name);
            if dir {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            }
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            fs::rename(self.0.join(from), self.0.join(to))
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }
}

/// Apply a member's time and attributes through its open file.
#[cfg(unix)]
pub(super) fn apply_to_handle(file: &File, mtime: Option<filetime::FileTime>, attrib: Option<u32>) {
    if let Some(time) = mtime {
        let _ = filetime::set_file_handle_times(file, Some(time), Some(time));
    }
    let Some(attrib) = attrib else {
        return;
    };
    use super::format::{ATTRIB_READONLY, ATTRIB_UNIX_EXTENSION};
    use std::os::unix::fs::PermissionsExt;
    if attrib & ATTRIB_UNIX_EXTENSION != 0 {
        let mode = (attrib >> 16) & 0o7777;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(mode));
    } else if attrib & ATTRIB_READONLY != 0
        && let Ok(meta) = file.metadata()
    {
        let mode = meta.permissions().mode() & !0o222;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(mode));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn parts(list: &[&str]) -> Vec<String> {
        list.iter().map(|part| (*part).to_owned()).collect()
    }

    /// A folder reached once keeps its handle: replacing it with a link
    /// afterwards does not move where its members are created.
    #[test]
    fn members_are_created_through_the_retained_folder_handle() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let mut tree = OutTree::new(&out);
        tree.folder(&parts(&["nest"]), true).ok().unwrap();
        std::fs::rename(out.join("nest"), out.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("nest")).unwrap();
        let folder = tree.folder(&parts(&["nest"]), true).ok().unwrap();
        drop(folder.create_file("ember.txt").unwrap());
        assert!(out.join("moved/ember.txt").is_file());
        assert!(!outside.join("ember.txt").exists());

        // Reached afresh, the linked folder is refused, never followed.
        tree.forget();
        assert!(matches!(
            tree.folder(&parts(&["nest", "deeper"]), true),
            Err(FolderError::Link)
        ));
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// A link at a member's own name is never written through.
    #[test]
    fn a_link_at_the_member_name_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"kept").unwrap();
        let out = dir.path().join("out");
        let mut tree = OutTree::new(&out);
        let root = tree.folder(&[], true).ok().unwrap();
        std::os::unix::fs::symlink(&target, out.join("decoy.txt")).unwrap();
        assert!(root.create_file("decoy.txt").is_err());
        assert!(root.stat("decoy.txt").unwrap().link);
        assert_eq!(std::fs::read(&target).unwrap(), b"kept");
    }
}
