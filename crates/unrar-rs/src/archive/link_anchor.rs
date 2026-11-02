//! Anchored resolution of hard-link and file-copy targets.
//!
//! A RAR5 hard-link or file-copy record names its target relative to the
//! extraction root. Resolving that name as a path lets a symlink, junction or
//! other reparse point anywhere in it redirect the link or copy to a file
//! outside the root, and lets a concurrent writer swap a real directory for
//! one between a check and the link. UnRAR 7.30 beta 2 refuses a hard-link
//! target that passes through a symlink; this module does the same for hard
//! links and file copies.
//!
//! On Unix every component is opened relative to the previous one with
//! `O_NOFOLLOW | O_DIRECTORY`, the final component is inspected with
//! `fstatat(AT_SYMLINK_NOFOLLOW)`, and the link is made with
//! `linkat(src_dir, name, dst_dir, name, 0)`, so the directory handles held
//! from check through use pin the exact directories that were checked. Mode
//! restore runs on a descriptor opened `O_NOFOLLOW` from the anchored output
//! directory whose device and inode match the file just checked.
//!
//! On Windows every component is opened with `FILE_FLAG_OPEN_REPARSE_POINT`
//! and refused when it carries `FILE_ATTRIBUTE_REPARSE_POINT`; directory
//! handles are held without `FILE_SHARE_DELETE`, so none of them can be
//! renamed, deleted or replaced by a junction until the link exists. Win32
//! has no handle-relative `CreateHardLinkW`, so the link itself is made by
//! path through those pinned directories; the target file is held with
//! delete sharing (the link call opens it for delete) and the new link is
//! reopened without following reparse points and compared by volume serial
//! and file index before its attributes are set through that handle.
//!
//! Any component that is a symlink or reparse point is refused, including
//! one that points inside the root, as UnRAR does.
//!
//! Other targets (wasm) keep the path-based link code in `member.rs`; this
//! module's shared helpers are unused there.
#![cfg_attr(not(any(unix, windows)), allow(dead_code))]

/// Why an anchored resolution failed.
#[derive(Debug)]
pub(super) enum AnchorError {
    /// A component is a symlink or reparse point, a directory component is
    /// not a directory, or the name climbs above the root.
    Unsafe,
    /// Any other I/O failure, including `NotFound` for a missing component.
    Io(std::io::Error),
}

impl From<std::io::Error> for AnchorError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// One component of a target name, after `.` and empty parts are dropped.
#[derive(Debug, PartialEq, Eq)]
enum Part<'a> {
    Parent,
    Name(&'a str),
}

/// Splits a `/`-separated target name into the components to walk.
fn parts(relative: &str) -> Vec<Part<'_>> {
    relative
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(|part| {
            if part == ".." {
                Part::Parent
            } else {
                Part::Name(part)
            }
        })
        .collect()
}

/// Splits `relative` into its directory walk and its final name. A name
/// that ends in `..`, or is empty, does not name a file.
fn split_final(relative: &str) -> Result<(Vec<Part<'_>>, &str), AnchorError> {
    let mut walk = parts(relative);
    match walk.pop() {
        Some(Part::Name(name)) => Ok((walk, name)),
        Some(Part::Parent) | None => Err(AnchorError::Unsafe),
    }
}

fn not_regular_file() -> AnchorError {
    AnchorError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "link target is not a regular file",
    ))
}

#[cfg(unix)]
pub(super) use unix::{AnchoredTarget, OutputDir};

#[cfg(windows)]
pub(super) use windows::AnchoredTarget;

#[cfg(unix)]
mod unix {
    use super::{AnchorError, Part, not_regular_file, split_final};
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const DIR_OPEN_FLAGS: libc::c_int =
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const DIR_OPEN_FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    fn c_name(name: &[u8]) -> Result<CString, AnchorError> {
        CString::new(name).map_err(|_| {
            AnchorError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link path contains a NUL byte",
            ))
        })
    }

    fn lstat_at(dir: RawFd, name: &CStr) -> std::io::Result<libc::stat> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `name` is NUL-terminated and `stat` is a valid out pointer.
        let rc = unsafe {
            libc::fstatat(
                dir,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstatat succeeded and filled `stat`.
        Ok(unsafe { stat.assume_init() })
    }

    fn fstat(fd: RawFd) -> std::io::Result<libc::stat> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `fd` is an open descriptor and `stat` a valid out pointer.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstat succeeded and filled `stat`.
        Ok(unsafe { stat.assume_init() })
    }

    /// Permission bits as the platform's `mode_t` (`u16` on Apple targets).
    #[allow(clippy::unnecessary_cast)]
    fn mode_t(mode: u32) -> libc::mode_t {
        (mode & 0o7777) as libc::mode_t
    }

    fn file_type(stat: &libc::stat) -> libc::mode_t {
        stat.st_mode & libc::S_IFMT
    }

    fn open_root(root: &Path) -> Result<OwnedFd, AnchorError> {
        let root = if root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            root
        };
        let path = c_name(root.as_os_str().as_bytes())?;
        // The extraction root is the caller's choice and may itself be
        // reached through a symlink; only the components beneath it are
        // archive-controlled, so no O_NOFOLLOW here. On Linux and Android
        // O_PATH needs only search permission, so a write-and-search root
        // without read permission still extracts, as it did before.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // SAFETY: `path` is NUL-terminated.
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd < 0 {
            return Err(AnchorError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` is a freshly opened descriptor we own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Opens directory `name` beneath `parent` without following a symlink.
    fn open_child_dir(parent: RawFd, name: &str) -> Result<OwnedFd, AnchorError> {
        let c = c_name(name.as_bytes())?;
        // SAFETY: `c` is NUL-terminated and `parent` is an open directory.
        let fd = unsafe { libc::openat(parent, c.as_ptr(), DIR_OPEN_FLAGS) };
        if fd >= 0 {
            // SAFETY: `fd` is a freshly opened descriptor we own.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let error = std::io::Error::last_os_error();
        // ELOOP, ENOTDIR and (on some BSDs) EMLINK all mean "not a real
        // directory"; classify by looking at the entry itself rather than
        // trusting each platform's errno for O_NOFOLLOW.
        match lstat_at(parent, &c) {
            Ok(stat) if file_type(&stat) != libc::S_IFDIR => Err(AnchorError::Unsafe),
            _ => Err(AnchorError::Io(error)),
        }
    }

    /// Walks `walk` beneath `root`, refusing symlinks and climbs above it.
    fn walk_dirs(root: OwnedFd, walk: &[Part<'_>]) -> Result<OwnedFd, AnchorError> {
        let mut stack: Vec<OwnedFd> = vec![root];
        for part in walk {
            match part {
                Part::Parent => {
                    if stack.len() == 1 {
                        return Err(AnchorError::Unsafe);
                    }
                    stack.pop();
                }
                Part::Name(name) => {
                    let parent = stack.last().expect("root stays on the stack").as_raw_fd();
                    let child = open_child_dir(parent, name)?;
                    stack.push(child);
                }
            }
        }
        Ok(stack.pop().expect("root stays on the stack"))
    }

    /// A regular file found beneath an extraction root without following a
    /// symlink, with the directory that holds it kept open.
    #[derive(Debug)]
    pub(in crate::archive) struct AnchoredTarget {
        dir: OwnedFd,
        name: CString,
        dev: u64,
        ino: u64,
    }

    impl AnchoredTarget {
        /// Resolves the `/`-separated `relative` beneath `root`.
        pub(in crate::archive) fn resolve(
            root: &Path,
            relative: &str,
        ) -> Result<Self, AnchorError> {
            Self::resolve_with_hook(root, relative, || {})
        }

        /// [`Self::resolve`], running `after_walk` once the directory walk
        /// is done and before the final component is inspected. Tests use
        /// the hook to swap a directory for a symlink inside the window.
        pub(in crate::archive) fn resolve_with_hook(
            root: &Path,
            relative: &str,
            after_walk: impl FnOnce(),
        ) -> Result<Self, AnchorError> {
            let (walk, name) = split_final(relative)?;
            let dir = walk_dirs(open_root(root)?, &walk)?;
            after_walk();
            let name = c_name(name.as_bytes())?;
            let stat = lstat_at(dir.as_raw_fd(), &name)?;
            match file_type(&stat) {
                libc::S_IFREG => {}
                libc::S_IFLNK => return Err(AnchorError::Unsafe),
                _ => return Err(not_regular_file()),
            }
            Ok(Self {
                dir,
                name,
                #[allow(clippy::unnecessary_cast)]
                dev: stat.st_dev as u64,
                #[allow(clippy::unnecessary_cast)]
                ino: stat.st_ino as u64,
            })
        }

        /// Opens the target for reading, refusing it if it was replaced
        /// since [`Self::resolve`] checked it.
        pub(in crate::archive) fn open_read(&self) -> Result<std::fs::File, AnchorError> {
            // SAFETY: `name` is NUL-terminated and `dir` is open.
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                return Err(if error.raw_os_error() == Some(libc::ELOOP) {
                    AnchorError::Unsafe
                } else {
                    AnchorError::Io(error)
                });
            }
            // SAFETY: `fd` is a freshly opened descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let stat = fstat(fd.as_raw_fd())?;
            if !self.same_file(&stat) {
                return Err(AnchorError::Unsafe);
            }
            Ok(std::fs::File::from(fd))
        }

        fn same_file(&self, stat: &libc::stat) -> bool {
            #[allow(clippy::unnecessary_cast)]
            let same = stat.st_dev as u64 == self.dev && stat.st_ino as u64 == self.ino;
            same && file_type(stat) == libc::S_IFREG
        }

        /// Hard-links the target as `out.name` in `out`'s directory, then
        /// sets `mode` on the file just linked when one is given.
        pub(in crate::archive) fn hard_link_into(
            &self,
            out: &OutputDir,
            mode: Option<u32>,
        ) -> Result<(), AnchorError> {
            // SAFETY: both names are NUL-terminated and both dirs are open.
            // No AT_SYMLINK_FOLLOW: a final component swapped for a symlink
            // after the check is linked as the symlink itself, which the
            // identity check below then refuses.
            let rc = unsafe {
                libc::linkat(
                    self.dir.as_raw_fd(),
                    self.name.as_ptr(),
                    out.dir.as_raw_fd(),
                    out.name.as_ptr(),
                    0,
                )
            };
            if rc != 0 {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            if let Err(error) = self.restore_mode(out, mode) {
                // SAFETY: as above; removes only the name this call created.
                unsafe {
                    libc::unlinkat(out.dir.as_raw_fd(), out.name.as_ptr(), 0);
                }
                return Err(error);
            }
            Ok(())
        }

        fn restore_mode(&self, out: &OutputDir, mode: Option<u32>) -> Result<(), AnchorError> {
            // SAFETY: `name` is NUL-terminated and `dir` is open.
            let fd = unsafe {
                libc::openat(
                    out.dir.as_raw_fd(),
                    out.name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                // SAFETY: `fd` is a freshly opened descriptor we own.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                let stat = fstat(fd.as_raw_fd())?;
                if !self.same_file(&stat) {
                    return Err(AnchorError::Unsafe);
                }
                if let Some(mode) = mode {
                    // SAFETY: `fd` is open.
                    if unsafe { libc::fchmod(fd.as_raw_fd(), mode_t(mode)) } != 0 {
                        return Err(AnchorError::Io(std::io::Error::last_os_error()));
                    }
                }
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ELOOP) => Err(AnchorError::Unsafe),
                // The file is not readable by this process: fall back to a
                // descriptor that needs no read permission.
                Some(libc::EACCES) | Some(libc::EPERM) => self.restore_mode_unreadable(out, mode),
                _ => Err(AnchorError::Io(error)),
            }
        }

        /// Linux and Android: an `O_PATH` descriptor needs no permission on
        /// the file, and `/proc/self/fd/N` names exactly that inode, so the
        /// chmod cannot be redirected. Without `/proc` the restore fails
        /// rather than fall back to a path.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn restore_mode_unreadable(
            &self,
            out: &OutputDir,
            mode: Option<u32>,
        ) -> Result<(), AnchorError> {
            // SAFETY: `name` is NUL-terminated and `dir` is open.
            let fd = unsafe {
                libc::openat(
                    out.dir.as_raw_fd(),
                    out.name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            // SAFETY: `fd` is a freshly opened descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let stat = fstat(fd.as_raw_fd())?;
            if !self.same_file(&stat) {
                return Err(AnchorError::Unsafe);
            }
            let Some(mode) = mode else {
                return Ok(());
            };
            let proc_path = c_name(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
            // SAFETY: `proc_path` is NUL-terminated.
            if unsafe { libc::chmod(proc_path.as_ptr(), mode_t(mode)) } != 0 {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        /// Other Unix targets have a reliable `AT_SYMLINK_NOFOLLOW` for
        /// `fchmodat`. The name is checked against the linked inode first;
        /// the remaining window needs write access to the output directory
        /// and a target this process cannot read.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        fn restore_mode_unreadable(
            &self,
            out: &OutputDir,
            mode: Option<u32>,
        ) -> Result<(), AnchorError> {
            let stat = lstat_at(out.dir.as_raw_fd(), &out.name)?;
            if !self.same_file(&stat) {
                return Err(AnchorError::Unsafe);
            }
            let Some(mode) = mode else {
                return Ok(());
            };
            // SAFETY: `name` is NUL-terminated and `dir` is open.
            let rc = unsafe {
                libc::fchmodat(
                    out.dir.as_raw_fd(),
                    out.name.as_ptr(),
                    mode_t(mode),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }

    /// The directory a link output goes in, opened beneath the extraction
    /// root without following a symlink when the output path is the member
    /// path under that root.
    #[derive(Debug)]
    pub(in crate::archive) struct OutputDir {
        dir: OwnedFd,
        name: CString,
    }

    impl OutputDir {
        pub(in crate::archive) fn open(
            root: &Path,
            member_name: &str,
            out_path: &Path,
        ) -> Result<Self, AnchorError> {
            let file_name = out_path.file_name().ok_or_else(|| {
                AnchorError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("link output path {} has no file name", out_path.display()),
                ))
            })?;
            let name = c_name(file_name.as_bytes())?;
            let member_path = Path::new(member_name);
            let dir = if !member_name.is_empty() && out_path.ends_with(member_path) {
                let member = member_path.to_string_lossy();
                let (walk, _) = split_final(&member)?;
                walk_dirs(open_root(root)?, &walk)?
            } else {
                let parent = out_path.parent().unwrap_or_else(|| Path::new(""));
                open_root(parent)?
            };
            Ok(Self { dir, name })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn assert_unsafe(result: Result<AnchoredTarget, AnchorError>) {
            assert!(
                matches!(result, Err(AnchorError::Unsafe)),
                "expected an unsafe-target refusal, got {result:?}"
            );
        }

        #[test]
        fn resolves_a_real_nested_file() {
            let temp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(temp.path().join("dir/sub")).unwrap();
            std::fs::write(temp.path().join("dir/sub/file.bin"), b"x").unwrap();
            AnchoredTarget::resolve(temp.path(), "dir/sub/file.bin").unwrap();
            AnchoredTarget::resolve(temp.path(), "dir/./sub//file.bin").unwrap();
            AnchoredTarget::resolve(temp.path(), "dir/sub/../sub/file.bin").unwrap();
        }

        /// A root with write and search permission but no read permission
        /// still resolves, since `O_PATH` needs only search permission.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn resolves_beneath_a_root_without_read_permission() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir_all(root.join("dir")).unwrap();
            std::fs::write(root.join("dir/file.bin"), b"x").unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).unwrap();
            let result = AnchoredTarget::resolve(&root, "dir/file.bin");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            result.unwrap();
        }

        #[test]
        fn refuses_a_climb_above_the_root() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(temp.path().join("outside.bin"), b"x").unwrap();
            assert_unsafe(AnchoredTarget::resolve(&root, "../outside.bin"));
            assert_unsafe(AnchoredTarget::resolve(&root, "dir/.."));
        }

        #[test]
        fn refuses_symlinks_anywhere_in_the_target() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("file.bin"), b"x").unwrap();
            std::fs::write(root.join("real/file.bin"), b"x").unwrap();
            std::os::unix::fs::symlink(&outside, root.join("dir")).unwrap();
            std::os::unix::fs::symlink(root.join("dir"), root.join("chain")).unwrap();
            std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
            std::os::unix::fs::symlink("real/file.bin", root.join("final")).unwrap();

            assert_unsafe(AnchoredTarget::resolve(&root, "dir/file.bin"));
            assert_unsafe(AnchoredTarget::resolve(&root, "chain/file.bin"));
            assert_unsafe(AnchoredTarget::resolve(&root, "alias/file.bin"));
            assert_unsafe(AnchoredTarget::resolve(&root, "final"));
            // A `..` that would leave the symlink first still walks through it.
            assert_unsafe(AnchoredTarget::resolve(&root, "dir/../real/file.bin"));
        }

        #[test]
        fn refuses_a_regular_file_used_as_a_directory() {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("plain"), b"x").unwrap();
            assert_unsafe(AnchoredTarget::resolve(temp.path(), "plain/file.bin"));
        }

        #[test]
        fn missing_target_is_not_found() {
            let temp = tempfile::tempdir().unwrap();
            match AnchoredTarget::resolve(temp.path(), "nope/file.bin") {
                Err(AnchorError::Io(error)) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::NotFound)
                }
                other => panic!("expected NotFound, got {other:?}"),
            }
        }

        /// The check/use race, made deterministic: the walk has opened
        /// `root/dir`, then the directory is renamed away and replaced by a
        /// symlink to an outside directory holding a same-named file. The
        /// held handle still names the original directory, so the link
        /// lands on the original file and the outside file is untouched.
        #[test]
        fn swap_after_the_walk_cannot_redirect_the_link() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            std::fs::create_dir_all(root.join("dir")).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(root.join("dir/file.bin"), b"inside").unwrap();
            std::fs::write(outside.join("file.bin"), b"outside").unwrap();
            std::fs::set_permissions(
                outside.join("file.bin"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let outside_before = std::fs::metadata(outside.join("file.bin")).unwrap();

            let target = AnchoredTarget::resolve_with_hook(&root, "dir/file.bin", || {
                std::fs::rename(root.join("dir"), root.join("moved")).unwrap();
                std::os::unix::fs::symlink(&outside, root.join("dir")).unwrap();
            })
            .unwrap();
            let out = OutputDir::open(&root, "link.bin", &root.join("link.bin")).unwrap();
            target.hard_link_into(&out, Some(0o644)).unwrap();

            let link = std::fs::metadata(root.join("link.bin")).unwrap();
            let moved = std::fs::metadata(root.join("moved/file.bin")).unwrap();
            assert_eq!(link.ino(), moved.ino());
            assert_eq!(std::fs::read(root.join("link.bin")).unwrap(), b"inside");
            let outside_after = std::fs::metadata(outside.join("file.bin")).unwrap();
            assert_eq!(outside_after.ino(), outside_before.ino());
            assert_eq!(outside_after.nlink(), 1);
            assert_eq!(outside_after.mode() & 0o7777, 0o600);
            assert_eq!(std::fs::read(outside.join("file.bin")).unwrap(), b"outside");
        }

        /// The final name swapped for a symlink after the check: the link is
        /// made to the symlink itself (no `AT_SYMLINK_FOLLOW`), the identity
        /// check refuses it, the new name is removed and the symlink's
        /// outside target keeps its mode.
        #[test]
        fn final_component_swap_is_refused_and_rolled_back() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let outside = temp.path().join("outside.bin");
            std::fs::write(&outside, b"outside").unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(root.join("file.bin"), b"inside").unwrap();

            let target = AnchoredTarget::resolve(&root, "file.bin").unwrap();
            std::fs::remove_file(root.join("file.bin")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("file.bin")).unwrap();
            let out = OutputDir::open(&root, "link.bin", &root.join("link.bin")).unwrap();
            assert!(matches!(
                target.hard_link_into(&out, Some(0o777)),
                Err(AnchorError::Unsafe)
            ));
            assert!(std::fs::symlink_metadata(root.join("link.bin")).is_err());
            let after = std::fs::metadata(&outside).unwrap();
            assert_eq!(after.mode() & 0o7777, 0o600);
            assert_eq!(after.nlink(), 1);
        }

        #[test]
        fn open_read_refuses_a_swapped_file() {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("file.bin"), b"one").unwrap();
            let target = AnchoredTarget::resolve(temp.path(), "file.bin").unwrap();
            // Create the replacement while the original still holds its
            // inode, so a filesystem that recycles freed inodes cannot hand
            // the replacement the original's identity.
            std::fs::write(temp.path().join("other.bin"), b"two").unwrap();
            std::fs::rename(temp.path().join("other.bin"), temp.path().join("file.bin")).unwrap();
            assert!(matches!(target.open_read(), Err(AnchorError::Unsafe)));
        }

        #[test]
        fn output_dir_refuses_a_symlinked_member_parent() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();
            let result = OutputDir::open(&root, "sub/link.bin", &root.join("sub/link.bin"));
            assert!(matches!(result, Err(AnchorError::Unsafe)));
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{AnchorError, Part, not_regular_file, split_final};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileBasicInfo, GetFileInformationByHandle,
        ReOpenFile, SetFileInformationByHandle,
    };

    fn open(path: &Path, access: u32, share: u32, follow: bool) -> std::io::Result<std::fs::File> {
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .custom_flags(flags)
            .open(path)
    }

    fn is_reparse(metadata: &std::fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    fn identity(file: &std::fs::File) -> std::io::Result<(u32, u32, u32)> {
        // SAFETY: zero is a valid bit pattern for this plain C struct.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open and `info` is a valid out pointer.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }

    /// A regular file found beneath an extraction root through no reparse
    /// point, with every directory on the way held open without delete
    /// sharing so none can be renamed or replaced while the link is made.
    #[derive(Debug)]
    pub(in crate::archive) struct AnchoredTarget {
        _dirs: Vec<std::fs::File>,
        file: std::fs::File,
        path: PathBuf,
    }

    impl AnchoredTarget {
        pub(in crate::archive) fn resolve(
            root: &Path,
            relative: &str,
        ) -> Result<Self, AnchorError> {
            let (walk, name) = split_final(relative)?;
            let pin = FILE_SHARE_READ | FILE_SHARE_WRITE;
            // An output path with no directory part extracts into the
            // current directory, as the Unix side does.
            let root = if root.as_os_str().is_empty() {
                Path::new(".")
            } else {
                root
            };
            // The root is the caller's choice and may be a junction itself.
            let mut dirs = vec![open(root, FILE_READ_ATTRIBUTES, pin, true)?];
            let mut path = root.to_path_buf();
            for part in &walk {
                match part {
                    Part::Parent => {
                        if dirs.len() == 1 {
                            return Err(AnchorError::Unsafe);
                        }
                        dirs.pop();
                        path.pop();
                    }
                    Part::Name(name) => {
                        if name.contains(':') {
                            return Err(AnchorError::Unsafe);
                        }
                        path.push(name);
                        let dir = open(&path, FILE_READ_ATTRIBUTES, pin, false)?;
                        let metadata = dir.metadata()?;
                        if is_reparse(&metadata) || !metadata.is_dir() {
                            return Err(AnchorError::Unsafe);
                        }
                        dirs.push(dir);
                    }
                }
            }
            if name.contains(':') {
                return Err(AnchorError::Unsafe);
            }
            path.push(name);
            // `CreateHardLinkW` opens the source for delete, so the file
            // handle must share delete; the identity check after the link
            // covers a swap of this last name. Attribute access only: a
            // hard link never reads the data, so an ACL that denies reading
            // must not refuse it. `open_read` asks for data access itself.
            let file = open(
                &path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                false,
            )?;
            let metadata = file.metadata()?;
            if is_reparse(&metadata) {
                return Err(AnchorError::Unsafe);
            }
            if !metadata.is_file() {
                return Err(not_regular_file());
            }
            Ok(Self {
                _dirs: dirs,
                file,
                path,
            })
        }

        /// The checked file itself, reopened for reading. `ReOpenFile`
        /// opens the same file object as the checked handle, never a path,
        /// so a swapped name cannot redirect it.
        pub(in crate::archive) fn open_read(&self) -> Result<std::fs::File, AnchorError> {
            // SAFETY: `self.file` is an open handle owned by `self`.
            let handle = unsafe {
                ReOpenFile(
                    self.file.as_raw_handle() as _,
                    FILE_GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            // SAFETY: `handle` is a valid handle we now own.
            let file = unsafe { std::fs::File::from_raw_handle(handle as _) };
            if identity(&file)? != identity(&self.file)? {
                return Err(AnchorError::Unsafe);
            }
            Ok(file)
        }

        /// Hard-links the target at `out_path` and sets `attributes` on the
        /// new link through a handle verified to be the checked file.
        ///
        /// Residual race: `out_path`'s own parent directories are not
        /// pinned here (they were prepared by the member-path checks just
        /// before), and the root path above the pinned root handle is
        /// trusted as the caller's choice.
        pub(in crate::archive) fn hard_link_to(
            &self,
            out_path: &Path,
            attributes: u32,
        ) -> Result<(), AnchorError> {
            std::fs::hard_link(&self.path, out_path)?;
            if let Err(error) = self.restore_attributes(out_path, attributes) {
                let _ = std::fs::remove_file(out_path);
                return Err(error);
            }
            Ok(())
        }

        fn restore_attributes(&self, out_path: &Path, attributes: u32) -> Result<(), AnchorError> {
            let link = open(
                out_path,
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                false,
            )?;
            let metadata = link.metadata()?;
            if is_reparse(&metadata) || identity(&link)? != identity(&self.file)? {
                return Err(AnchorError::Unsafe);
            }
            let info = FILE_BASIC_INFO {
                CreationTime: 0,
                LastAccessTime: 0,
                LastWriteTime: 0,
                ChangeTime: 0,
                FileAttributes: if attributes == 0 {
                    FILE_ATTRIBUTE_NORMAL
                } else {
                    attributes
                },
            };
            // SAFETY: the handle is open with FILE_WRITE_ATTRIBUTES and
            // `info` is a valid FILE_BASIC_INFO of the size passed.
            let ok = unsafe {
                SetFileInformationByHandle(
                    link.as_raw_handle() as _,
                    FileBasicInfo,
                    (&info as *const FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                )
            };
            if ok == 0 {
                return Err(AnchorError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_drop_dots_and_empty_components() {
        assert_eq!(
            parts("a/./b//../c"),
            vec![
                Part::Name("a"),
                Part::Name("b"),
                Part::Parent,
                Part::Name("c")
            ]
        );
    }

    #[test]
    fn split_final_refuses_names_that_are_not_files() {
        assert!(matches!(split_final(""), Err(AnchorError::Unsafe)));
        assert!(matches!(split_final("a/.."), Err(AnchorError::Unsafe)));
        assert!(matches!(split_final("a/b"), Ok((_, "b"))));
    }
}
