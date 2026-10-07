//! Whole-file clones for repair staging. A clone shares the original's
//! extents; only the blocks a repair later writes are copied.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

use crate::source::SourceSnapshot;

/// Whether a refused clone means only that this file cannot be cloned here:
/// the filesystem has no clones, the two files are on different devices, or
/// the file refuses the operation. The caller stages by copying instead.
pub(crate) fn unsupported(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == libc::EOPNOTSUPP
            || code == libc::ENOTSUP
            || code == libc::EXDEV
            || code == libc::EINVAL
            || code == libc::ENOTTY
            || code == libc::EPERM
    })
}

/// Whether a refused clone says the staging filesystem has no clones at all,
/// so no later output of the same repair asks again. `EINVAL` is not one: a
/// reflink filesystem can refuse a single file (an inline extent, say) and
/// still clone the next.
pub(super) fn never(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == libc::EOPNOTSUPP || code == libc::ENOTSUP || code == libc::ENOTTY
    })
}

/// Whether the open file with `metadata` is the regular file `source`
/// snapshots, so that a clone of it holds the bytes that snapshot describes.
/// A macOS clone also keeps the original's mode and file flags, and the staged
/// file must be writable and removable.
pub(crate) fn is_source(metadata: &std::fs::Metadata, source: SourceSnapshot) -> bool {
    #[cfg(target_os = "macos")]
    let writable = {
        use std::os::macos::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        // An immutable or append-only clone could be neither written nor
        // removed.
        const LOCKED: u32 =
            libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND;
        metadata.permissions().mode() & 0o200 != 0 && metadata.st_flags() & LOCKED == 0
    };
    #[cfg(target_os = "linux")]
    let writable = true;
    metadata.is_file() && writable && crate::source::disk_snapshot(metadata) == source
}

/// Create `name` in `directory` as a clone of the open file `source`. The
/// name must not exist, exactly as for a `create_new` open.
#[cfg(target_os = "macos")]
pub(super) fn clone_new(
    source: &impl AsFd,
    directory: &impl AsFd,
    name: &std::ffi::OsStr,
) -> io::Result<()> {
    clone_at(source, directory.as_fd().as_raw_fd(), name)
}

/// Create `path` as a clone of the open file `source`, relative to the
/// working directory when it is relative. It must not exist.
#[cfg(target_os = "macos")]
pub(crate) fn clone_path(source: &impl AsFd, path: &std::path::Path) -> io::Result<()> {
    clone_at(source, libc::AT_FDCWD, path.as_os_str())
}

#[cfg(target_os = "macos")]
fn clone_at(
    source: &impl AsFd,
    directory: std::os::fd::RawFd,
    name: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    // <sys/clonefile.h>
    const CLONE_NOFOLLOW: u32 = 0x0001;
    const CLONE_NOOWNERCOPY: u32 = 0x0002;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the source descriptor is borrowed for the duration of the call,
    // `directory` is a descriptor the caller holds or `AT_FDCWD`, and `name`
    // is a NUL-terminated string that outlives the call.
    let result = unsafe {
        libc::fclonefileat(
            source.as_fd().as_raw_fd(),
            directory,
            name.as_ptr(),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Replace the contents of the open, writable file `target` with a clone of
/// the open file `source`.
#[cfg(target_os = "linux")]
pub(crate) fn clone_into(source: &impl AsFd, target: &impl AsFd) -> io::Result<()> {
    // SAFETY: both descriptors are borrowed for the duration of the call, and
    // FICLONE takes the source descriptor by value.
    let result = unsafe {
        libc::ioctl(
            target.as_fd().as_raw_fd(),
            libc::FICLONE,
            source.as_fd().as_raw_fd(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
