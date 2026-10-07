//! What kind of filesystem a source lives on.
//!
//! Disk verification picks the order it hashes a file in from this: a second
//! read of a damaged file costs another trip over the network on a remote
//! mount, while on a local disk it is usually served from memory. The probe
//! is one filesystem query per directory; a kind it cannot name is
//! [`MountKind::Unknown`], and the engine keeps its default order for it.

use std::path::Path;

/// Where a source's bytes come from, as far as the order of disk
/// verification is concerned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MountKind {
    /// A filesystem on a disk of this machine.
    Local = 0,
    /// A network filesystem: NFS or SMB.
    Remote = 1,
    /// Neither could be established: an unrecognised filesystem, a FUSE
    /// mount (which may be either), a failed probe, or a source that is not
    /// a file on disk.
    #[default]
    Unknown = 2,
}

/// Whether disk verification hashes a file whole before its extents on a
/// mount of this kind, when no order is forced.
pub(crate) fn whole_file_first(kind: MountKind) -> bool {
    match kind {
        MountKind::Local | MountKind::Unknown => true,
        MountKind::Remote => false,
    }
}

/// Classify a Linux `statfs` `f_type` magic number.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn from_linux_magic(magic: u64) -> MountKind {
    // The kernel's magic numbers are 32-bit; `f_type`'s width and signedness
    // vary by libc and architecture.
    match magic as u32 {
        // NFS_SUPER_MAGIC; SMB_SUPER_MAGIC, CIFS_MAGIC_NUMBER, SMB2_MAGIC_NUMBER.
        0x6969 | 0x517b | 0xff53_4d42 | 0xfe53_4d42 => MountKind::Remote,
        // ext2/3/4, XFS, Btrfs, tmpfs, F2FS, ZFS, overlayfs, bcachefs, exFAT,
        // FAT, NTFS (ntfs3 and the older driver).
        0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0xf2f5_2010 | 0x2fc1_2fc1
        | 0x794c_7630 | 0xca45_1a4e | 0x2011_bab0 | 0x4d44 | 0x7366_746e => MountKind::Local,
        // FUSE_SUPER_MAGIC and everything else: a FUSE filesystem may sit on
        // a local disk or on a network.
        _ => MountKind::Unknown,
    }
}

/// Classify a BSD or macOS `statfs` `f_fstypename`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn from_type_name(name: &str) -> MountKind {
    match name {
        "nfs" | "smbfs" | "afpfs" | "webdav" => MountKind::Remote,
        "apfs" | "hfs" | "msdos" | "exfat" | "ufs" | "zfs" | "tmpfs" => MountKind::Local,
        // macFUSE, FUSE-T and everything else.
        _ => MountKind::Unknown,
    }
}

/// Classify a Windows `GetDriveTypeW` result.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn from_drive_type(drive: u32) -> MountKind {
    match drive {
        // DRIVE_REMOTE.
        4 => MountKind::Remote,
        // DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM, DRIVE_RAMDISK.
        2 | 3 | 5 | 6 => MountKind::Local,
        // DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR.
        _ => MountKind::Unknown,
    }
}

/// The kind of filesystem `dir` is on. Any failure is [`MountKind::Unknown`].
pub(crate) fn probe(dir: &Path) -> MountKind {
    platform::probe(dir).unwrap_or(MountKind::Unknown)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
mod platform {
    use super::MountKind;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub(super) fn probe(dir: &Path) -> Option<MountKind> {
        let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `path` is NUL-terminated and outlives the call; `stat` is
        // written in full when the call succeeds and read only then.
        if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: statfs returned success.
        let stat = unsafe { stat.assume_init() };
        Some(kind(&stat))
    }

    #[cfg(target_os = "linux")]
    fn kind(stat: &libc::statfs) -> MountKind {
        #[allow(clippy::unnecessary_cast)]
        let magic = stat.f_type as u64;
        super::from_linux_magic(magic)
    }

    #[cfg(target_os = "macos")]
    fn kind(stat: &libc::statfs) -> MountKind {
        let name = &stat.f_fstypename;
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let bytes: Vec<u8> = name[..len].iter().map(|&c| c as u8).collect();
        std::str::from_utf8(&bytes).map_or(MountKind::Unknown, super::from_type_name)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use super::MountKind;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetVolumePathNameW(name: *const u16, root: *mut u16, len: u32) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
    }

    pub(super) fn probe(dir: &Path) -> Option<MountKind> {
        let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        let mut root = vec![0u16; path.len().max(4) + 1];
        // SAFETY: `path` is NUL-terminated; `root` holds `root.len()` units,
        // which is at least the path's own length plus its terminator, the
        // most a volume root of it can need.
        if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return None;
        }
        // SAFETY: GetVolumePathNameW wrote a NUL-terminated root into `root`.
        Some(super::from_drive_type(unsafe {
            GetDriveTypeW(root.as_ptr())
        }))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::MountKind;
    use std::path::Path;

    pub(super) fn probe(_dir: &Path) -> Option<MountKind> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_magic_numbers_classify_every_branch() {
        for magic in [0x6969u64, 0x517b, 0xff53_4d42, 0xfe53_4d42] {
            assert_eq!(from_linux_magic(magic), MountKind::Remote, "{magic:#x}");
        }
        // A sign-extended CIFS magic from a 32-bit signed `f_type`.
        assert_eq!(from_linux_magic(0xffff_ffff_ff53_4d42), MountKind::Remote);
        for magic in [
            0xef53u64,
            0x5846_5342,
            0x9123_683e,
            0x0102_1994,
            0xf2f5_2010,
            0x2fc1_2fc1,
            0x794c_7630,
            0xca45_1a4e,
            0x2011_bab0,
            0x4d44,
            0x7366_746e,
        ] {
            assert_eq!(from_linux_magic(magic), MountKind::Local, "{magic:#x}");
        }
        // FUSE, procfs, and nothing at all.
        for magic in [0x6573_5546u64, 0x9fa0, 0] {
            assert_eq!(from_linux_magic(magic), MountKind::Unknown, "{magic:#x}");
        }
    }

    #[test]
    fn type_names_classify_every_branch() {
        for name in ["nfs", "smbfs", "afpfs", "webdav"] {
            assert_eq!(from_type_name(name), MountKind::Remote, "{name}");
        }
        for name in ["apfs", "hfs", "msdos", "exfat", "ufs", "zfs", "tmpfs"] {
            assert_eq!(from_type_name(name), MountKind::Local, "{name}");
        }
        for name in ["macfuse", "osxfuse", "fusefs", "devfs", "", "NFS"] {
            assert_eq!(from_type_name(name), MountKind::Unknown, "{name}");
        }
    }

    #[test]
    fn drive_types_classify_every_branch() {
        assert_eq!(from_drive_type(4), MountKind::Remote);
        for drive in [2, 3, 5, 6] {
            assert_eq!(from_drive_type(drive), MountKind::Local, "{drive}");
        }
        for drive in [0, 1, 7] {
            assert_eq!(from_drive_type(drive), MountKind::Unknown, "{drive}");
        }
    }

    #[test]
    fn a_missing_directory_is_unknown() {
        let dir = std::env::temp_dir().join("par3-rs-mount-kind-no-such-directory");
        assert_eq!(probe(&dir), MountKind::Unknown);
    }
}
