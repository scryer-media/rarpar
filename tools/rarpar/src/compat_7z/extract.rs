//! `x`, `e` and `t`: decode the selected items the way 7-Zip's extract
//! callback does, in archive order, block by block.

use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(not(unix))]
use std::path::Path;
use std::path::PathBuf;

use crc_fast::{CrcAlgorithm, Digest};
use sevenz_turbo::{ArchiveEntry, ArchiveReader, BlockErrorKind, Error as SevenZError, Password};

use super::censor::{Censor, split_path};
use super::format::{
    ATTRIB_READONLY, ATTRIB_UNIX_EXTENSION, block_is_encrypted, filetime_string, smart_size,
    unix_time_string,
};
use super::volume::Opened;
use super::{Session, errno_text, filetime_of};

/// The longest symlink target buffered; anything longer is refused while it
/// streams, never accumulated.
const MAX_LINK_TARGET: usize = 4096;

/// Why a member's folders could not be made safely.
#[derive(Debug)]
enum FolderError {
    /// A folder on the way is a symbolic link: writing through it could land
    /// outside the output folder.
    Link,
    Io(io::Error),
}

/// What is already at a name in the output tree.
struct Existing {
    len: u64,
    is_dir: bool,
    /// Seconds since the Unix epoch.
    modified: Option<i64>,
}

/// Folders of the output tree, reached without following links.
///
/// On Unix a [`Dir`](anchored::Dir) is an open handle, and every name below
/// it is resolved from that handle (`openat`, `mkdirat`, `symlinkat`,
/// `renameat`, `unlinkat`), never by path: a folder already reached cannot
/// be swapped for a link that leads outside the output folder, because
/// nothing below it is looked up through its name again.
#[cfg(unix)]
mod anchored {
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    use super::{Existing, FolderError};

    /// An open folder.
    pub(super) struct Dir(pub(super) File);

    fn c_name(name: &[u8]) -> io::Result<CString> {
        CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    /// Takes ownership of a descriptor a successful call returned.
    fn own(fd: libc::c_int) -> File {
        // SAFETY: `fd` is a fresh descriptor nothing else owns.
        unsafe { File::from_raw_fd(fd) }
    }

    const DIR_FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    impl Dir {
        /// The output folder itself: the caller's own choice, so a link
        /// there is followed.
        pub fn open(path: &str) -> io::Result<Dir> {
            let path = c_name(path.as_bytes())?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
            // SAFETY: a NUL-terminated path.
            let fd = check(unsafe { libc::open(path.as_ptr(), flags) })?;
            Ok(Dir(own(fd)))
        }

        pub fn try_clone(&self) -> io::Result<Dir> {
            self.0.try_clone().map(Dir)
        }

        fn fd(&self) -> libc::c_int {
            self.0.as_raw_fd()
        }

        fn stat(&self, name: &CStr) -> io::Result<libc::stat> {
            // SAFETY: a zeroed `stat` is a valid buffer for `fstatat`.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: an open folder, a NUL-terminated name and a buffer.
            check(unsafe {
                libc::fstatat(
                    self.fd(),
                    name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            Ok(stat)
        }

        /// What is at `name`, a link itself rather than its target.
        pub fn lstat(&self, name: &str) -> io::Result<Existing> {
            let stat = self.stat(&c_name(name.as_bytes())?)?;
            Ok(Existing {
                len: stat.st_size as u64,
                is_dir: stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
                modified: Some(stat.st_mtime as i64),
            })
        }

        /// The folder `name` in this one, made first when `create` asks and
        /// it is absent; the flag says whether it was made. A link there is
        /// refused, never followed.
        pub fn child(&self, name: &str, create: bool) -> Result<(Dir, bool), FolderError> {
            let name = c_name(name.as_bytes()).map_err(FolderError::Io)?;
            let mut made = false;
            let mut tried = false;
            loop {
                // SAFETY: an open folder and a NUL-terminated name.
                let opened = check(unsafe { libc::openat(self.fd(), name.as_ptr(), DIR_FLAGS) });
                match opened {
                    Ok(fd) => return Ok((Dir(own(fd)), made)),
                    Err(error)
                        if create && !tried && error.raw_os_error() == Some(libc::ENOENT) =>
                    {
                        tried = true;
                        // SAFETY: an open folder and a NUL-terminated name.
                        match check(unsafe { libc::mkdirat(self.fd(), name.as_ptr(), 0o777) }) {
                            Ok(_) => made = true,
                            // Raced: open what is there now, and judge it.
                            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                            Err(error) => return Err(FolderError::Io(error)),
                        }
                    }
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ELOOP | libc::ENOTDIR | libc::EMLINK)
                        ) =>
                    {
                        let link = self
                            .stat(&name)
                            .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFLNK);
                        return Err(if link {
                            FolderError::Link
                        } else {
                            FolderError::Io(io::Error::from_raw_os_error(libc::ENOTDIR))
                        });
                    }
                    Err(error) => return Err(FolderError::Io(error)),
                }
            }
        }

        /// A new file at `name`. Whatever was at the name has been removed
        /// or renamed by the overwrite policy, so anything there now (a
        /// link, or a hard link to a file outside) is refused rather than
        /// written through or truncated.
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            let name = c_name(name.as_bytes())?;
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mode: libc::c_uint = 0o666;
            // SAFETY: an open folder, a NUL-terminated name and a mode.
            let fd = check(unsafe { libc::openat(self.fd(), name.as_ptr(), flags, mode) })?;
            Ok(own(fd))
        }

        /// The file already at `name`, to set its metadata; never a link,
        /// and never blocking on a FIFO or claiming a terminal.
        pub fn open_existing(&self, name: &str) -> io::Result<File> {
            let name = c_name(name.as_bytes())?;
            let flags = libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY
                | libc::O_CLOEXEC;
            // SAFETY: an open folder and a NUL-terminated name.
            let fd = check(unsafe { libc::openat(self.fd(), name.as_ptr(), flags) })?;
            Ok(own(fd))
        }

        pub fn remove(&self, name: &str, is_dir: bool) -> io::Result<()> {
            let name = c_name(name.as_bytes())?;
            let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
            // SAFETY: an open folder and a NUL-terminated name.
            check(unsafe { libc::unlinkat(self.fd(), name.as_ptr(), flags) }).map(drop)
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            let (from, to) = (c_name(from.as_bytes())?, c_name(to.as_bytes())?);
            // SAFETY: an open folder and NUL-terminated names.
            check(unsafe { libc::renameat(self.fd(), from.as_ptr(), self.fd(), to.as_ptr()) })
                .map(drop)
        }

        pub fn symlink(&self, target: &OsStr, name: &str) -> io::Result<()> {
            let (target, name) = (c_name(target.as_bytes())?, c_name(name.as_bytes())?);
            // SAFETY: an open folder and NUL-terminated strings.
            check(unsafe { libc::symlinkat(target.as_ptr(), self.fd(), name.as_ptr()) }).map(drop)
        }

        /// Sets the times of `name` itself, a link included.
        pub fn set_link_times(&self, name: &str, time: filetime::FileTime) {
            let Ok(name) = c_name(name.as_bytes()) else {
                return;
            };
            // SAFETY: a zeroed `timespec` is valid; both fields are set.
            let mut stamp: libc::timespec = unsafe { std::mem::zeroed() };
            stamp.tv_sec = time.unix_seconds() as _;
            stamp.tv_nsec = time.nanoseconds() as _;
            let times = [stamp, stamp];
            // SAFETY: an open folder, a NUL-terminated name and two times.
            unsafe {
                libc::utimensat(
                    self.fd(),
                    name.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                );
            }
        }
    }
}

/// Folders of the output tree, by path.
///
/// Windows has no `openat`: each name is checked and then opened by path,
/// so confinement relies on the output tree not being concurrently writable
/// by an untrusted party, who could swap a checked folder for a link between
/// the check and the open. Anchoring there would mean opening every
/// component with `NtCreateFile` relative to a `RootDirectory` handle.
#[cfg(not(unix))]
mod anchored {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::PathBuf;

    use super::{Existing, FolderError};

    pub(super) struct Dir(pub(super) PathBuf);

    impl Dir {
        pub fn open(path: &str) -> io::Result<Dir> {
            Ok(Dir(PathBuf::from(path)))
        }

        pub fn try_clone(&self) -> io::Result<Dir> {
            Ok(Dir(self.0.clone()))
        }

        pub fn lstat(&self, name: &str) -> io::Result<Existing> {
            let meta = fs::symlink_metadata(self.0.join(name))?;
            let modified = meta.modified().ok().map(|modified| {
                match modified.duration_since(std::time::UNIX_EPOCH) {
                    Ok(after) => after.as_secs() as i64,
                    Err(before) => -(before.duration().as_secs() as i64),
                }
            });
            Ok(Existing {
                len: meta.len(),
                is_dir: meta.is_dir(),
                modified,
            })
        }

        pub fn child(&self, name: &str, create: bool) -> Result<(Dir, bool), FolderError> {
            let path = self.0.join(name);
            let mut made = false;
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(FolderError::Link),
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => {
                    // ERROR_DIRECTORY
                    return Err(FolderError::Io(io::Error::from_raw_os_error(267)));
                }
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    match fs::create_dir(&path) {
                        Ok(()) => made = true,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            // Raced: look again rather than trust it.
                            let meta = fs::symlink_metadata(&path).map_err(FolderError::Io)?;
                            if !meta.is_dir() || meta.file_type().is_symlink() {
                                return Err(FolderError::Link);
                            }
                        }
                        Err(error) => return Err(FolderError::Io(error)),
                    }
                }
                Err(error) => return Err(FolderError::Io(error)),
            }
            Ok((Dir(path), made))
        }

        pub fn create_file(&self, name: &str) -> io::Result<File> {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.0.join(name))
        }

        pub fn remove(&self, name: &str, is_dir: bool) -> io::Result<()> {
            let path = self.0.join(name);
            if is_dir {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            }
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            fs::rename(self.0.join(from), self.0.join(to))
        }
    }
}

use anchored::Dir;

/// Walks `parts` down from `root`, one folder at a time, making each absent
/// one when `create` asks; the flag says whether the last was made.
fn walk(root: &Dir, parts: &[String], create: bool) -> Result<(Dir, bool), FolderError> {
    let mut dir = root.try_clone().map_err(FolderError::Io)?;
    let mut made = false;
    for part in parts {
        (dir, made) = dir.child(part, create)?;
    }
    Ok((dir, made))
}

/// Where a member is written: the folders on the way, its own name, and the
/// path shown for it.
#[derive(Clone)]
struct Place {
    folders: Vec<String>,
    name: String,
    path: String,
}

impl Place {
    /// The same folder under another name.
    fn renamed(&self, name: String) -> Place {
        let prefix = &self.path[..self.path.len() - self.name.len()];
        Place {
            folders: self.folders.clone(),
            path: format!("{prefix}{name}"),
            name,
        }
    }
}

/// What to do with an output file that already exists (`-ao`, `-y`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Overwrite {
    Ask,
    Always,
    Skip,
    Rename,
    RenameExisting,
}

/// How the command extracts.
#[derive(Clone)]
pub(super) struct Setup {
    pub test: bool,
    pub flat: bool,
    pub to_stdout: bool,
    /// The output folder prefix, ending in a separator.
    pub out_dir: String,
    pub overwrite: Overwrite,
    pub threads: u32,
}

/// `-scrc`: the sums 7-Zip prints after extracting.
#[derive(Default)]
pub(super) struct HashSums {
    /// The last file's digest, which a folder's name digest reuses.
    current: u32,
    data: u64,
    data_count: u64,
    names: u64,
    names_count: u64,
    items: u64,
    folders: u64,
}

impl HashSums {
    /// One item that got 7-Zip's hash stream: every file, and folders only
    /// when testing, since extracting gives a folder no output stream.
    fn finish(&mut self, is_dir: bool, path: &str, crc: u32) {
        if is_dir {
            self.folders += 1;
        } else {
            self.items += 1;
            self.current = crc;
            self.data += u64::from(crc);
            self.data_count += 1;
        }
        let mut digest = Digest::new(CrcAlgorithm::Crc32IsoHdlc);
        let mut pre = [0u8; 16];
        pre[0] = u8::from(is_dir);
        digest.update(&pre);
        digest.update(&self.current.to_le_bytes());
        let mut units = Vec::with_capacity(path.len() * 2);
        for unit in path.encode_utf16() {
            let unit = if cfg!(windows) && unit == u16::from(b'\\') {
                u16::from(b'/')
            } else {
                unit
            };
            units.extend_from_slice(&unit.to_le_bytes());
        }
        digest.update(&units);
        self.names += digest.finalize();
        self.names_count += 1;
    }

    fn line(name: &str, sum: u64, count: u64) -> String {
        let mut text = format!("CRC32  {name}{:08X}", sum as u32);
        if count != 1 {
            text.push_str(&format!("-{:08X}", (sum >> 32) as u32));
        }
        text.push('\n');
        text
    }

    /// `PrintHashStat`.
    pub fn report(&self) -> String {
        let mut out = Self::line("for data:              ", self.data, self.data_count);
        if self.items != 1 || self.folders != 0 {
            out.push_str(&Self::line(
                "for data and names:    ",
                self.names,
                self.names_count,
            ));
        }
        out.push('\n');
        out
    }
}

/// Counts that run across every archive of the command.
#[derive(Default)]
pub(super) struct Stats {
    pub folders: u64,
    pub files: u64,
    pub size: u64,
    pub hash: Option<HashSums>,
}

/// How one archive's extraction ended.
pub(super) enum Ending {
    /// Every selected item was processed.
    Done {
        /// Item errors.
        errors: u64,
        /// Outputs actually made: files and links written (or streamed to
        /// stdout) and folders created. Items the overwrite policy skipped,
        /// and folders that were already there, are not counted.
        written: u64,
    },
    /// The user quit at a prompt (7-Zip's E_ABORT).
    Abort,
    /// Output failed in a way 7-Zip stops the archive for.
    Failed(io::Error),
}

/// The size of a member's first read.
const FIRST_READ: usize = 4 << 10;

/// An opened member's destination: the file written, if any, and the
/// folder it was made in.
#[derive(Default)]
struct Output {
    place: Option<Place>,
    file: Option<File>,
    dir: Option<Dir>,
}

#[derive(Clone)]
struct Item {
    name: String,
    is_dir: bool,
    has_stream: bool,
    size: u64,
    crc: Option<u32>,
    mtime: Option<u64>,
    attrib: Option<u32>,
    symlink: bool,
}

impl Item {
    fn from_entry(entry: &ArchiveEntry) -> Self {
        Self {
            name: entry.name.clone(),
            is_dir: entry.is_directory,
            has_stream: entry.has_stream,
            size: entry.size,
            crc: entry.has_crc.then_some(entry.crc as u32),
            mtime: entry
                .has_last_modified_date
                .then(|| u64::from(entry.last_modified_date)),
            attrib: entry
                .has_windows_attributes
                .then_some(entry.windows_attributes),
            symlink: entry.is_symlink(),
        }
    }
}

/// Why processing one file stopped early.
enum Stop {
    /// Decoding failed: the block's remaining files share the error.
    Read(io::Error),
    /// Writing the output failed.
    Write(io::Error),
    /// The user quit at the overwrite prompt.
    Abort,
}

struct Extractor<'a> {
    session: &'a mut Session,
    setup: &'a Setup,
    stats: &'a mut Stats,
    items: Vec<Item>,
    selected: Vec<bool>,
    done: Vec<bool>,
    cursor: usize,
    errors: u64,
    written: u64,
    overwrite: Overwrite,
    encrypted: bool,
    /// The member being written, and once its output is open, where it
    /// went (`Some(None)` when it is not written to a file).
    in_progress: Option<(usize, Option<Option<Place>>)>,
    stop: Option<Stop>,
    /// Folders made, as their parts below the output folder and their path.
    dirs: Vec<(Vec<String>, PathBuf, Item)>,
    /// The output folder, opened once when the first output is made.
    root: Option<Dir>,
    buffer: Vec<u8>,
}

/// 7-Zip's `Correct_FsPath` for an extracted item, as relative path parts.
fn correct_parts(name: &str, is_dir: bool) -> Vec<String> {
    let mut parts = split_path(name);
    let mut index = 0;
    while index < parts.len() {
        let part = &mut parts[index];
        if part == "." || part == ".." {
            part.clear();
        } else if cfg!(windows) {
            *part = part
                .chars()
                .map(|c| {
                    if matches!(c, ':' | '*' | '?' | '<' | '>' | '|' | '"' | '/')
                        || (c as u32) < 0x20
                    {
                        '_'
                    } else {
                        c
                    }
                })
                .collect();
            let trimmed = part.trim_end_matches(['.', ' ']).len();
            let tail = part.len() - trimmed;
            part.truncate(trimmed);
            part.push_str(&"_".repeat(tail));
        }
        if parts[index].is_empty() {
            if is_dir || index != parts.len() - 1 {
                parts.remove(index);
                continue;
            }
            parts[index] = "_".to_owned();
        }
        index += 1;
    }
    if !is_dir && parts.is_empty() {
        parts.push("_".to_owned());
    }
    parts
}

/// 7-Zip's `AutoRenamePath`: the first free `name_N.ext` in `dir`, for the
/// file name `file`.
fn auto_rename(dir: &Dir, file: &str) -> Option<String> {
    let (stem, extension) = match file.rfind('.') {
        Some(dot) if dot > 0 => (&file[..dot], &file[dot..]),
        _ => (file, ""),
    };
    let name = |n: u32| format!("{stem}_{n}{extension}");
    let exists = |n: u32| dir.lstat(&name(n)).is_ok();
    let (mut left, mut right) = (1u32, 1u32 << 30);
    while left != right {
        let mid = (left + right) / 2;
        if exists(mid) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    (!exists(right)).then(|| name(right))
}

/// Whether a link target stays inside the output folder.
#[cfg(unix)]
fn link_is_safe(item_parts: &[String], target: &str) -> bool {
    if target.starts_with('/') {
        return false;
    }
    let mut depth = item_parts.len() as isize - 1;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// Sets a member's time and mode through an open handle on its output, so
/// nothing is looked up by path again.
#[cfg(unix)]
fn apply_metadata(file: &File, item: &Item) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(ticks) = item.mtime {
        let time = filetime_of(ticks);
        let _ = filetime::set_file_handle_times(file, Some(time), Some(time));
    }
    let Some(attrib) = item.attrib else {
        return;
    };
    if attrib & ATTRIB_UNIX_EXTENSION != 0 {
        let mode = (attrib >> 16) & 0o7777;
        let _ = file.set_permissions(fs::Permissions::from_mode(mode));
    } else if attrib & ATTRIB_READONLY != 0
        && let Ok(meta) = file.metadata()
    {
        let mode = meta.permissions().mode() & !0o222;
        let _ = file.set_permissions(fs::Permissions::from_mode(mode));
    }
}

/// Sets the metadata of `name` in `dir`. A link member gets its times only:
/// setting a mode follows a link, and a link's target may sit outside the
/// output folder (through a link already there), so a link keeps the mode it
/// was made with. Anything else is opened without following a link.
#[cfg(unix)]
fn set_metadata_at(dir: &Dir, name: &str, item: &Item) {
    if item.symlink {
        if let Some(ticks) = item.mtime {
            dir.set_link_times(name, filetime_of(ticks));
        }
    } else if let Ok(file) = dir.open_existing(name) {
        apply_metadata(&file, item);
    }
}

#[cfg(not(unix))]
fn set_metadata(path: &Path, item: &Item) {
    if let Some(ticks) = item.mtime {
        let time = filetime_of(ticks);
        let _ = filetime::set_symlink_file_times(path, time, time);
    }
    let Some(attrib) = item.attrib else {
        return;
    };
    // Setting permissions follows a link, and a link's target may sit outside
    // the output folder (through a link already there), so a link keeps the
    // mode it was made with.
    if fs::symlink_metadata(path).map_or(true, |meta| meta.file_type().is_symlink()) {
        return;
    }
    if attrib & ATTRIB_READONLY != 0
        && let Ok(meta) = fs::metadata(path)
    {
        let mut permissions = meta.permissions();
        permissions.set_readonly(true);
        let _ = fs::set_permissions(path, permissions);
    }
}

/// Whether a decoded member is intact: one with its own CRC is judged by it,
/// one without is only as good as its block's checksum.
fn member_intact(expected: Option<u32>, crc: u32, block_failed: bool) -> bool {
    match expected {
        Some(expected) => expected == crc,
        None => !block_failed,
    }
}

/// Whether a read failed on sevenz-turbo's block checksum.
fn is_checksum_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<SevenZError>())
        .is_some_and(|inner| matches!(inner, SevenZError::ChecksumVerificationFailed))
}

/// The text 7-Zip prints for a member its block could not deliver.
fn decode_message(error: &SevenZError, encrypted: bool) -> &'static str {
    let (kind, message) = match error {
        SevenZError::BlockDecode { kind, message, .. } => (Some(*kind), message.as_str()),
        _ => (None, ""),
    };
    match kind {
        Some(BlockErrorKind::UnsupportedMethod) => "Unsupported Method",
        Some(BlockErrorKind::ChecksumMismatch) if encrypted => {
            "CRC Failed in encrypted file. Wrong password?"
        }
        Some(BlockErrorKind::ChecksumMismatch) => "CRC Failed",
        _ if encrypted => "Data Error in encrypted file. Wrong password?",
        Some(BlockErrorKind::Password) => "Wrong password",
        _ if message.contains("UnexpectedEof") => "Unexpected end of data",
        _ => "Data Error",
    }
}

impl Extractor<'_> {
    fn out_path(&self, item: &Item) -> (String, Vec<String>) {
        let mut parts = correct_parts(&item.name, item.is_dir);
        if self.setup.flat
            && let Some(last) = parts.pop()
        {
            parts = vec![last];
        }
        let mut path = self.setup.out_dir.clone();
        path.push_str(&parts.join(std::path::MAIN_SEPARATOR_STR));
        (path, parts)
    }

    /// The folder `parts` names below the output folder, walked from the
    /// output folder's own handle (opened, and made if `create` asks, on
    /// first use); the flag says whether its last part was made.
    fn folder(&mut self, parts: &[String], create: bool) -> Result<(Dir, bool), FolderError> {
        let root = match self.root.take() {
            Some(root) => root,
            None => {
                let base = &self.setup.out_dir;
                if create && !base.is_empty() {
                    fs::create_dir_all(base).map_err(FolderError::Io)?;
                }
                let base = if base.is_empty() { "." } else { base.as_str() };
                Dir::open(base).map_err(FolderError::Io)?
            }
        };
        let walked = walk(&root, parts, create);
        self.root = Some(root);
        walked
    }

    /// Sets a written member's metadata, reaching it the way it was made.
    fn place_metadata(&mut self, place: &Place, item: &Item) {
        #[cfg(unix)]
        if let Ok((dir, _)) = self.folder(&place.folders, false) {
            set_metadata_at(&dir, &place.name, item);
        }
        #[cfg(not(unix))]
        set_metadata(Path::new(&place.path), item);
    }

    fn operation_line(&mut self, item: &Item, test: bool) {
        if self.session.log_level >= 1 {
            let mark = if test { "T " } else { "- " };
            let mut name = item.name.clone();
            if item.is_dir && !name.ends_with('/') {
                name.push('/');
            }
            self.session.out(&format!("{mark}{name}\n"));
        }
    }

    fn item_error(&mut self, message: &str, name: &str) {
        self.errors += 1;
        self.session.err(&format!("ERROR: {message} : {name}\n"));
    }

    /// Items without data, from the cursor up to `limit`.
    fn flush_until(&mut self, limit: usize) -> Result<(), Stop> {
        while self.cursor < limit {
            let index = self.cursor;
            self.cursor += 1;
            if self.done[index] || !self.selected[index] || self.items[index].has_stream {
                continue;
            }
            self.done[index] = true;
            let item = self.items[index].clone();
            if item.is_dir {
                self.directory(&item);
            } else {
                let mut empty: &[u8] = &[];
                self.file(index, Some(&mut empty))?;
            }
        }
        Ok(())
    }

    fn directory(&mut self, item: &Item) {
        self.stats.folders += 1;
        self.operation_line(item, self.setup.test);
        if self.setup.test
            && let Some(hash) = self.stats.hash.as_mut()
        {
            hash.finish(true, &item.name, 0);
        }
        if self.setup.test || self.setup.to_stdout {
            return;
        }
        let (path, parts) = self.out_path(item);
        let path = PathBuf::from(path);
        match self.folder(&parts, true) {
            Ok((_, made)) => {
                if made {
                    self.written += 1;
                }
            }
            Err(FolderError::Link) => {
                self.item_error("Dangerous link via another link was ignored", &item.name);
                return;
            }
            Err(FolderError::Io(error)) => {
                let text = format!("Cannot create folder : {}", errno_text(&error));
                let shown = path.display().to_string();
                self.item_error(&text, &shown);
                return;
            }
        }
        self.dirs.push((parts, path, item.clone()));
    }

    /// The overwrite decision for an existing output in `dir`; `None` skips
    /// the file.
    fn resolve_existing(
        &mut self,
        dir: &Dir,
        place: Place,
        item: &Item,
    ) -> Result<Option<Place>, Stop> {
        let Ok(existing) = dir.lstat(&place.name) else {
            return Ok(Some(place));
        };
        let path = place.path.as_str();
        if self.overwrite == Overwrite::Skip {
            return Ok(None);
        }
        if self.overwrite == Overwrite::Ask {
            let mut text = String::from("\nWould you like to replace the existing file:\n");
            text.push_str(&format!("  Path:     {path}\n"));
            text.push_str(&format!("  Size:     {}\n", smart_size(existing.len)));
            if let Some(secs) = existing.modified {
                text.push_str(&format!("  Modified: {}\n", unix_time_string(secs)));
            }
            text.push_str("with the file from archive:\n");
            text.push_str(&format!("  Path:     {}\n", item.name));
            text.push_str(&format!("  Size:     {}\n", smart_size(item.size)));
            if let Some(ticks) = item.mtime {
                text.push_str(&format!("  Modified: {}\n", filetime_string(ticks, false)));
            }
            text.push_str("? ");
            self.session.out(&text);
            let answer = loop {
                self.session
                    .out("(Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? ");
                let Some(line) = self.session.read_line() else {
                    return Err(Stop::Abort);
                };
                let mut chars = line.trim().chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    let c = c.to_ascii_lowercase();
                    if matches!(c, 'y' | 'n' | 'a' | 's' | 'u' | 'q') {
                        break c;
                    }
                }
            };
            if answer == 'q' {
                return Err(Stop::Abort);
            }
            self.session.out("\n");
            match answer {
                'n' => return Ok(None),
                's' => {
                    self.overwrite = Overwrite::Skip;
                    return Ok(None);
                }
                'a' => self.overwrite = Overwrite::Always,
                'u' => self.overwrite = Overwrite::Rename,
                _ => {}
            }
        }
        match self.overwrite {
            Overwrite::Rename => match auto_rename(dir, &place.name) {
                Some(renamed) => Ok(Some(place.renamed(renamed))),
                None => {
                    self.item_error("Cannot create name for file", path);
                    Ok(None)
                }
            },
            Overwrite::RenameExisting => {
                let Some(renamed) = auto_rename(dir, &place.name) else {
                    self.item_error("Cannot create name for file", path);
                    return Ok(None);
                };
                if let Err(error) = dir.rename(&place.name, &renamed) {
                    let text = format!("Cannot rename existing file : {}", errno_text(&error));
                    self.item_error(&text, path);
                    return Ok(None);
                }
                Ok(Some(place))
            }
            _ => match dir.remove(&place.name, existing.is_dir) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    let what = if existing.is_dir {
                        "Cannot delete output folder"
                    } else {
                        "Cannot delete output file"
                    };
                    let text = format!("{what} : {}", errno_text(&error));
                    self.item_error(&text, path);
                    Ok(None)
                }
                _ => Ok(Some(place)),
            },
        }
    }

    /// The member's file, made in `dir` and never through a link planted at
    /// its own name.
    fn create(&mut self, dir: &Dir, place: &Place) -> Option<File> {
        match dir.create_file(&place.name) {
            Ok(file) => Some(file),
            Err(error) => {
                let text = format!("Cannot open output file : {}", errno_text(&error));
                self.item_error(&text, &place.path);
                None
            }
        }
    }

    /// Where a member's bytes go once its first bytes arrive. `None` means
    /// skipped: its data is still read past.
    fn open_output(&mut self, item: &Item) -> Result<Option<Output>, Stop> {
        if self.setup.test || self.setup.to_stdout {
            self.operation_line(item, self.setup.test);
            return Ok(Some(Output::default()));
        }
        let (path, mut folders) = self.out_path(item);
        // `correct_parts` always names a file.
        let name = folders.pop().unwrap_or_else(|| "_".to_owned());
        // The folders on the way, made one at a time and never through a
        // symbolic link, before anything at the member's own name is touched.
        let dir = match self.folder(&folders, true) {
            Ok((dir, _)) => dir,
            Err(FolderError::Link) => {
                self.operation_line(item, false);
                self.item_error("Dangerous link via another link was ignored", &item.name);
                return Ok(None);
            }
            Err(FolderError::Io(error)) => {
                // Reported as the open in that folder would have failed.
                self.operation_line(item, false);
                let text = format!("Cannot open output file : {}", errno_text(&error));
                self.item_error(&text, &path);
                return Ok(Some(Output::default()));
            }
        };
        let place = Place {
            folders,
            name,
            path,
        };
        let Some(place) = self.resolve_existing(&dir, place, item)? else {
            return Ok(None);
        };
        self.operation_line(item, false);
        let file = self.create(&dir, &place);
        Ok(Some(Output {
            place: file.is_some().then_some(place),
            file,
            dir: Some(dir),
        }))
    }

    /// One file: stream its data. `None` is a file its block failed to
    /// deliver: it is counted and named, and nothing is written for it.
    ///
    /// As 7-Zip's `CFolderOutStream` does, the output is opened when the
    /// member's first bytes arrive (or its data ends cleanly, for an empty
    /// one), so a member whose block fails before any of its bytes is only
    /// tested: not asked about and not created. One that fails partway keeps
    /// what was written.
    fn file(&mut self, index: usize, data: Option<&mut dyn Read>) -> Result<(), Stop> {
        let item = self.items[index].clone();
        self.stats.files += 1;
        self.stats.size += item.size;
        self.done[index] = true;
        let Some(data) = data else {
            self.operation_line(&item, true);
            return Ok(());
        };
        self.in_progress = Some((index, None));
        let mut output: Option<Output> = None;
        let mut digest = Digest::new(CrcAlgorithm::Crc32IsoHdlc);
        let mut link_target: Vec<u8> = Vec::new();
        let mut link_too_long = false;
        let mut got = 0u64;
        let mut last = false;
        let mut block_failed = false;
        loop {
            let read = if last {
                0
            } else {
                // Until a member's first bytes arrive, read a little at a
                // time: a decoder that faults drops what the failing read
                // decoded, and 7-Zip keeps every byte decoded before a fault.
                let take = if got == 0 {
                    FIRST_READ
                } else {
                    self.buffer.len()
                };
                match data.read(&mut self.buffer[..take]) {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    // sevenz-turbo checks a block's own CRC on the final read
                    // even with verification off, and fails that read with
                    // the bytes already in the buffer. Take them: this
                    // member's own CRC below says whether it is damaged, as
                    // 7-Zip's does.
                    Err(error) if is_checksum_failure(&error) && item.size - got <= take as u64 => {
                        last = true;
                        block_failed = true;
                        (item.size - got) as usize
                    }
                    Err(error) => return Err(Stop::Read(error)),
                }
            };
            if output.is_none() {
                match self.open_output(&item)? {
                    Some(opened) => {
                        self.in_progress = Some((index, Some(opened.place.clone())));
                        output = Some(opened);
                    }
                    None => {
                        self.in_progress = None;
                        if !last {
                            self.drain(data)?;
                        }
                        return Ok(());
                    }
                }
            }
            if read == 0 {
                break;
            }
            got += read as u64;
            let chunk = &self.buffer[..read];
            digest.update(chunk);
            if self.setup.to_stdout {
                if let Err(error) = io::stdout().lock().write_all(chunk) {
                    return Err(Stop::Write(error));
                }
            } else if item.symlink && cfg!(unix) {
                if link_target.len() + chunk.len() > MAX_LINK_TARGET {
                    link_too_long = true;
                    link_target = Vec::new();
                } else if !link_too_long {
                    link_target.extend_from_slice(chunk);
                }
            } else if let Some(file) = output.as_mut().and_then(|output| output.file.as_mut())
                && let Err(error) = file.write_all(chunk)
            {
                return Err(Stop::Write(error));
            }
        }
        if self.setup.to_stdout
            && let Err(error) = io::stdout().lock().flush()
        {
            return Err(Stop::Write(error));
        }
        self.in_progress = None;
        let target = output.and_then(|output| Some((output.place?, output.dir?, output.file)));
        if self.setup.to_stdout {
            self.written += 1;
        }
        let crc = digest.finalize() as u32;
        if let Some(hash) = self.stats.hash.as_mut() {
            hash.finish(false, &item.name, crc);
        }
        let crc_ok = member_intact(item.crc, crc, block_failed);
        if !crc_ok {
            let message = if self.encrypted {
                "CRC Failed in encrypted file. Wrong password?"
            } else {
                "CRC Failed"
            };
            self.item_error(message, &item.name);
        }
        let Some((place, dir, file)) = target else {
            return Ok(());
        };
        #[cfg(unix)]
        if item.symlink && crc_ok {
            // The placeholder made when the member's data began is closed
            // before it is replaced.
            drop(file);
            if link_too_long {
                let _ = dir.remove(&place.name, false);
                self.item_error(
                    "Cannot create symbolic link : File name too long",
                    &place.path,
                );
                return Ok(());
            }
            let link = String::from_utf8_lossy(&link_target).into_owned();
            let Some(link_path) = self.link_path(&item, &link_target) else {
                // As 7-Zip does, the placeholder goes before the link is
                // judged: a refused link leaves nothing at its name.
                let _ = dir.remove(&place.name, false);
                let text = format!("Dangerous link path was ignored : {} : {link}", item.name);
                self.errors += 1;
                self.session.err(&format!("ERROR: {text}\n"));
                return Ok(());
            };
            let _ = dir.remove(&place.name, false);
            if let Err(error) = dir.symlink(&link_path, &place.name) {
                let text = format!("Cannot create symbolic link : {}", errno_text(&error));
                self.item_error(&text, &place.path);
                return Ok(());
            }
            self.written += 1;
            set_metadata_at(&dir, &place.name, &item);
            return Ok(());
        }
        let _ = &link_target;
        self.written += 1;
        #[cfg(unix)]
        match &file {
            // A link member that failed its CRC keeps its placeholder, and
            // gets only the times a link would.
            Some(file) if !item.symlink => apply_metadata(file, &item),
            _ => set_metadata_at(&dir, &place.name, &item),
        }
        #[cfg(not(unix))]
        {
            drop((file, dir));
            set_metadata(Path::new(&place.path), &item);
        }
        Ok(())
    }

    /// Where a link points once extracted: relative targets must stay in
    /// the output folder, absolute ones are re-rooted there, as 7-Zip does.
    ///
    /// The target keeps its own bytes: a Unix link target is a byte string,
    /// and one that is not UTF-8 must not be rewritten. It is judged on its
    /// text, which is as safe: a replaced byte is never `/` or `.`, so the
    /// parts and their `..`s are the same.
    #[cfg(unix)]
    fn link_path(&self, item: &Item, link: &[u8]) -> Option<std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt;
        if let Some(rest) = link.strip_prefix(b"/") {
            if !link_is_safe(&[String::new()], &String::from_utf8_lossy(rest)) {
                return None;
            }
            let base = if self.setup.out_dir.is_empty() {
                ".".to_owned()
            } else {
                self.setup.out_dir.clone()
            };
            let mut target = std::path::absolute(&base).ok()?.into_os_string().into_vec();
            if !target.ends_with(b"/") {
                target.push(b'/');
            }
            target.extend_from_slice(rest);
            return Some(std::ffi::OsString::from_vec(target));
        }
        // Judge the link from where it is actually created: the sanitised
        // path, not the archive's own name, whose `..` parts are dropped.
        let (_, parts) = self.out_path(item);
        link_is_safe(&parts, &String::from_utf8_lossy(link))
            .then(|| std::ffi::OsString::from_vec(link.to_vec()))
    }

    fn drain(&mut self, data: &mut dyn Read) -> Result<(), Stop> {
        loop {
            match data.read(&mut self.buffer) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Stop::Read(error)),
            }
        }
    }

    /// The selected files of a block that never got their data: each is
    /// reported with the block's error, as 7-Zip's `FlushCorrupted` does.
    fn fail_rest(&mut self, files: &[usize], message: &str) -> Result<(), Stop> {
        if let Some((index, opened)) = self.in_progress.take() {
            let item = self.items[index].clone();
            if opened.is_none() {
                // Failed before its first bytes: only tested.
                self.operation_line(&item, true);
            }
            self.item_error(message, &item.name);
            if let Some(Some(place)) = opened {
                self.place_metadata(&place, &item);
            }
        }
        for &index in files {
            if self.done[index] || !self.selected[index] {
                continue;
            }
            self.flush_until(index)?;
            self.file(index, None)?;
            let name = self.items[index].name.clone();
            self.item_error(message, &name);
        }
        Ok(())
    }
}

/// Which items of `archive` the censor selects.
pub(super) fn selection(files: &[ArchiveEntry], censor: &Censor) -> Vec<bool> {
    files
        .iter()
        .map(|entry| !entry.is_anti_item && censor.selects(&entry.name, entry.is_directory))
        .collect()
}

/// Extract (or test) the selected items of an opened archive.
pub(super) fn extract(
    session: &mut Session,
    setup: &Setup,
    stats: &mut Stats,
    opened: Opened,
    selected: Vec<bool>,
) -> Ending {
    let Opened {
        archive, reader, ..
    } = opened;
    let items: Vec<Item> = archive.files.iter().map(Item::from_entry).collect();
    let count = items.len();
    let mut block_files: Vec<Vec<usize>> = vec![Vec::new(); archive.blocks.len()];
    for (index, block) in archive.stream_map.file_block_index.iter().enumerate() {
        if let Some(block) = *block
            && items[index].has_stream
            && let Some(files) = block_files.get_mut(block)
        {
            files.push(index);
        }
    }
    if !selected.iter().any(|&wanted| wanted) {
        session.out("\nNo files to process\n");
        return Ending::Done {
            errors: 0,
            written: 0,
        };
    }
    let encrypted: Vec<bool> = archive.blocks.iter().map(block_is_encrypted).collect();
    let mut extractor = Extractor {
        overwrite: setup.overwrite,
        session,
        setup,
        stats,
        items,
        selected,
        done: vec![false; count],
        cursor: 0,
        errors: 0,
        written: 0,
        encrypted: false,
        in_progress: None,
        stop: None,
        dirs: Vec::new(),
        root: None,
        buffer: vec![0u8; 1 << 20],
    };
    let mut password = extractor.session.password.clone();
    let mut reader = ArchiveReader::from_archive(
        archive.clone(),
        reader,
        Password::from(password.as_deref().unwrap_or("")),
    );
    reader.set_thread_count(setup.threads);
    reader.set_verify_checksums(false);

    let ending = 'blocks: {
        for (block, files) in block_files.iter().enumerate() {
            let wanted: Vec<usize> = files
                .iter()
                .copied()
                .filter(|&index| extractor.selected[index])
                .collect();
            let Some(&last) = wanted.last() else {
                continue;
            };
            if let Err(stop) = extractor.flush_until(wanted[0]) {
                break 'blocks Some(stop);
            }
            extractor.encrypted = encrypted[block];
            if encrypted[block] && password.is_none() {
                match extractor.session.ask_password() {
                    Some(text) => {
                        password = Some(text.clone());
                        let source = reader.into_source();
                        reader = ArchiveReader::from_archive(
                            archive.clone(),
                            source,
                            Password::from(text.as_str()),
                        );
                        reader.set_thread_count(setup.threads);
                        reader.set_verify_checksums(false);
                    }
                    None => break 'blocks Some(Stop::Abort),
                }
            }
            let mut position = 0usize;
            let result = match reader.block_decoder(block) {
                Ok(decoder) => decoder.for_each_entries(&mut |entry, data| {
                    if !entry.has_stream {
                        return Ok(true);
                    }
                    let Some(&index) = files.get(position) else {
                        return Ok(true);
                    };
                    position += 1;
                    let outcome = extractor.flush_until(index).and_then(|()| {
                        if extractor.selected[index] {
                            extractor.file(index, Some(data))
                        } else {
                            // 7-Zip counts the members it decodes past in a
                            // solid block, though it writes none of them.
                            extractor.stats.files += 1;
                            extractor.stats.size += extractor.items[index].size;
                            extractor.drain(data)
                        }
                    });
                    match outcome {
                        Ok(()) => Ok(index != last),
                        Err(Stop::Read(error)) => Err(SevenZError::from(error)),
                        Err(stop) => {
                            extractor.stop = Some(stop);
                            Err(SevenZError::from(io::Error::other("stopped")))
                        }
                    }
                }),
                Err(error) => Err(error),
            };
            if let Some(stop) = extractor.stop.take() {
                break 'blocks Some(stop);
            }
            if let Err(error) = result {
                let message = decode_message(&error, encrypted[block]);
                if let Err(stop) = extractor.fail_rest(&wanted, message) {
                    break 'blocks Some(stop);
                }
            }
        }
        extractor.flush_until(count).err()
    };
    let ending = match ending {
        None => Ending::Done {
            errors: extractor.errors,
            written: extractor.written,
        },
        Some(Stop::Abort) => Ending::Abort,
        Some(Stop::Write(error) | Stop::Read(error)) => Ending::Failed(error),
    };
    for (parts, path, item) in std::mem::take(&mut extractor.dirs).iter().rev() {
        // Each folder is reached again from the output folder's handle,
        // rather than held open: an archive may make any number of them.
        #[cfg(unix)]
        {
            let _ = path;
            if let Ok((dir, _)) = extractor.folder(parts, false) {
                apply_metadata(&dir.0, item);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = parts;
            set_metadata(path, item);
        }
    }
    ending
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_block_checksum_fails_members_without_their_own_crc() {
        assert!(member_intact(None, 7, false));
        assert!(!member_intact(None, 7, true));
        // A member's own CRC proves its bytes whatever the block said.
        assert!(member_intact(Some(7), 7, true));
        assert!(!member_intact(Some(7), 8, false));
    }

    /// A folder the walk has already reached is held by its handle: swapping
    /// it on disk for a link that leads outside the output folder does not
    /// move anything made below it afterwards, and a fresh walk refuses the
    /// link.
    #[cfg(unix)]
    #[test]
    fn a_reached_folder_stays_anchored_when_swapped_for_a_link() {
        let scratch = tempfile::tempdir().unwrap();
        let out = scratch.path().join("out");
        let outside = scratch.path().join("outside");
        fs::create_dir_all(outside.join("b")).unwrap();
        fs::create_dir(&out).unwrap();
        let root = Dir::open(out.to_str().unwrap()).unwrap();
        let parts = ["a".to_owned()];
        let (a, made) = walk(&root, &parts, true).unwrap();
        assert!(made);

        // Swap `a` for a link to a folder outside, where a lookup by path of
        // `a/b/file` would land.
        fs::rename(out.join("a"), out.join("a-moved")).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("a")).unwrap();

        let (b, made) = a.child("b", true).unwrap();
        assert!(made);
        b.create_file("file")
            .unwrap()
            .write_all(b"anchored")
            .unwrap();
        assert_eq!(fs::read(out.join("a-moved/b/file")).unwrap(), b"anchored");
        assert!(fs::symlink_metadata(outside.join("b/file")).is_err());
        assert!(matches!(
            walk(&root, &["a".to_owned(), "b".to_owned()], true),
            Err(FolderError::Link)
        ));
    }

    /// A link already at a folder on the way is refused, never followed,
    /// whether its target exists or not, and nothing is made through it.
    #[cfg(unix)]
    #[test]
    fn a_link_on_the_way_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let out = scratch.path().join("out");
        let outside = scratch.path().join("outside");
        fs::create_dir(&out).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("shelf")).unwrap();
        std::os::unix::fs::symlink(outside.join("absent"), out.join("dangling")).unwrap();
        let root = Dir::open(out.to_str().unwrap()).unwrap();
        for link in ["shelf", "dangling"] {
            let parts = [link.to_owned(), "inner".to_owned()];
            assert!(matches!(walk(&root, &parts, true), Err(FolderError::Link)));
        }
        assert!(fs::symlink_metadata(outside.join("inner")).is_err());
        assert!(fs::symlink_metadata(outside.join("absent")).is_err());
        // A file planted at a member's own name is refused, not truncated.
        fs::write(outside.join("ledger.txt"), b"keep me").unwrap();
        std::os::unix::fs::symlink(outside.join("ledger.txt"), out.join("ledger.txt")).unwrap();
        assert!(root.create_file("ledger.txt").is_err());
        assert_eq!(fs::read(outside.join("ledger.txt")).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn links_are_judged_from_their_sanitised_place() {
        // `../../pivot` lands at the top of the output folder.
        assert!(!link_is_safe(&["pivot".to_owned()], "../../outside"));
        assert!(!link_is_safe(&["pivot".to_owned()], "../outside"));
        assert!(link_is_safe(
            &["deep".to_owned(), "pivot".to_owned()],
            "../sibling"
        ));
    }
}
