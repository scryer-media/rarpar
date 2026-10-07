//! `x`, `e` and `t`: decode the selected items the way 7-Zip's extract
//! callback does, in archive order, block by block.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

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
enum FolderError {
    /// A folder on the way is a symbolic link: writing through it could land
    /// outside the output folder.
    Link,
    Io(io::Error),
}

/// Create the folders `parts` names under `base`, one component at a time,
/// refusing any that is a symbolic link. `base` itself is the caller's own
/// output folder and is trusted.
fn confined_folders(base: &OsStr, parts: &[String]) -> Result<(), FolderError> {
    let mut path = PathBuf::from(if base.is_empty() {
        OsStr::new(".")
    } else {
        base
    });
    if !base.is_empty() {
        fs::create_dir_all(&path).map_err(FolderError::Io)?;
    }
    for part in parts {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(FolderError::Link),
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(FolderError::Io(io::Error::from_raw_os_error(
                    #[cfg(unix)]
                    libc::ENOTDIR,
                    #[cfg(not(unix))]
                    267, // ERROR_DIRECTORY
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&path) {
                    Ok(()) => {}
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
    }
    Ok(())
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
    /// The output folder prefix, ending in a separator, exactly as given.
    pub out_dir: OsString,
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
    /// Every selected item was processed; the count is of item errors.
    Done(u64),
    /// The user quit at a prompt (7-Zip's E_ABORT).
    Abort,
    /// Output failed in a way 7-Zip stops the archive for.
    Failed(io::Error),
}

/// The size of a member's first read.
const FIRST_READ: usize = 4 << 10;

/// An opened member's destination: the file written, if any.
#[derive(Default)]
struct Output {
    path: Option<PathBuf>,
    file: Option<File>,
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
    overwrite: Overwrite,
    encrypted: bool,
    /// The member being written, and once its output is open, the path
    /// it went to (`Some(None)` when it is not written to a file).
    in_progress: Option<(usize, Option<Option<PathBuf>>)>,
    stop: Option<Stop>,
    dirs: Vec<(PathBuf, Item)>,
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

/// 7-Zip's `AutoRenamePath`: the first free `name_N.ext`. The file name is a
/// member's, so text; the folder it is in is kept as given.
fn auto_rename(path: &Path) -> Option<PathBuf> {
    let file = path.file_name()?.to_string_lossy().into_owned();
    let (stem, extension) = match file.rfind('.') {
        Some(dot) if dot > 0 => (&file[..dot], &file[dot..]),
        _ => (file.as_str(), ""),
    };
    let name = |n: u32| path.with_file_name(format!("{stem}_{n}{extension}"));
    let exists = |n: u32| fs::symlink_metadata(name(n)).is_ok();
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

fn set_metadata(path: &Path, item: &Item) {
    if let Some(ticks) = item.mtime {
        let time = filetime_of(ticks);
        let _ = filetime::set_symlink_file_times(path, time, time);
    }
    let Some(attrib) = item.attrib else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if attrib & ATTRIB_UNIX_EXTENSION != 0 {
            let mode = (attrib >> 16) & 0o7777;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        } else if attrib & ATTRIB_READONLY != 0
            && let Ok(meta) = fs::metadata(path)
        {
            let mode = meta.permissions().mode() & !0o222;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
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
    fn out_path(&self, item: &Item) -> (PathBuf, Vec<String>) {
        let mut parts = correct_parts(&item.name, item.is_dir);
        if self.setup.flat
            && let Some(last) = parts.pop()
        {
            parts = vec![last];
        }
        let mut path = self.setup.out_dir.clone();
        path.push(parts.join(std::path::MAIN_SEPARATOR_STR));
        (PathBuf::from(path), parts)
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
        match confined_folders(&self.setup.out_dir, &parts) {
            Ok(()) => {}
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
        self.dirs.push((path, item.clone()));
    }

    /// The overwrite decision for an existing output; `None` skips the file.
    fn resolve_existing(&mut self, path: PathBuf, item: &Item) -> Result<Option<PathBuf>, Stop> {
        let Ok(existing) = fs::symlink_metadata(&path) else {
            return Ok(Some(path));
        };
        let shown = path.to_string_lossy().into_owned();
        if self.overwrite == Overwrite::Skip {
            return Ok(None);
        }
        if self.overwrite == Overwrite::Ask {
            let mut text = String::from("\nWould you like to replace the existing file:\n");
            text.push_str(&format!("  Path:     {shown}\n"));
            text.push_str(&format!("  Size:     {}\n", smart_size(existing.len())));
            if let Ok(modified) = existing.modified() {
                let secs = match modified.duration_since(std::time::UNIX_EPOCH) {
                    Ok(after) => after.as_secs() as i64,
                    Err(before) => -(before.duration().as_secs() as i64),
                };
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
            Overwrite::Rename => match auto_rename(&path) {
                Some(renamed) => Ok(Some(renamed)),
                None => {
                    self.item_error("Cannot create name for file", &shown);
                    Ok(None)
                }
            },
            Overwrite::RenameExisting => {
                let Some(renamed) = auto_rename(&path) else {
                    self.item_error("Cannot create name for file", &shown);
                    return Ok(None);
                };
                if let Err(error) = fs::rename(&path, &renamed) {
                    let text = format!("Cannot rename existing file : {}", errno_text(&error));
                    self.item_error(&text, &shown);
                    return Ok(None);
                }
                Ok(Some(path))
            }
            _ => {
                let removed = if existing.is_dir() {
                    fs::remove_dir(&path)
                } else {
                    fs::remove_file(&path)
                };
                match removed {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => {
                        let what = if existing.is_dir() {
                            "Cannot delete output folder"
                        } else {
                            "Cannot delete output file"
                        };
                        let text = format!("{what} : {}", errno_text(&error));
                        self.item_error(&text, &shown);
                        Ok(None)
                    }
                    _ => Ok(Some(path)),
                }
            }
        }
    }

    fn create(&mut self, path: &Path) -> Option<File> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // Never write through a link planted at the member's own name.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
        match options.open(path) {
            Ok(file) => Some(file),
            Err(error) => {
                let text = format!("Cannot open output file : {}", errno_text(&error));
                self.item_error(&text, &path.to_string_lossy());
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
        let (path, parts) = self.out_path(item);
        // The folders on the way, made one at a time and never through a
        // symbolic link, before anything at the member's own name is touched.
        let folders = &parts[..parts.len().saturating_sub(1)];
        match confined_folders(&self.setup.out_dir, folders) {
            Ok(()) => {}
            Err(FolderError::Link) => {
                self.operation_line(item, false);
                self.item_error("Dangerous link via another link was ignored", &item.name);
                return Ok(None);
            }
            // As before: the open below reports the failure.
            Err(FolderError::Io(_)) => {}
        }
        let Some(path) = self.resolve_existing(path, item)? else {
            return Ok(None);
        };
        self.operation_line(item, false);
        let file = self.create(&path);
        Ok(Some(Output {
            path: file.is_some().then_some(path),
            file,
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
                        self.in_progress = Some((index, Some(opened.path.clone())));
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
        let target = output.and_then(|output| output.path);
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
        let Some(path) = target else {
            return Ok(());
        };
        #[cfg(unix)]
        if item.symlink && crc_ok {
            if link_too_long {
                let _ = fs::remove_file(&path);
                self.item_error(
                    "Cannot create symbolic link : File name too long",
                    &path.to_string_lossy(),
                );
                return Ok(());
            }
            let link = String::from_utf8_lossy(&link_target).into_owned();
            let Some(link_path) = self.link_path(&item, &link) else {
                let text = format!("Dangerous link path was ignored : {} : {link}", item.name);
                self.errors += 1;
                self.session.err(&format!("ERROR: {text}\n"));
                return Ok(());
            };
            let _ = fs::remove_file(&path);
            if let Err(error) = std::os::unix::fs::symlink(&link_path, &path) {
                let text = format!("Cannot create symbolic link : {}", errno_text(&error));
                self.item_error(&text, &path.to_string_lossy());
                return Ok(());
            }
        }
        let _ = &link_target;
        set_metadata(&path, &item);
        Ok(())
    }

    /// Where a link points once extracted: relative targets must stay in
    /// the output folder, absolute ones are re-rooted there, as 7-Zip does.
    #[cfg(unix)]
    fn link_path(&self, item: &Item, link: &str) -> Option<PathBuf> {
        if let Some(rest) = link.strip_prefix('/') {
            if !link_is_safe(&[String::new()], rest) {
                return None;
            }
            let base = if self.setup.out_dir.is_empty() {
                OsStr::new(".")
            } else {
                self.setup.out_dir.as_os_str()
            };
            // `rest` is relative: `link_is_safe` refused another leading `/`.
            return Some(std::path::absolute(base).ok()?.join(rest));
        }
        // Judge the link from where it is actually created: the sanitised
        // path, not the archive's own name, whose `..` parts are dropped.
        let (_, parts) = self.out_path(item);
        link_is_safe(&parts, link).then(|| PathBuf::from(link))
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
            if let Some(Some(path)) = opened {
                set_metadata(&path, &item);
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
        return Ending::Done(0);
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
        encrypted: false,
        in_progress: None,
        stop: None,
        dirs: Vec::new(),
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
        None => Ending::Done(extractor.errors),
        Some(Stop::Abort) => Ending::Abort,
        Some(Stop::Write(error) | Stop::Read(error)) => Ending::Failed(error),
    };
    for (path, item) in extractor.dirs.iter().rev() {
        set_metadata(path, item);
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
