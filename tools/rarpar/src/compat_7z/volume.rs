//! Opening an archive the way 7-Zip does: a file, or a `.001` split set read
//! as one stream, then the 7z header inside it.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sevenz_turbo::{Archive, Error as SevenZError, Password};

/// Volumes read back to back as one seekable stream.
pub(super) struct Volumes {
    files: Vec<File>,
    starts: Vec<u64>,
    len: u64,
    pos: u64,
}

impl Volumes {
    /// The first volume, opened by the path the caller named (a link there
    /// is the caller's choice), then the siblings [`volume_set`] already
    /// opened without following a link.
    fn open(first: &Path, siblings: Vec<File>, sizes: &[u64]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(sizes.len());
        files.push(File::open(first)?);
        files.extend(siblings);
        let mut starts = Vec::with_capacity(sizes.len());
        let mut at = 0u64;
        for size in sizes {
            starts.push(at);
            at += size;
        }
        Ok(Self {
            files,
            starts,
            len: at,
            pos: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

impl Read for Volumes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len {
            return Ok(0);
        }
        let index = match self.starts.binary_search(&self.pos) {
            Ok(index) => index,
            Err(index) => index - 1,
        };
        let end = self.starts.get(index + 1).copied().unwrap_or(self.len);
        let want = buf.len().min((end - self.pos) as usize);
        let file = &mut self.files[index];
        file.seek(SeekFrom::Start(self.pos - self.starts[index]))?;
        let read = file.read(&mut buf[..want])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "volume shorter than when opened",
            ));
        }
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for Volumes {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(at) => i128::from(at),
            SeekFrom::End(delta) => i128::from(self.len) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.pos) + i128::from(delta),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start",
            ));
        }
        self.pos = u64::try_from(target).unwrap_or(u64::MAX);
        Ok(self.pos)
    }
}

/// Where the volumes of an archive are.
pub(super) struct VolumeSet {
    pub paths: Vec<PathBuf>,
    pub sizes: Vec<u64>,
    /// The name 7-Zip gives the joined stream: the first volume's file name
    /// without its number; `None` for a single file.
    pub split_name: Option<String>,
    /// The volumes after the first, already open; [`open_archive`] takes
    /// them.
    pub siblings: Vec<File>,
}

/// Opens a sibling volume the archive's name implies, never through a link:
/// only the first volume is named by the user, so a link planted at a later
/// number would let anyone who can write the folder splice another file into
/// the stream. The size comes from the open handle, which must be a regular
/// file; `None` ends the set.
fn open_sibling(path: &Path) -> Option<(File, u64)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Non-blocking so a FIFO at the name is opened, judged and refused
        // rather than waited on; reads of a regular file ignore the flag.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return None;
        }
    }
    meta.is_file().then_some((file, meta.len()))
}

/// `name.001`, `name.002`, ...: the volumes 7-Zip's split handler joins when
/// it is given the first one. The first volume is `path` as given; each later
/// one must be a regular file at its own name, not a link.
pub(super) fn volume_set(path: &Path, first_size: u64) -> VolumeSet {
    let single = || VolumeSet {
        paths: vec![path.to_path_buf()],
        sizes: vec![first_size],
        split_name: None,
        siblings: Vec::new(),
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return single();
    };
    let Some(dot) = file_name.rfind('.') else {
        return single();
    };
    let (stem, digits) = (&file_name[..dot], &file_name[dot + 1..]);
    if stem.is_empty()
        || digits.len() < 2
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.parse::<u64>().ok() != Some(1)
    {
        return single();
    }
    let width = digits.len();
    let mut paths = vec![path.to_path_buf()];
    let mut sizes = vec![first_size];
    let mut siblings = Vec::new();
    let mut number = 2u64;
    loop {
        let name = format!("{stem}.{number:0width$}");
        let next = path.with_file_name(&name);
        let Some((file, size)) = open_sibling(&next) else {
            break;
        };
        paths.push(next);
        sizes.push(size);
        siblings.push(file);
        number += 1;
    }
    VolumeSet {
        paths,
        sizes,
        split_name: Some(stem.to_owned()),
        siblings,
    }
}

/// Why an archive could not be opened.
pub(super) enum OpenFailure {
    /// 7-Zip's error flags for a 7z it could not open.
    Format(&'static str),
    /// The header is encrypted and the password does not open it.
    WrongPassword,
    /// The header asks for a password nobody gave and the prompt was refused.
    Aborted,
    /// Reading the volumes failed.
    Io(io::Error),
}

/// An opened archive.
pub(super) struct Opened {
    pub archive: Archive,
    pub reader: Volumes,
    pub physical_size: u64,
    pub headers_size: u64,
    pub stream_len: u64,
}

const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// Read the archive, asking `password` for the header password if it turns
/// out to be encrypted.
pub(super) fn open_archive(
    set: &mut VolumeSet,
    password: &mut dyn FnMut() -> Option<String>,
) -> Result<Opened, OpenFailure> {
    let siblings = std::mem::take(&mut set.siblings);
    let mut reader = Volumes::open(&set.paths[0], siblings, &set.sizes).map_err(OpenFailure::Io)?;
    let stream_len = reader.len();
    let mut start = [0u8; 32];
    reader.seek(SeekFrom::Start(0)).map_err(OpenFailure::Io)?;
    let mut got = 0;
    while got < start.len() {
        match reader.read(&mut start[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(error) => return Err(OpenFailure::Io(error)),
        }
    }
    if got < 6 || start[..6] != SIGNATURE {
        return Err(OpenFailure::Format("Is not archive"));
    }
    if got < 32 {
        return Err(OpenFailure::Format("Unexpected end of archive"));
    }
    let next_offset = u64::from_le_bytes(start[12..20].try_into().unwrap_or_default());
    let next_size = u64::from_le_bytes(start[20..28].try_into().unwrap_or_default());
    let physical_size = 32u64
        .checked_add(next_offset)
        .and_then(|size| size.checked_add(next_size))
        .ok_or(OpenFailure::Format("Headers Error"))?;
    if physical_size > stream_len {
        return Err(OpenFailure::Format("Unexpected end of archive"));
    }
    reader.seek(SeekFrom::Start(0)).map_err(OpenFailure::Io)?;
    let archive = match Archive::read(&mut reader, &Password::empty()) {
        Ok(archive) => archive,
        Err(SevenZError::PasswordRequired) => {
            let Some(text) = password() else {
                return Err(OpenFailure::Aborted);
            };
            reader.seek(SeekFrom::Start(0)).map_err(OpenFailure::Io)?;
            Archive::read(&mut reader, &Password::from(text.as_str()))
                .map_err(|_| OpenFailure::WrongPassword)?
        }
        Err(SevenZError::Io(error, _)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(OpenFailure::Format("Unexpected end of archive"));
        }
        Err(_) => return Err(OpenFailure::Format("Headers Error")),
    };
    let packed: u64 = archive.pack_sizes().iter().sum();
    Ok(Opened {
        headers_size: physical_size.saturating_sub(packed),
        archive,
        reader,
        physical_size,
        stream_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link planted at a later volume number ends the set there: only the
    /// first volume, which the user names, may be a link. Sizes come from
    /// the opened volumes.
    #[cfg(unix)]
    #[test]
    fn a_linked_sibling_volume_ends_the_set() {
        let scratch = tempfile::tempdir().unwrap();
        let elsewhere = scratch.path().join("elsewhere.bin");
        std::fs::write(&elsewhere, b"spliced in").unwrap();
        let real_first = scratch.path().join("real.bin");
        std::fs::write(&real_first, b"first").unwrap();
        let first = scratch.path().join("set.7z.001");
        std::os::unix::fs::symlink(&real_first, &first).unwrap();
        std::fs::write(scratch.path().join("set.7z.002"), b"second!").unwrap();
        std::os::unix::fs::symlink(&elsewhere, scratch.path().join("set.7z.003")).unwrap();
        std::fs::write(scratch.path().join("set.7z.004"), b"fourth").unwrap();

        let mut set = volume_set(&first, 5);
        assert_eq!(set.paths.len(), 2);
        assert_eq!(set.sizes, vec![5, 7]);
        assert_eq!(set.split_name.as_deref(), Some("set.7z"));
        let mut reader =
            Volumes::open(&set.paths[0], std::mem::take(&mut set.siblings), &set.sizes).unwrap();
        let mut joined = Vec::new();
        reader.read_to_end(&mut joined).unwrap();
        assert_eq!(joined, b"firstsecond!");
    }

    /// A sibling that is not a regular file (a folder, a FIFO) ends the set
    /// rather than being read or waited on.
    #[cfg(unix)]
    #[test]
    fn a_sibling_that_is_not_a_file_ends_the_set() {
        let scratch = tempfile::tempdir().unwrap();
        let first = scratch.path().join("set.001");
        std::fs::write(&first, b"first").unwrap();
        std::fs::create_dir(scratch.path().join("set.002")).unwrap();
        assert_eq!(volume_set(&first, 5).paths.len(), 1);

        std::fs::remove_dir(scratch.path().join("set.002")).unwrap();
        let fifo = std::ffi::CString::new(
            scratch
                .path()
                .join("set.002")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(volume_set(&first, 5).paths.len(), 1);
    }
}
