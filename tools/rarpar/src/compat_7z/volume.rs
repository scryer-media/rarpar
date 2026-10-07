//! Opening an archive the way 7-Zip does: a file, or a `.001` split set read
//! as one stream, then the 7z header inside it.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sevenz_turbo::{Archive, Error as SevenZError, Password};

/// How many volume handles a [`Volumes`] keeps open at once. Decoding reads
/// the volume holding the current position, and a seek pattern rarely
/// alternates among more than a couple; a set of any size never needs more
/// descriptors than this.
const OPEN_VOLUMES: usize = 4;

/// Volumes read back to back as one seekable stream. Each volume is opened
/// when a read reaches it, and only the few most recently read stay open.
pub(super) struct Volumes {
    paths: Vec<PathBuf>,
    sizes: Vec<u64>,
    starts: Vec<u64>,
    /// Open handles by volume index, most recently used last.
    open: Vec<(usize, File)>,
    len: u64,
    pos: u64,
}

impl Volumes {
    fn open(paths: &[PathBuf], sizes: &[u64]) -> io::Result<Self> {
        let mut starts = Vec::with_capacity(paths.len());
        let mut at = 0u64;
        for size in sizes {
            starts.push(at);
            at += size;
        }
        let mut volumes = Self {
            paths: paths.to_vec(),
            sizes: sizes.to_vec(),
            starts,
            open: Vec::new(),
            len: at,
            pos: 0,
        };
        // The first volume is the archive named: fail as before when it
        // cannot be opened at all.
        if !paths.is_empty() {
            volumes.handle(0)?;
        }
        Ok(volumes)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// The handle of volume `index`, opened (and checked against the size it
    /// had when the set was found) if it is not already open.
    fn handle(&mut self, index: usize) -> io::Result<&mut File> {
        if let Some(at) = self.open.iter().position(|(open, _)| *open == index) {
            let entry = self.open.remove(at);
            self.open.push(entry);
        } else {
            let file = File::open(&self.paths[index])?;
            if file.metadata()?.len() != self.sizes[index] {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "volume changed size since the set was found",
                ));
            }
            if self.open.len() >= OPEN_VOLUMES {
                self.open.remove(0);
            }
            self.open.push((index, file));
        }
        Ok(&mut self.open.last_mut().expect("just pushed").1)
    }

    /// How many volume handles are open now.
    #[cfg(test)]
    fn open_handles(&self) -> usize {
        self.open.len()
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
        // Skip empty volumes: they share their start with the next one.
        let index = (index..self.starts.len())
            .find(|&at| self.sizes[at] > 0)
            .unwrap_or(index);
        let end = self.starts.get(index + 1).copied().unwrap_or(self.len);
        let want = buf.len().min((end - self.pos) as usize);
        let offset = self.pos - self.starts[index];
        let file = self.handle(index)?;
        file.seek(SeekFrom::Start(offset))?;
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
}

/// `name.001`, `name.002`, ...: the volumes 7-Zip's split handler joins when
/// it is given the first one.
pub(super) fn volume_set(path: &Path, first_size: u64) -> VolumeSet {
    let single = || VolumeSet {
        paths: vec![path.to_path_buf()],
        sizes: vec![first_size],
        split_name: None,
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
    let mut number = 2u64;
    loop {
        let name = format!("{stem}.{number:0width$}");
        let next = path.with_file_name(&name);
        match std::fs::metadata(&next) {
            Ok(meta) if meta.is_file() => {
                paths.push(next);
                sizes.push(meta.len());
            }
            _ => break,
        }
        number += 1;
    }
    VolumeSet {
        paths,
        sizes,
        split_name: Some(stem.to_owned()),
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
    set: &VolumeSet,
    password: &mut dyn FnMut() -> Option<String>,
) -> Result<Opened, OpenFailure> {
    let mut reader = Volumes::open(&set.paths, &set.sizes).map_err(OpenFailure::Io)?;
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

    /// A set of many volumes reads back whole while at most
    /// [`OPEN_VOLUMES`] handles are ever open, in order and out of order.
    #[test]
    fn volumes_open_on_demand_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let count = 40;
        let mut paths = Vec::new();
        let mut sizes = Vec::new();
        let mut whole = Vec::new();
        for number in 0..count {
            let bytes: Vec<u8> = (0..(number % 5) * 7)
                .map(|at| (at * 31 + number) as u8)
                .collect();
            let path = dir.path().join(format!("ledger.7z.{:03}", number + 1));
            std::fs::write(&path, &bytes).unwrap();
            whole.extend_from_slice(&bytes);
            sizes.push(bytes.len() as u64);
            paths.push(path);
        }
        let mut volumes = Volumes::open(&paths, &sizes).unwrap();
        assert_eq!(volumes.open_handles(), 1);
        let mut read = Vec::new();
        let mut buf = [0u8; 5];
        loop {
            let got = volumes.read(&mut buf).unwrap();
            if got == 0 {
                break;
            }
            read.extend_from_slice(&buf[..got]);
            assert!(volumes.open_handles() <= OPEN_VOLUMES);
        }
        assert_eq!(read, whole);
        for at in [whole.len() - 1, 0, whole.len() / 2, 3, whole.len() - 9] {
            volumes.seek(SeekFrom::Start(at as u64)).unwrap();
            let mut byte = [0u8; 1];
            volumes.read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], whole[at], "byte {at}");
            assert!(volumes.open_handles() <= OPEN_VOLUMES);
        }
    }
}
