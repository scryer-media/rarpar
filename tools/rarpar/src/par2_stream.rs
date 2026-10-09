//! A PAR2 set over one file whose bytes arrive once, in order.
//!
//! par2-rs creates sets from files it can open and read up front. A sidecar
//! for an archive rarpar is writing, or for a stream, has neither: the bytes
//! go by once and the length is known only at the end. So, as
//! [`crate::par3_stream`] does for PAR3, this module assembles the packets of
//! a one-file set from par2-rs's public pieces (its Galois arithmetic, its
//! input-slice constants, its MD5 and CRC-32) while the bytes stream past.
//!
//! The recovery block for exponent `e` is the sum over input slices `i` of
//! `c_i^e * slice_i`, where `c_i` is the PAR2 constant of slice `i`. The term
//! depends only on the slice's index, never on how many slices the file ends
//! up with, so each slice is folded into every recovery block as it completes
//! and then dropped. Memory is the recovery blocks, one slice, the file's
//! first 16 KiB and 20 bytes of checksums per slice.
//!
//! The slice size and recovery count are fixed up front. A slice whose bytes
//! are changed after they were fed (a 7z start header written last) cannot be
//! taken: MD5 over the whole file is sequential and cannot be patched.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use par2_rs::checksum::md5;
use par2_rs::packet::header::{
    HEADER_SIZE, MAGIC, TYPE_CREATOR, TYPE_FILE_DESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECOVERY,
};
use par2_rs::{
    FactorDst, FileHashState, SliceChecksumState, gf_pow, input_slice_constants,
    mul_acc_multi_region,
};

use crate::par3_stream::{Durability, StagedSibling, check_targets, split_volumes, write_file};

/// The most input slices a PAR2 set can have: one per input-slice constant.
pub(crate) const MAX_SLICES: u64 = 32_768;
/// The most recovery blocks: one per exponent, 0 to 65535.
pub(crate) const MAX_ROWS: u64 = 65_536;
/// The prefix of the file the file ID hashes.
const HASH_16K: usize = 16 * 1024;
/// The creator `rarpar par create` records through par2-rs. With the same
/// packet layout, a sidecar is byte for byte the set `par create` makes from
/// the finished file with the same slice size and recovery count.
const CREATOR: &str = "par2-rs";

/// The slice size a requested block size becomes: PAR2 slices are a multiple
/// of four bytes.
pub(crate) fn slice_size(requested: u64) -> u64 {
    requested.max(4).next_multiple_of(4)
}

/// Bytes a lane holds whatever the file's length: its recovery blocks, the
/// slice being filled and the 16 KiB prefix.
pub(crate) fn lane_bytes(slice_size: u64, rows: u64) -> u64 {
    slice_size
        .saturating_mul(rows)
        .saturating_add(slice_size)
        .saturating_add(HASH_16K as u64)
}

/// Bytes per input slice a lane keeps: its MD5 and CRC-32.
pub(crate) const BYTES_PER_SLICE: u64 = 20;

/// The recovery blocks of one file's set, accumulated as its bytes arrive.
pub(crate) struct Par2Lane {
    slice_size: usize,
    rows: Vec<Vec<u8>>,
    pending: Vec<u8>,
    constants: Vec<u16>,
    checksums: Vec<([u8; 16], u32)>,
    file: FileHashState,
    head: Vec<u8>,
    len: u64,
}

impl Par2Lane {
    pub(crate) fn new(slice_size: u64, rows: u64) -> Result<Self, String> {
        if slice_size == 0 || !slice_size.is_multiple_of(4) {
            return Err(format!(
                "a PAR2 slice is a nonzero multiple of 4 bytes, not {slice_size}"
            ));
        }
        if rows >= MAX_ROWS {
            return Err(format!(
                "a PAR2 set has fewer than {MAX_ROWS} recovery blocks"
            ));
        }
        let size = usize::try_from(slice_size).map_err(|_| "slice size exceeds memory")?;
        Ok(Par2Lane {
            slice_size: size,
            rows: (0..rows).map(|_| vec![0u8; size]).collect(),
            pending: Vec::with_capacity(size),
            constants: Vec::new(),
            checksums: Vec::new(),
            file: FileHashState::new(),
            head: Vec::with_capacity(HASH_16K),
            len: 0,
        })
    }

    pub(crate) fn feed(&mut self, mut data: &[u8]) -> Result<(), String> {
        self.file.update(data);
        self.len += data.len() as u64;
        if self.head.len() < HASH_16K {
            let take = (HASH_16K - self.head.len()).min(data.len());
            self.head.extend_from_slice(&data[..take]);
        }
        let size = self.slice_size;
        while !data.is_empty() {
            if self.pending.is_empty() && data.len() >= size {
                self.slice(&data[..size])?;
                data = &data[size..];
                continue;
            }
            let take = (size - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() == size {
                let pending = std::mem::take(&mut self.pending);
                self.slice(&pending)?;
                self.pending = pending;
                self.pending.clear();
            }
        }
        Ok(())
    }

    /// Fold one whole slice (zero-padded if it ends the file) into every
    /// recovery block and keep its checksums.
    fn slice(&mut self, slice: &[u8]) -> Result<(), String> {
        let index = self.checksums.len();
        if index as u64 >= MAX_SLICES {
            return Err(format!(
                "the file passes {MAX_SLICES} slices of {} bytes, the most a PAR2 set holds; use a larger block size",
                self.slice_size
            ));
        }
        let mut state = SliceChecksumState::new();
        state.update(slice);
        let (crc, digest) = state.finalize(Some(self.slice_size as u64));
        self.checksums.push((digest, crc));
        if self.rows.is_empty() {
            return Ok(());
        }
        if index >= self.constants.len() {
            let wanted = (index + 1)
                .next_power_of_two()
                .clamp(64, MAX_SLICES as usize);
            self.constants = input_slice_constants(wanted);
        }
        let constant = self.constants[index];
        let mut factors: Vec<FactorDst<'_>> = self
            .rows
            .iter_mut()
            .enumerate()
            .map(|(exponent, row)| FactorDst {
                factor: gf_pow(constant, exponent as u32),
                dst: row.as_mut_slice(),
            })
            .collect();
        mul_acc_multi_region(&mut factors, slice);
        Ok(())
    }

    /// The finished set, recording the file as `name`.
    pub(crate) fn finish(mut self, name: &str) -> Result<Par2Set, String> {
        if !self.pending.is_empty() {
            let mut pending = std::mem::take(&mut self.pending);
            pending.resize(self.slice_size, 0);
            // The checksums cover the real bytes, padded with zeros.
            self.slice(&pending)?;
        }
        let hash_16k = md5(&self.head);
        let hash_full = self.file.finalize();
        let mut id_input = Vec::with_capacity(24 + name.len());
        id_input.extend_from_slice(&hash_16k);
        id_input.extend_from_slice(&self.len.to_le_bytes());
        id_input.extend_from_slice(name.as_bytes());
        let file_id = md5(&id_input);

        let mut main = Vec::with_capacity(28);
        main.extend_from_slice(&(self.slice_size as u64).to_le_bytes());
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&file_id);
        let set_id = md5(&main);

        let mut description = Vec::with_capacity(56 + name.len() + 3);
        description.extend_from_slice(&file_id);
        description.extend_from_slice(&hash_full);
        description.extend_from_slice(&hash_16k);
        description.extend_from_slice(&self.len.to_le_bytes());
        description.extend_from_slice(name.as_bytes());
        pad(&mut description);

        let mut ifsc = Vec::with_capacity(16 + self.checksums.len() * 20);
        ifsc.extend_from_slice(&file_id);
        for (digest, crc) in &self.checksums {
            ifsc.extend_from_slice(digest);
            ifsc.extend_from_slice(&crc.to_le_bytes());
        }

        let mut creator_body = CREATOR.as_bytes().to_vec();
        pad(&mut creator_body);

        Ok(Par2Set {
            critical: vec![
                packet(&set_id, TYPE_MAIN, &main),
                packet(&set_id, TYPE_FILE_DESC, &description),
                packet(&set_id, TYPE_IFSC, &ifsc),
            ],
            creator: packet(&set_id, TYPE_CREATOR, &creator_body),
            set_id,
            rows: self.rows,
            slice_size: self.slice_size as u64,
            blocks: self.checksums.len() as u64,
            len: self.len,
        })
    }
}

/// A finished one-file PAR2 set, not yet written.
pub(crate) struct Par2Set {
    pub(crate) set_id: [u8; 16],
    critical: Vec<Vec<u8>>,
    creator: Vec<u8>,
    rows: Vec<Vec<u8>>,
    pub(crate) slice_size: u64,
    pub(crate) blocks: u64,
    pub(crate) len: u64,
}

impl Par2Set {
    pub(crate) fn recovery_blocks(&self) -> u64 {
        self.rows.len() as u64
    }

    fn recovery_packet(&self, out: &mut impl Write, exponent: u32) -> io::Result<()> {
        let data = &self.rows[exponent as usize];
        let length = (HEADER_SIZE + 4 + data.len()) as u64;
        let mut hash = FileHashState::new();
        hash.update(&self.set_id);
        hash.update(TYPE_RECOVERY);
        hash.update(&exponent.to_le_bytes());
        hash.update(data);
        out.write_all(MAGIC)?;
        out.write_all(&length.to_le_bytes())?;
        out.write_all(&hash.finalize())?;
        out.write_all(&self.set_id)?;
        out.write_all(TYPE_RECOVERY)?;
        out.write_all(&exponent.to_le_bytes())?;
        out.write_all(data)
    }
}

fn pad(body: &mut Vec<u8>) {
    body.resize(body.len().next_multiple_of(4), 0);
}

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_SIZE + body.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&((HEADER_SIZE + body.len()) as u64).to_le_bytes());
    packet.extend_from_slice(&[0u8; 16]);
    packet.extend_from_slice(set_id);
    packet.extend_from_slice(kind);
    packet.extend_from_slice(body);
    let hash = md5(&packet[32..]);
    packet[16..32].copy_from_slice(&hash);
    packet
}

/// The largest packet read to authenticate a file as a PAR2 volume. Every
/// volume carries the set's Main, file description and checksum packets,
/// which stay far below this; larger packets (recovery slices) are skipped.
const AUTHENTICATING_PACKET_LIMIT: u64 = 1 << 20;

/// The first volume of an earlier set at `stem` that a new set writing
/// `outputs` would leave behind: a file named `BASE.vol*.par2` beside the
/// stem, not among `outputs`, holding at least one PAR2 packet whose hash
/// checks. A file that only has a volume's name is nobody's volume and is
/// ignored, as `par3 create` ignores unauthenticated carriers.
pub(crate) fn obsolete_volume(stem: &Path, outputs: &[PathBuf]) -> io::Result<Option<PathBuf>> {
    let directory = match stem.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if !directory.is_dir() {
        return Ok(None);
    }
    let name = stem
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prefix = format!("{}.vol", name.strip_suffix(".par2").unwrap_or(&name));
    let planned: Vec<_> = outputs.iter().filter_map(|path| path.file_name()).collect();
    let mut entries: Vec<_> = std::fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_name = entry.file_name();
        let text = file_name.to_string_lossy();
        if !text.starts_with(&prefix)
            || !text.ends_with(".par2")
            || planned.contains(&file_name.as_os_str())
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        if holds_an_authentic_packet(&entry.path())? {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

/// Whether `path` holds a PAR2 packet whose MD5 checks, walking packet
/// headers from the start and reading only packets up to
/// [`AUTHENTICATING_PACKET_LIMIT`].
fn holds_an_authentic_packet(path: &Path) -> io::Result<bool> {
    use par2_rs::packet::header::PacketHeader;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let mut offset = 0u64;
    let mut header = [0u8; HEADER_SIZE];
    while length.saturating_sub(offset) >= HEADER_SIZE as u64 {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut header)?;
        let Ok(parsed) = PacketHeader::parse(&header, offset) else {
            return Ok(false);
        };
        if parsed.length > length - offset {
            return Ok(false);
        }
        if parsed.length <= AUTHENTICATING_PACKET_LIMIT {
            let mut packet = header.to_vec();
            packet.resize(parsed.length as usize, 0);
            file.read_exact(&mut packet[HEADER_SIZE..])?;
            if parsed.validate_hash(&packet, offset).is_ok() {
                return Ok(true);
            }
        }
        offset += parsed.length;
    }
    Ok(false)
}

/// The index file and volume paths of a set named by `stem`, as par2-rs
/// names them: `stem.par2`, then `stem.volFIRST+COUNT.par2` in power-of-two
/// volumes.
pub(crate) fn sidecar_paths(stem: &Path, rows: u64) -> (PathBuf, Vec<(u64, u64, PathBuf)>) {
    let directory = stem.parent().unwrap_or(Path::new(""));
    let name = stem
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = name.strip_suffix(".par2").unwrap_or(&name).to_owned();
    let splits = split_volumes(rows);
    let first_width = rows.to_string().len();
    let count_width = splits
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0)
        .to_string()
        .len();
    let volumes = splits
        .into_iter()
        .map(|(first, count)| {
            (
                first,
                count,
                directory.join(format!(
                    "{base}.vol{first:0first_width$}+{count:0count_width$}.par2"
                )),
            )
        })
        .collect();
    (directory.join(format!("{base}.par2")), volumes)
}

/// Write the set beside its destinations: the index (the critical packets
/// and the creator) and the recovery volumes, each with its own copy of the
/// critical packets. Nothing is installed until [`StagedSibling::install`].
pub(crate) fn write_sidecar(
    stem: &Path,
    set: &Par2Set,
    overwrite: bool,
    durability: Durability,
) -> io::Result<StagedSibling> {
    let (index, volumes) = sidecar_paths(stem, set.recovery_blocks());
    check_targets(
        std::iter::once(&index).chain(volumes.iter().map(|(_, _, path)| path)),
        overwrite,
    )?;
    let index_file = write_file(&index, durability, |out| {
        for packet in &set.critical {
            out.write_all(packet)?;
        }
        out.write_all(&set.creator)
    })?;
    let mut files = vec![(index_file, index)];
    for (first, count, path) in volumes {
        let staged = write_file(&path, durability, |out| {
            // par2-rs's layout, after par2cmdline's: a volume of `count`
            // blocks carries bit_length(count) copies of each critical packet,
            // spread evenly between its recovery packets, then the creator.
            let copies = u64::from(u64::BITS - count.leading_zeros());
            let critical = set.critical.len() as u64;
            let mut due = 0u64;
            let mut next = 0usize;
            for exponent in first..first + count {
                set.recovery_packet(out, exponent as u32)?;
                due += copies * critical;
                while due >= count {
                    out.write_all(&set.critical[next])?;
                    next = (next + 1) % set.critical.len();
                    due -= count;
                }
            }
            out.write_all(&set.creator)
        })?;
        files.push((staged, path));
    }
    Ok(StagedSibling::new(files, overwrite))
}
