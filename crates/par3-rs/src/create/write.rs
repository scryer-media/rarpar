//! Laying the packets out into an index file and recovery volumes.
//!
//! The index file holds one copy of everything except the recovery data. Each
//! volume holds the recovery blocks it was given, and around them a full copy of
//! the common packets plus `log2(blocks in this volume)` further copies spread
//! between the recovery packets — so a volume that survives on its own describes
//! the whole set, and a volume damaged in one place probably still does.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use super::packets::BuiltPackets;
use crate::cauchy::RecoveryRow;
use crate::error::{Par3Error, Result};
use crate::packet::{Packet, PacketBody, RecoveryDataPacket};

/// One recovery volume: the recovery blocks it carries, and what it is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Volume {
    /// Index of its first recovery block.
    pub start: u64,
    /// How many recovery blocks it holds.
    pub count: u64,
    /// Its file name, `<stem>.vol<start>+<count>.par3`.
    pub path: PathBuf,
}

/// Split the recovery blocks across volumes: 1, 2, 4, 8, … with the last volume
/// taking whatever is left.
///
/// A reader that has lost a few blocks then only has to fetch a small volume,
/// while a reader that has lost many can fetch one large one.
pub(crate) fn split_volumes(recovery_count: u64) -> Vec<(u64, u64)> {
    let mut splits = Vec::new();
    let mut remaining = recovery_count;
    let mut start = 0u64;
    let mut size = 1u64;
    while remaining > 0 {
        let count = size.min(remaining);
        splits.push((start, count));
        start += count;
        remaining -= count;
        size = size.saturating_mul(2);
    }
    splits
}

/// How wide the two numbers in a volume name are written, zero-padded: the width
/// of the largest starting index and the width of the largest block count.
fn digit_widths(splits: &[(u64, u64)]) -> (usize, usize) {
    let decimal = |value: u64| value.to_string().len();
    let starts = splits.last().map_or(0, |(start, _)| *start);
    let counts = splits.iter().map(|(_, count)| *count).max().unwrap_or(0);
    (decimal(starts), decimal(counts))
}

/// Work out where everything will be written.
///
/// A stem that already ends in `.par3` keeps that name for the index rather than
/// gaining a second one, and the volumes sit next to it.
pub(crate) fn plan_paths(
    output_stem: &Path,
    recovery_count: u64,
) -> Result<(PathBuf, Vec<Volume>)> {
    let refuse = |reason: &str| Par3Error::CreateInput {
        path: output_stem.display().to_string(),
        reason: reason.to_owned(),
    };
    let name = output_stem
        .file_name()
        .ok_or_else(|| refuse("names no file"))?
        .to_str()
        .ok_or_else(|| refuse("is not valid UTF-8"))?;
    let stem = name.strip_suffix(".par3").unwrap_or(name);
    if stem.is_empty() {
        return Err(refuse("has no name before its \".par3\" suffix"));
    }
    let directory = output_stem.parent().unwrap_or(Path::new(""));

    let splits = split_volumes(recovery_count);
    let (start_width, count_width) = digit_widths(&splits);
    let volumes = splits
        .into_iter()
        .map(|(start, count)| Volume {
            start,
            count,
            path: directory.join(format!(
                "{stem}.vol{start:0start_width$}+{count:0count_width$}.par3"
            )),
        })
        .collect();
    Ok((directory.join(format!("{stem}.par3")), volumes))
}

/// Write the index file and every recovery volume.
///
/// Nothing is written until every target has been checked, so a refusal to
/// overwrite leaves the directory as it was.
pub(crate) fn write_set(
    index_path: &Path,
    volumes: &[Volume],
    packets: &BuiltPackets,
    recovery: &[RecoveryRow],
    block_size: u64,
    overwrite: bool,
) -> Result<Vec<PathBuf>> {
    if !overwrite {
        for path in std::iter::once(index_path).chain(volumes.iter().map(|volume| &*volume.path)) {
            if path.try_exists().unwrap_or(false) {
                return Err(Par3Error::CreateInput {
                    path: path.display().to_string(),
                    reason: "already exists; pass `overwrite` to replace it".to_owned(),
                });
            }
        }
    }

    let mut written = Vec::with_capacity(1 + volumes.len());
    write_file(index_path, overwrite, |out| {
        out.write_all(&packets.creator)?;
        for packet in &packets.common {
            out.write_all(packet)?;
        }
        if let Some(comment) = &packets.comment {
            out.write_all(comment)?;
        }
        Ok(())
    })?;
    written.push(index_path.to_path_buf());

    for volume in volumes {
        write_file(&volume.path, overwrite, |out| {
            write_volume(out, volume, packets, recovery, block_size)
        })?;
        written.push(volume.path.clone());
    }
    Ok(written)
}

/// Write one recovery volume's packets.
fn write_volume(
    out: &mut impl Write,
    volume: &Volume,
    packets: &BuiltPackets,
    recovery: &[RecoveryRow],
    block_size: u64,
) -> std::io::Result<()> {
    out.write_all(&packets.creator)?;
    for packet in &packets.common {
        out.write_all(packet)?;
    }

    // One further copy of the common packets per doubling of this volume's block
    // count, spread evenly between the recovery packets and cycling through the
    // list so that consecutive volumes do not all repeat the same few packets.
    let mut repeats = 0u64;
    let mut step = 2u64;
    while step <= volume.count {
        repeats += 1;
        step *= 2;
    }
    let total_repeats = repeats * packets.common.len() as u64;
    let mut emitted = 0u64;
    let mut cursor = 0usize;

    for (position, row) in recovery
        .iter()
        .filter(|row| row.index() >= volume.start && row.index() < volume.start + volume.count)
        .enumerate()
    {
        let mut data = row.data().to_vec();
        data.resize(block_size as usize, 0);
        let packet = Packet::new(
            packets.set_id,
            PacketBody::RecoveryData(RecoveryDataPacket {
                root_hash: packets.root_hash,
                matrix_hash: packets
                    .matrix_hash
                    .expect("a set with recovery blocks has a Matrix packet"),
                recovery_block_index: row.index(),
                data,
            }),
        );
        out.write_all(&packet.to_bytes())?;

        let target = total_repeats * (position as u64 + 1) / volume.count;
        while emitted < target {
            out.write_all(&packets.common[cursor])?;
            cursor = (cursor + 1) % packets.common.len();
            emitted += 1;
        }
    }

    if let Some(comment) = &packets.comment {
        out.write_all(comment)?;
    }
    Ok(())
}

/// Create a file and hand a buffered writer to `body`, naming the path in any
/// error.
fn write_file(
    path: &Path,
    overwrite: bool,
    body: impl FnOnce(&mut BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> Result<()> {
    let name = || path.display().to_string();
    let file = OpenOptions::new()
        .write(true)
        .create(overwrite)
        .create_new(!overwrite)
        .truncate(overwrite)
        .open(path)
        .map_err(|source| Par3Error::FileIo {
            path: name(),
            source,
        })?;
    let mut out = BufWriter::new(file);
    body(&mut out).map_err(|source| Par3Error::FileIo {
        path: name(),
        source,
    })?;
    out.flush().map_err(|source| Par3Error::FileIo {
        path: name(),
        source,
    })?;
    out.into_inner()
        .map_err(|error| Par3Error::FileIo {
            path: name(),
            source: error.into_error(),
        })?
        .sync_all()
        .map_err(|source| Par3Error::FileIo {
            path: name(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volumes_double_until_the_blocks_run_out() {
        assert_eq!(split_volumes(0), []);
        assert_eq!(split_volumes(1), [(0, 1)]);
        assert_eq!(split_volumes(2), [(0, 1), (1, 1)]);
        assert_eq!(split_volumes(3), [(0, 1), (1, 2)]);
        assert_eq!(split_volumes(10), [(0, 1), (1, 2), (3, 4), (7, 3)]);
    }

    #[test]
    fn names_are_padded_to_the_widest_number_either_field_reaches() {
        // Compared as paths, not as text: the directory is joined with the
        // platform's separator, which is a backslash on Windows.
        let (index, volumes) = plan_paths(Path::new("out/set.par3"), 3).expect("paths");
        assert_eq!(index, Path::new("out/set.par3"));
        let paths: Vec<&Path> = volumes.iter().map(|volume| volume.path.as_path()).collect();
        assert_eq!(
            paths,
            [
                Path::new("out").join("set.vol0+1.par3"),
                Path::new("out").join("set.vol1+2.par3"),
            ]
        );

        // 20 blocks split 1, 2, 4, 8, 5 with the last starting at 15.
        let (_, volumes) = plan_paths(Path::new("set"), 20).expect("paths");
        let names: Vec<String> = volumes
            .iter()
            .map(|volume| volume.path.display().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "set.vol00+1.par3",
                "set.vol01+2.par3",
                "set.vol03+4.par3",
                "set.vol07+8.par3",
                "set.vol15+5.par3"
            ]
        );
    }

    #[test]
    fn a_stem_without_the_suffix_gains_one() {
        let (index, _) = plan_paths(Path::new("set"), 0).expect("paths");
        assert_eq!(index, Path::new("set.par3"));
    }

    #[test]
    fn an_empty_stem_is_refused() {
        assert!(plan_paths(Path::new(".par3"), 0).is_err());
        assert!(plan_paths(Path::new("/"), 0).is_err());
    }
}
