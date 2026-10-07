//! `l` and `l -slt`: 7-Zip's listing of an archive's items.

use std::path::PathBuf;

use super::format::{
    attributes_long, attributes_short, block_is_encrypted, block_method, filetime_string,
};
use super::volume::{OpenFailure, Opened};
use super::{
    EXIT_FATAL, EXIT_OK, Options, Session, break_signaled, info_block, open_error_body, open_path,
};

const TITLE: &str = "   Date      Time    Attr         Size   Compressed  Name\n";
const RULE: &str = "------------------- ----- ------------ ------------  ------------------------";

#[derive(Default)]
struct Sum {
    mtime: u64,
    size: u64,
    packed: u64,
    files: u64,
    folders: u64,
}

impl Sum {
    fn add(&mut self, other: &Sum) {
        self.mtime = self.mtime.max(other.mtime);
        self.size += other.size;
        self.packed += other.packed;
        self.files += other.files;
        self.folders += other.folders;
    }

    fn line(&self) -> String {
        let time = if self.mtime == 0 {
            String::new()
        } else {
            filetime_string(self.mtime, false)
        };
        let mut count = format!("{} files", self.files);
        if self.folders != 0 {
            count.push_str(&format!(", {} folders", self.folders));
        }
        format!(
            "{time:<19}       {:>12} {:>12}  {count}\n",
            self.size, self.packed
        )
    }
}

/// Each file's packed size as 7-Zip shows it: a block's packed bytes on its
/// first file, zero for items without data, nothing for the rest.
fn packed_sizes(opened: &Opened) -> Vec<Option<u64>> {
    let archive = &opened.archive;
    let pack_sizes = archive.pack_sizes();
    let firsts = archive.stream_map.block_first_pack_stream_index();
    let block_packed: Vec<u64> = (0..archive.blocks.len())
        .map(|block| {
            let start = firsts[block];
            let end = firsts.get(block + 1).copied().unwrap_or(pack_sizes.len());
            pack_sizes[start..end].iter().sum()
        })
        .collect();
    let mut seen = vec![false; archive.blocks.len()];
    archive
        .files
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            if !entry.has_stream {
                return Some(0);
            }
            let block = archive.stream_map.file_block_index[index]?;
            if seen[block] {
                None
            } else {
                seen[block] = true;
                Some(block_packed[block])
            }
        })
        .collect()
}

fn ticks_text(defined: bool, ticks: u64, fraction: bool) -> String {
    if defined {
        filetime_string(ticks, fraction)
    } else {
        String::new()
    }
}

fn technical(opened: &Opened, selected: &[bool], packed: &[Option<u64>]) -> String {
    let archive = &opened.archive;
    let files = &archive.files;
    let any_anti = files.iter().any(|entry| entry.is_anti_item);
    let any_created = files.iter().any(|entry| entry.has_creation_date);
    let any_accessed = files.iter().any(|entry| entry.has_access_date);
    let any_attrib = files.iter().any(|entry| entry.has_windows_attributes);
    let any_stream = files.iter().any(|entry| entry.has_stream);
    let mut text = String::new();
    for (index, entry) in files.iter().enumerate() {
        if !selected[index] {
            continue;
        }
        let block = archive.stream_map.file_block_index[index];
        text.push_str(&format!("Path = {}\n", entry.name));
        text.push_str(&format!("Size = {}\n", entry.size));
        match packed[index] {
            Some(value) => text.push_str(&format!("Packed Size = {value}\n")),
            None => text.push_str("Packed Size = \n"),
        }
        text.push_str(&format!(
            "Modified = {}\n",
            ticks_text(
                entry.has_last_modified_date,
                u64::from(entry.last_modified_date),
                true
            )
        ));
        if any_anti {
            text.push_str(&format!(
                "Anti = {}\n",
                if entry.is_anti_item { '+' } else { '-' }
            ));
        }
        if any_created {
            text.push_str(&format!(
                "Created = {}\n",
                ticks_text(
                    entry.has_creation_date,
                    u64::from(entry.creation_date),
                    true
                )
            ));
        }
        if any_accessed {
            text.push_str(&format!(
                "Accessed = {}\n",
                ticks_text(entry.has_access_date, u64::from(entry.access_date), true)
            ));
        }
        if any_attrib {
            let value = if entry.has_windows_attributes {
                attributes_long(entry.windows_attributes, entry.is_directory)
            } else {
                String::new()
            };
            text.push_str(&format!("Attributes = {value}\n"));
        }
        if any_stream {
            if entry.has_crc && entry.has_stream {
                text.push_str(&format!("CRC = {:08X}\n", entry.crc as u32));
            } else {
                text.push_str("CRC = \n");
            }
        }
        let encrypted = block.is_some_and(|b| block_is_encrypted(&archive.blocks[b]));
        text.push_str(&format!(
            "Encrypted = {}\n",
            if encrypted { '+' } else { '-' }
        ));
        match block {
            Some(b) => {
                text.push_str(&format!("Method = {}\n", block_method(&archive.blocks[b])));
                text.push_str(&format!("Block = {b}\n"));
            }
            None => text.push_str("Method = \nBlock = \n"),
        }
        text.push('\n');
    }
    text
}

fn table(opened: &Opened, selected: &[bool], packed: &[Option<u64>], sum: &mut Sum) -> String {
    let mut text = String::new();
    for (index, entry) in opened.archive.files.iter().enumerate() {
        if !selected[index] {
            continue;
        }
        let ticks = u64::from(entry.last_modified_date);
        let time = if entry.has_last_modified_date && ticks != 0 {
            sum.mtime = sum.mtime.max(ticks);
            filetime_string(ticks, false)
        } else {
            String::new()
        };
        let attrib = attributes_short(
            if entry.has_windows_attributes {
                entry.windows_attributes
            } else {
                0
            },
            entry.is_directory,
        );
        let packed_text = match packed[index] {
            Some(value) => {
                sum.packed += value;
                format!("{value:>12}")
            }
            None => " ".repeat(12),
        };
        if entry.is_directory {
            sum.folders += 1;
        } else {
            sum.files += 1;
            sum.size += entry.size;
        }
        text.push_str(&format!(
            "{time:<19} {attrib} {:>12} {packed_text}  {}\n",
            entry.size, entry.name
        ));
    }
    text
}

pub(super) fn run(session: &mut Session, options: &Options, archives: Vec<(PathBuf, u64)>) -> u8 {
    let mut errors = 0u64;
    let mut warnings = 0u64;
    let mut total = Sum::default();
    let mut archive_count = 0u64;
    let mut volume_count = 0u64;
    let mut total_size = 0u64;
    let mut read_volumes: Vec<PathBuf> = Vec::new();
    for (archive, size) in &archives {
        if read_volumes.iter().any(|seen| seen == archive) {
            continue;
        }
        let shown = archive.to_string_lossy();
        let path = shown.as_ref();
        total_size += size;
        if options.headers {
            session.out(&format!("\nListing archive: {path}\n\n"));
        }
        let (set, opened) = open_path(session, options, archive, *size);
        let opened = match opened {
            Ok(opened) => opened,
            Err(OpenFailure::Aborted) => return break_signaled(session),
            Err(failure) => {
                errors += 1;
                let body = open_error_body(path, &set, &failure, options.forced_type.as_deref());
                session.err(&format!("\nERROR: {path} : {body}\n"));
                continue;
            }
        };
        read_volumes.extend(set.paths.iter().skip(1).cloned());
        archive_count += 1;
        volume_count += set.paths.len() as u64;
        total_size += set.sizes.iter().skip(1).sum::<u64>();
        if opened.stream_len > opened.physical_size {
            warnings += 1;
        }
        let mut text = String::new();
        if options.headers {
            text.push_str(&info_block(path, &set, &opened));
            text.push('\n');
        }
        let selected = super::extract::selection(&opened.archive.files, &options.censor);
        let packed = packed_sizes(&opened);
        if options.technical {
            text.push_str("----------\n");
            text.push_str(&technical(&opened, &selected, &packed));
        } else {
            let mut sum = Sum::default();
            if options.headers {
                text.push_str(TITLE);
                text.push_str(RULE);
                text.push('\n');
            }
            text.push_str(&table(&opened, &selected, &packed, &mut sum));
            if options.headers {
                text.push_str(RULE);
                text.push('\n');
                text.push_str(&sum.line());
            }
            total.add(&sum);
        }
        session.out(&text);
    }
    if options.headers && !options.technical && (archives.len() > 1 || volume_count > 1) {
        session.out(&format!(
            "\n{RULE}\n{}\nArchives: {archive_count}\nVolumes: {volume_count}\nTotal archives size: {total_size}\n",
            total.line()
        ));
    }
    if options.headers && warnings > 0 {
        session.out(&format!("\nWarnings: {warnings}\n"));
    }
    if errors > 0 {
        if options.headers {
            session.out(&format!("\nErrors: {errors}\n"));
        }
        return EXIT_FATAL;
    }
    EXIT_OK
}
