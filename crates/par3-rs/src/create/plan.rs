//! Deciding what a set will contain before any of its data is read.
//!
//! Everything here works from paths, names and sizes alone: the input order,
//! the block size, the number of recovery blocks and the Galois field are all
//! settled before a single byte of file content is touched. That is what lets
//! [`super::create`] read each input file exactly once.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use crate::cauchy::default_field;
use crate::error::{Par3Error, Result};
use crate::packet::GaloisField;
use crate::packet::reader::check_name;

use super::{CreateLimits, InputSpec, RecoveryAmount};

/// The smallest chunk tail that is given an input block of its own; anything
/// shorter is stored inside the File packet.
pub(crate) const MIN_TAIL_BLOCK_LEN: u64 = crate::hash::TAIL_HASH_LEN as u64;

/// The most input and recovery blocks the format can address at once.
pub(crate) const MAX_TOTAL_BLOCKS: u64 = 65536;

/// One input file, named and measured.
#[derive(Debug, Clone)]
pub(crate) struct PlannedFile {
    /// Relative name with `/` separators, as the File and Directory packets
    /// will spell it.
    pub name: String,
    /// Where the bytes are, for reading.
    pub path: PathBuf,
    /// Size in bytes, from the file system.
    pub size: u64,
}

/// Refuse a path that cannot be a PAR3 relative name, and render the one that
/// can as `/`-separated text.
///
/// The rules are the ones this crate's *reader* enforces on the names it parses
/// out of a packet, applied one component at a time, so nothing written here
/// can fail to be read back.
pub(crate) fn relative_name(path: &Path) -> Result<String> {
    let refuse = |reason: String| -> Par3Error {
        Par3Error::CreateInput {
            path: path.display().to_string(),
            reason,
        }
    };
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        let part = match component {
            Component::Normal(part) => part,
            Component::CurDir => return Err(refuse("has a \".\" component".to_owned())),
            Component::ParentDir => return Err(refuse("has a \"..\" component".to_owned())),
            Component::RootDir | Component::Prefix(_) => {
                return Err(refuse("is an absolute path".to_owned()));
            }
        };
        let part = part
            .to_str()
            .ok_or_else(|| refuse("is not valid UTF-8".to_owned()))?;
        check_name(part).map_err(|error| match error {
            Par3Error::UnsafeName { name, reason } => {
                refuse(format!("has an unusable component {name:?}: {reason}"))
            }
            other => other,
        })?;
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(refuse("names no file".to_owned()));
    }
    Ok(parts.join("/"))
}

/// Order input files the way the reference implementation does before it
/// assigns blocks: longest chunk tail first, then largest file, then name.
///
/// Tail size decides the order because tails are packed into shared blocks in
/// this order, and placing the long ones first is what leaves usable gaps.
pub(crate) fn sort_files(files: &mut [PlannedFile], block_size: u64) {
    files.sort_by(|left, right| {
        let tail = |file: &PlannedFile| file.size % block_size;
        tail(right)
            .cmp(&tail(left))
            .then_with(|| right.size.cmp(&left.size))
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
}

/// Order directory names so that a directory always follows the directories
/// beneath it.
///
/// Names are compared one component at a time; when one name is a component
/// prefix of the other, the *longer* one sorts first. A Directory packet names
/// its children by their packet hashes, so every child's packet has to be built
/// before its parent's can be.
pub(crate) fn compare_directory_names(left: &str, right: &str) -> Ordering {
    let mut left = left.split('/');
    let mut right = right.split('/');
    loop {
        match (left.next(), right.next()) {
            (Some(one), Some(other)) => match one.as_bytes().cmp(other.as_bytes()) {
                Ordering::Equal => {}
                difference => return difference,
            },
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Every directory the set describes: the ancestors of each file name, the
/// names the caller listed, and the ancestors of those.
pub(crate) fn directories_of(files: &[PlannedFile], extra: &[String]) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut ancestors = |name: &str, include_self: bool| {
        let mut prefix = String::new();
        let parts: Vec<&str> = name.split('/').collect();
        let last = if include_self {
            parts.len()
        } else {
            parts.len() - 1
        };
        for part in &parts[..last] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            names.insert(prefix.clone());
        }
    };
    for file in files {
        ancestors(&file.name, false);
    }
    for name in extra {
        ancestors(name, true);
    }
    let mut names: Vec<String> = names.into_iter().collect();
    names.sort_by(|left, right| compare_directory_names(left, right));
    names
}

/// Input blocks a set of files needs at a given block size, before any tails
/// are packed together.
///
/// This is the count the reference implementation uses to choose a block size,
/// not the count that ends up in the Root packet: packing tails into shared
/// blocks can only lower it.
fn unpacked_block_count(sizes: &[u64], block_size: u64) -> u64 {
    let mut count: u64 = 0;
    for &size in sizes {
        if size == 0 {
            continue;
        }
        count = count.saturating_add(size / block_size);
        if size % block_size >= MIN_TAIL_BLOCK_LEN {
            count = count.saturating_add(1);
        }
    }
    count
}

/// The block size the reference implementation would choose for these file
/// sizes.
///
/// Aims for a block count near one percent of the block size — that is, the
/// square root of the total, times ten — rounded down to a power of two, then
/// adjusted so that a small set does not end up with awkwardly few blocks and a
/// very large one does not end up with tens of thousands:
///
/// - every file 40 bytes or smaller: 40, and nothing else applies;
/// - otherwise `sqrt(total) * 10`, clamped to the largest file, at least 8,
///   rounded down to a power of two;
/// - 129 to 1000 blocks: halved, but never below 40;
/// - more than 32768 blocks: doubled until it is not, or until a block is as
///   large as the largest file and doubling can no longer help.
///
/// ```
/// # use par3_rs::create::suggest_block_size;
/// assert_eq!(suggest_block_size([40]), 40);
/// assert_eq!(suggest_block_size([5000, 10, 4000]), 512);
/// ```
#[must_use]
pub fn suggest_block_size(sizes: impl IntoIterator<Item = u64>) -> u64 {
    let sizes: Vec<u64> = sizes.into_iter().collect();
    let largest = sizes.iter().copied().max().unwrap_or(0);
    if largest <= MIN_TAIL_BLOCK_LEN {
        return MIN_TAIL_BLOCK_LEN;
    }
    let total: u64 = sizes.iter().copied().fold(0u64, u64::saturating_add);

    // The square root of a total that large is far below the range where an
    // f64 cannot count integers, and the reference computes it in floating
    // point as well.
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    let mut block_size = ((total as f64).sqrt() * 10.0) as u64;
    block_size = block_size.min(largest).max(8);

    let mut power = 8u64;
    while power * 2 <= block_size {
        power *= 2;
    }
    block_size = power;

    // The reference deliberately does not recount after halving; the halving
    // only happens for counts it has already decided are too low.
    let mut count = unpacked_block_count(&sizes, block_size);
    if count > 128 && count <= 1000 {
        block_size = (block_size / 2).max(MIN_TAIL_BLOCK_LEN);
    }
    // Doubling stops once a block is as large as the largest file, because past
    // that point every non-empty file needs exactly one block whatever the size
    // is and the count cannot fall any further. The reference has no such guard
    // and spins forever on a set of many small files; this returns the size the
    // last useful doubling reached.
    while count > 32768 && block_size < largest {
        block_size = block_size.saturating_mul(2);
        count = unpacked_block_count(&sizes, block_size);
    }
    block_size
}

/// Settle the block size, refusing zero and rounding an odd one up.
///
/// GF(2^16) reads a block as little-endian 16-bit symbols and so needs an even
/// block size. The reference rounds *every* odd block size up by one rather
/// than only the ones that will end up in that field, and says nothing about
/// it; the returned value is what the caller gets back in its report.
pub(crate) fn settle_block_size(
    requested: Option<u64>,
    sizes: &[u64],
    limits: &CreateLimits,
) -> Result<u64> {
    let block_size = match requested {
        Some(0) => {
            return Err(Par3Error::CreateInput {
                path: String::new(),
                reason: "a block size of zero protects nothing".to_owned(),
            });
        }
        Some(size) if size % 2 == 1 => size + 1,
        Some(size) => size,
        None => suggest_block_size(sizes.iter().copied()),
    };
    if block_size > limits.max_block_size {
        return Err(Par3Error::CreateLimitExceeded {
            reason: format!(
                "a block size of {block_size} bytes is above the {} the limits allow",
                limits.max_block_size
            ),
        });
    }
    Ok(block_size)
}

/// How many recovery blocks to build, and the field they will be built in.
///
/// A percentage applies to the block count that survives tail packing, which is
/// the one the set actually stores. A set with no input blocks gets no recovery
/// blocks whatever was asked for, because there would be nothing to compute
/// them from.
pub(crate) fn settle_recovery(
    amount: RecoveryAmount,
    block_count: u64,
) -> Result<(u64, GaloisField)> {
    if block_count == 0 {
        return Ok((
            0,
            GaloisField {
                size: 0,
                generator: 0,
            },
        ));
    }
    let count = match amount {
        RecoveryAmount::Blocks(count) => count,
        RecoveryAmount::Percent(percent) => {
            if percent > 250 {
                return Err(Par3Error::CreateInput {
                    path: String::new(),
                    reason: format!("a redundancy of {percent}% is above the 250% maximum"),
                });
            }
            block_count
                .saturating_mul(u64::from(percent))
                .saturating_add(99)
                / 100
        }
    };
    let total = block_count.saturating_add(count);
    if total > MAX_TOTAL_BLOCKS {
        return Err(Par3Error::CreateInput {
            path: String::new(),
            reason: format!(
                "{block_count} input blocks and {count} recovery blocks are more than the \
                 {MAX_TOTAL_BLOCKS} a set can address"
            ),
        });
    }
    Ok((count, default_field(block_count, count, 0)))
}

/// Turn the caller's input list into named, measured files.
///
/// Every name is checked, and every file is measured, before anything is opened:
/// a set that cannot be built fails without having read a byte.
pub(crate) fn collect_files(
    inputs: &InputSpec<'_>,
    limits: &CreateLimits,
) -> Result<Vec<PlannedFile>> {
    if inputs.files.is_empty() {
        return Err(Par3Error::CreateInput {
            path: String::new(),
            reason: "a set has to protect at least one file".to_owned(),
        });
    }
    if inputs.files.len() as u64 > limits.max_files {
        return Err(Par3Error::CreateLimitExceeded {
            reason: format!(
                "{} input files are more than the {} the limits allow",
                inputs.files.len(),
                limits.max_files
            ),
        });
    }

    let mut budget = PathBudget::new(limits);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut files = Vec::with_capacity(inputs.files.len());
    for given in inputs.files {
        let name = relative_name(given)?;
        budget.spend(&name)?;
        if !seen.insert(name.clone()) {
            return Err(Par3Error::CreateInput {
                path: name,
                reason: "is named twice; a set stores each name once".to_owned(),
            });
        }
        let path = inputs.base.join(given);
        let metadata = std::fs::metadata(&path).map_err(|source| Par3Error::FileIo {
            path: path.display().to_string(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(Par3Error::CreateInput {
                path: path.display().to_string(),
                reason: "is not a regular file".to_owned(),
            });
        }
        files.push(PlannedFile {
            name,
            path,
            size: metadata.len(),
        });
    }
    Ok(files)
}

/// The directories the caller asked for beyond the ones the file names imply,
/// checked the same way. They need not exist yet: nothing is read from them.
pub(crate) fn collect_directories(
    inputs: &InputSpec<'_>,
    limits: &CreateLimits,
) -> Result<Vec<String>> {
    let mut budget = PathBudget::new(limits);
    inputs
        .directories
        .iter()
        .map(|given| {
            let name = relative_name(given)?;
            budget.spend(&name)?;
            Ok(name)
        })
        .collect()
}

/// The running total of path text, against the limit on it.
struct PathBudget {
    spent: u64,
    allowed: u64,
}

impl PathBudget {
    fn new(limits: &CreateLimits) -> Self {
        Self {
            spent: 0,
            allowed: limits.max_path_bytes,
        }
    }

    fn spend(&mut self, name: &str) -> Result<()> {
        self.spent = self.spent.saturating_add(name.len() as u64);
        if self.spent > self.allowed {
            return Err(Par3Error::CreateLimitExceeded {
                reason: format!(
                    "the input names are longer than the {} bytes of path text the limits allow",
                    self.allowed
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_name_joins_components_with_slashes() {
        let name = relative_name(Path::new("sub/dir/file.bin")).expect("a usable name");
        assert_eq!(name, "sub/dir/file.bin");
    }

    #[test]
    fn absolute_and_relative_components_are_refused() {
        assert!(relative_name(Path::new("/etc/passwd")).is_err());
        assert!(relative_name(Path::new("../escape")).is_err());
        assert!(relative_name(Path::new("a/../b")).is_err());
        assert!(relative_name(Path::new("")).is_err());
    }

    #[test]
    fn deeper_directories_sort_before_their_parents() {
        let mut names = vec![
            "a".to_owned(),
            "f".to_owned(),
            "a/b".to_owned(),
            "a/b/c".to_owned(),
        ];
        names.sort_by(|left, right| compare_directory_names(left, right));
        assert_eq!(names, ["a/b/c", "a/b", "a", "f"]);
    }

    #[test]
    fn a_name_that_differs_before_the_split_sorts_by_that_name() {
        assert_eq!(compare_directory_names("ab", "a/c"), Ordering::Greater);
        assert_eq!(compare_directory_names("a/c", "ab"), Ordering::Less);
    }

    #[test]
    fn suggested_sizes_follow_the_reference_rule() {
        assert_eq!(suggest_block_size([]), 40);
        assert_eq!(suggest_block_size([0, 12]), 40);
        assert_eq!(suggest_block_size([5000]), 512);
        assert_eq!(suggest_block_size([2 * 1024 * 1024]), 4096);
    }

    #[test]
    fn an_odd_block_size_is_rounded_up() {
        let limits = CreateLimits::default();
        assert_eq!(
            settle_block_size(Some(101), &[], &limits).expect("even"),
            102
        );
        assert_eq!(
            settle_block_size(Some(100), &[], &limits).expect("even"),
            100
        );
        assert!(settle_block_size(Some(0), &[], &limits).is_err());
    }

    #[test]
    fn a_percentage_rounds_up_and_a_ceiling_is_refused() {
        let (count, _) = settle_recovery(RecoveryAmount::Percent(5), 5).expect("five percent");
        assert_eq!(count, 1);
        assert!(settle_recovery(RecoveryAmount::Blocks(70_000), 1).is_err());
        assert!(settle_recovery(RecoveryAmount::Percent(251), 1).is_err());
    }
}
