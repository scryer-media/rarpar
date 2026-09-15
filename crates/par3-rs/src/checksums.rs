//! Run-compact storage for authenticated input-block checksums.
//!
//! External Data packets describe consecutive blocks from a starting index, so
//! a set's checksums arrive as runs and almost always stay runs: the reference
//! omits only the blocks that hold chunk tails. Keeping them as runs stores one
//! [`BlockChecksum`] per block plus a small descriptor per run, instead of an
//! ordered-map node per block. Lookup stays `O(log runs)`.

use crate::packet::BlockChecksum;

/// Bytes one [`ChecksumRun`] descriptor occupies, for the resolution budget.
pub(crate) const RUN_BYTES: usize = size_of::<ChecksumRun>();

/// One span of consecutive block indices whose checksums are stored together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChecksumRun {
    /// Index of the first block this run describes.
    first: u64,
    /// Offset of that block's checksum in `values`.
    at: usize,
    /// Number of consecutive blocks the run covers.
    count: usize,
}

/// Every input-block checksum a set carries, stored as sorted disjoint runs.
///
/// Coverage is normally partial, so this is a sparse map keyed by block index,
/// not a dense table: `len` counts checksums, never blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockChecksums {
    runs: Vec<ChecksumRun>,
    values: Vec<BlockChecksum>,
}

impl BlockChecksums {
    /// Number of blocks a checksum is held for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the set supplied no input-block checksums at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Number of consecutive runs the checksums collapse into.
    #[must_use]
    pub fn runs(&self) -> usize {
        self.runs.len()
    }

    /// The checksum for one input block, if this set carries it.
    #[must_use]
    pub fn get(&self, index: u64) -> Option<&BlockChecksum> {
        let at = self.runs.partition_point(|run| run.first <= index);
        let run = self.runs.get(at.checked_sub(1)?)?;
        let step = usize::try_from(index - run.first).ok()?;
        (step < run.count).then(|| &self.values[run.at + step])
    }

    /// Whether a checksum is held for one input block.
    #[must_use]
    pub fn contains(&self, index: u64) -> bool {
        self.get(index).is_some()
    }

    /// Every block index and checksum, in ascending block order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &BlockChecksum)> + '_ {
        self.runs.iter().flat_map(move |run| {
            (0..run.count).map(move |step| (run.first + step as u64, &self.values[run.at + step]))
        })
    }

    /// Bytes these containers hold, from their real capacities.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        self.runs
            .capacity()
            .saturating_mul(size_of::<ChecksumRun>())
            .saturating_add(
                self.values
                    .capacity()
                    .saturating_mul(size_of::<BlockChecksum>()),
            )
    }
}

impl<'a> IntoIterator for &'a BlockChecksums {
    type Item = (u64, &'a BlockChecksum);
    type IntoIter = Box<dyn Iterator<Item = (u64, &'a BlockChecksum)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Collects `(index, checksum)` pairs and compacts them into runs.
///
/// Later duplicates for a block are discarded, matching the ordered map this
/// replaces: the first External Data packet to describe a block wins.
#[derive(Debug, Default)]
pub(crate) struct BlockChecksumsBuilder {
    pairs: Vec<(u64, BlockChecksum)>,
}

impl BlockChecksumsBuilder {
    /// Start with room for `pairs` records already allocated.
    ///
    /// The pair vector is what the set's resolution charge covers, one
    /// slot per described checksum. Growing it by doubling would hold up to
    /// twice that while `build` allocates the values and the runs beside it, so
    /// the caller counts the checksums it is about to push and says so here.
    pub(crate) fn with_capacity(pairs: usize) -> Self {
        Self {
            pairs: Vec::with_capacity(pairs),
        }
    }

    /// How many records are allocated for. Test-facing.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.pairs.capacity()
    }

    /// Record one block's checksum; the first record for a block wins.
    pub(crate) fn push(&mut self, index: u64, checksum: BlockChecksum) {
        self.pairs.push((index, checksum));
    }

    /// Sort, deduplicate and collapse into runs.
    pub(crate) fn build(mut self) -> BlockChecksums {
        // A stable sort keeps arrival order inside one block index, so the
        // first packet that described a block is the one `dedup_by_key` keeps.
        self.pairs.sort_by_key(|(index, _)| *index);
        self.pairs.dedup_by_key(|(index, _)| *index);
        // Count the runs before allocating the vector that holds them.
        // `shrink_to_fit` on a vector that grew by doubling allocates the exact
        // copy while the oversized buffer is still live, so the peak is the sum
        // of both — for a set whose blocks are scattered that is one descriptor
        // per block, twice over, none of it budgeted. One extra pass over a
        // vector already in cache buys an exact allocation and no copy.
        let mut count = 0usize;
        let mut previous: Option<u64> = None;
        for (index, _) in &self.pairs {
            if previous.and_then(|last: u64| last.checked_add(1)) != Some(*index) {
                count += 1;
            }
            previous = Some(*index);
        }
        let mut runs: Vec<ChecksumRun> = Vec::with_capacity(count);
        let mut values = Vec::with_capacity(self.pairs.len());
        for (index, checksum) in self.pairs {
            match runs.last_mut() {
                Some(run) if run.first + run.count as u64 == index => run.count += 1,
                _ => runs.push(ChecksumRun {
                    first: index,
                    at: values.len(),
                    count: 1,
                }),
            }
            values.push(checksum);
        }
        debug_assert_eq!(runs.len(), runs.capacity(), "the run count was exact");
        BlockChecksums { runs, values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fingerprint;

    /// PR #73 round 2, finding 2. The builder started empty and grew by
    /// doubling, so the pair vector could hold twice the slots the set's
    /// resolution charge paid for, and held them while `build` allocated the
    /// values and the runs beside it. It is now told the count up front.
    #[test]
    fn the_pair_vector_never_grows_past_the_count_it_was_given() {
        let total = 300usize;
        let mut builder = BlockChecksumsBuilder::with_capacity(total);
        assert_eq!(builder.capacity(), total, "the count was not allocated");
        for index in 0..total as u64 {
            builder.push(
                index,
                BlockChecksum {
                    rolling_hash: index,
                    fingerprint: [0u8; 16],
                },
            );
            assert_eq!(
                builder.capacity(),
                total,
                "the vector doubled past the charge at {index}"
            );
        }
        let checksums = builder.build();
        assert_eq!(checksums.len(), total);
    }

    /// PR #73 finding 13. `shrink_to_fit` on a vector that grew by doubling
    /// allocates the exact copy while the oversized buffer is still live, so a
    /// set whose blocks are scattered peaked at two descriptor arrays at once.
    /// The run count is now known before the vector exists.
    #[test]
    fn the_run_vector_is_allocated_at_exactly_the_size_it_will_hold() {
        for step in [1u64, 2, 7] {
            let mut builder = BlockChecksumsBuilder::default();
            for index in 0..300u64 {
                builder.push(index * step, checksum(index as u8));
            }
            let built = builder.build();
            assert_eq!(
                built.runs.len(),
                built.runs.capacity(),
                "step {step} left {} spare run slots",
                built.runs.capacity() - built.runs.len()
            );
            let expected = if step == 1 { 1 } else { 300 };
            assert_eq!(built.runs.len(), expected, "step {step}");
            assert_eq!(built.len(), 300);
        }
        // Duplicates and arrival order must not change the count either.
        let mut builder = BlockChecksumsBuilder::default();
        for index in [5u64, 1, 2, 5, 3, 9, 1] {
            builder.push(index, checksum(index as u8));
        }
        let built = builder.build();
        assert_eq!(built.runs.len(), built.runs.capacity());
        assert_eq!(built.runs.len(), 3, "1..=3, then 5, then 9");
    }

    fn checksum(seed: u8) -> BlockChecksum {
        BlockChecksum {
            rolling_hash: u64::from(seed),
            fingerprint: [seed; 16] as Fingerprint,
        }
    }

    #[test]
    fn consecutive_indices_collapse_into_one_run() {
        let mut builder = BlockChecksumsBuilder::default();
        for index in 0..8u64 {
            builder.push(index, checksum(index as u8));
        }
        let checksums = builder.build();
        assert_eq!(checksums.runs(), 1);
        assert_eq!(checksums.len(), 8);
        assert_eq!(checksums.get(3).expect("present").rolling_hash, 3);
        assert!(checksums.get(8).is_none());
    }

    #[test]
    fn a_gap_starts_a_new_run_and_lookup_still_answers_both_sides() {
        let mut builder = BlockChecksumsBuilder::default();
        for index in [0u64, 1, 2, 7, 8] {
            builder.push(index, checksum(index as u8));
        }
        let checksums = builder.build();
        assert_eq!(checksums.runs(), 2);
        assert_eq!(checksums.len(), 5);
        assert!(checksums.get(3).is_none());
        assert!(checksums.get(6).is_none());
        assert_eq!(checksums.get(7).expect("present").rolling_hash, 7);
        assert_eq!(checksums.get(8).expect("present").rolling_hash, 8);
        let collected: Vec<u64> = checksums.iter().map(|(index, _)| index).collect();
        assert_eq!(collected, vec![0, 1, 2, 7, 8]);
    }

    #[test]
    fn the_first_description_of_a_block_wins_whatever_order_it_arrives_in() {
        let mut builder = BlockChecksumsBuilder::default();
        builder.push(5, checksum(1));
        builder.push(4, checksum(2));
        builder.push(5, checksum(3));
        let checksums = builder.build();
        assert_eq!(checksums.len(), 2);
        assert_eq!(checksums.get(5).expect("present").rolling_hash, 1);
        assert_eq!(checksums.get(4).expect("present").rolling_hash, 2);
    }

    #[test]
    fn unsorted_arrival_produces_the_same_runs_as_sorted_arrival() {
        let mut forward = BlockChecksumsBuilder::default();
        let mut backward = BlockChecksumsBuilder::default();
        for index in 0..16u64 {
            forward.push(index, checksum(index as u8));
        }
        for index in (0..16u64).rev() {
            backward.push(index, checksum(index as u8));
        }
        assert_eq!(forward.build(), backward.build());
    }
}
