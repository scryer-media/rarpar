//! Contiguous work ranges for a bounded worker batch.
//!
//! A round covers at most [`capacity`] blocks split into at most one
//! contiguous chunk per worker. Chunking is deliberate: one worker decoding a
//! contiguous run reuses its warm table/scratch state and walks the staged
//! input sequentially. The one-job-per-block alternative was measured to
//! inflate per-block symbol-decode time ~35-42% for identical work while the
//! pool showed no idle slots at chunk granularity, so finer stealing bought
//! nothing and cost locality.

/// An inclusive-exclusive range of block indices assigned together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Batch {
    /// First block in the range.
    pub start: usize,
    /// One past the last block in the range.
    pub end: usize,
}

#[cfg(test)]
impl Batch {
    /// Number of blocks in this range.
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Whether this range contains exactly one block.
    pub const fn is_single_block(self) -> bool {
        self.len() == 1
    }
}

/// Maximum number of blocks considered in one scheduling round.
pub const fn capacity(worker_count: usize) -> usize {
    worker_count.saturating_mul(2)
}

/// Blocks one scheduling round covers: at most two per worker.
pub const fn planned_block_count(block_count: usize, worker_count: usize) -> usize {
    // `capacity(0)` is zero, so a pool with no workers plans nothing.
    let capacity = capacity(worker_count);
    if block_count < capacity {
        block_count
    } else {
        capacity
    }
}

/// Append the round's contiguous, balanced ranges to `out`.
///
/// Ranges are absolute: the first planned block is `first_block`. At most two
/// blocks are considered per worker and at most one range is produced per
/// worker, so each worker decodes one contiguous run — the shape UnRAR uses,
/// and the one that keeps per-worker table scratch and staged input reads
/// sequential. When fewer blocks are available than workers, each range holds
/// one block.
///
/// The caller owns `out` so a controller can recycle one plan buffer across
/// dispatches.
pub fn plan_batches_into(
    first_block: usize,
    block_count: usize,
    worker_count: usize,
    out: &mut Vec<Batch>,
) {
    let planned_count = planned_block_count(block_count, worker_count);
    if planned_count == 0 {
        return;
    }
    // `planned_count > 0` implies `worker_count > 0` (capacity(0) is zero).
    let batch_size =
        planned_count / worker_count + usize::from(!planned_count.is_multiple_of(worker_count));

    let mut start = 0;
    while start < planned_count {
        let end = start.saturating_add(batch_size).min(planned_count);
        out.push(Batch {
            start: first_block + start,
            end: first_block + end,
        });
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(block_count: usize, worker_count: usize) -> Vec<Batch> {
        let mut batches = Vec::new();
        plan_batches_into(0, block_count, worker_count, &mut batches);
        batches
    }

    fn ranges(batches: &[Batch]) -> Vec<(usize, usize)> {
        batches
            .iter()
            .map(|batch| (batch.start, batch.end))
            .collect()
    }

    #[test]
    fn empty_input_has_no_batches() {
        assert!(plan(0, 4).is_empty());
    }

    #[test]
    fn one_block_is_represented_as_a_single_block_batch() {
        let batches = plan(1, 4);
        assert_eq!(ranges(&batches), vec![(0, 1)]);
        assert!(batches[0].is_single_block());
        assert_eq!(batches[0].len(), 1);
    }

    #[test]
    fn partial_count_uses_one_block_ranges() {
        let batches = plan(3, 4);
        assert_eq!(ranges(&batches), vec![(0, 1), (1, 2), (2, 3)]);
        assert!(batches.iter().all(|batch| batch.is_single_block()));
    }

    #[test]
    fn exact_worker_count_is_balanced() {
        let batches = plan(4, 4);
        assert_eq!(ranges(&batches), vec![(0, 1), (1, 2), (2, 3), (3, 4)]);
        assert_eq!(batches.len(), 4);
    }

    #[test]
    fn partial_round_is_balanced_without_empty_ranges() {
        let batches = plan(5, 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 5)]);
        assert!(batches.windows(2).all(|pair| pair[0].end == pair[1].start));
        assert!(batches.iter().all(|batch| batch.start < batch.end));
    }

    #[test]
    fn exact_capacity_uses_one_chunk_per_worker() {
        let batches = plan(capacity(4), 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 6), (6, 8)]);
        assert_eq!(batches.len(), 4);
        assert_eq!(batches.last().unwrap().end, capacity(4));
    }

    #[test]
    fn over_capacity_is_limited_to_two_blocks_per_worker() {
        let batches = plan(capacity(4) + 3, 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 6), (6, 8)]);
        assert_eq!(
            batches.iter().map(|batch| batch.len()).sum::<usize>(),
            capacity(4)
        );
        assert!(batches.len() <= 4);
    }

    #[test]
    fn zero_workers_do_not_create_assignments() {
        assert!(plan(4, 0).is_empty());
        assert_eq!(capacity(0), 0);
        assert_eq!(planned_block_count(4, 0), 0);
    }

    #[test]
    fn ranges_are_absolute_to_the_first_planned_block() {
        let mut batches = vec![Batch { start: 0, end: 1 }];
        plan_batches_into(9, 3, 4, &mut batches);
        // Appended, not replaced: the controller recycles one plan buffer.
        assert_eq!(ranges(&batches), vec![(0, 1), (9, 10), (10, 11), (11, 12)]);
    }

    #[test]
    fn planner_never_exceeds_worker_count() {
        for worker_count in 1..=8 {
            for block_count in 0..=capacity(worker_count) + 3 {
                let batches = plan(block_count, worker_count);
                let planned = planned_block_count(block_count, worker_count);
                // One contiguous chunk per worker, two blocks per worker max.
                assert!(batches.len() <= worker_count);
                assert!(batches.iter().all(|batch| batch.len() <= 2));
                assert!(batches.windows(2).all(|pair| pair[0].end == pair[1].start));
                assert_eq!(batches.last().map_or(0, |batch| batch.end), planned);
                assert_eq!(
                    batches.iter().map(|batch| batch.len()).sum::<usize>(),
                    planned
                );
            }
        }
    }
}
