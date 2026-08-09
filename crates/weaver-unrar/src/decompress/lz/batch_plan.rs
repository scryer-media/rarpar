//! Contiguous work ranges for a bounded worker batch.

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

/// Split the first scheduling round into contiguous, balanced ranges.
///
/// At most two blocks are considered per worker, and at most one range is
/// produced per worker. When fewer blocks are available than workers, each
/// range contains one block.
pub fn plan_batches(block_count: usize, worker_count: usize) -> Vec<Batch> {
    if block_count == 0 || worker_count == 0 {
        return Vec::new();
    }

    let planned_count = block_count.min(capacity(worker_count));
    let batch_size =
        planned_count / worker_count + usize::from(!planned_count.is_multiple_of(worker_count));

    let mut batches = Vec::new();
    let mut start = 0;
    while start < planned_count {
        let end = start.saturating_add(batch_size).min(planned_count);
        batches.push(Batch { start, end });
        start = end;
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(batches: &[Batch]) -> Vec<(usize, usize)> {
        batches
            .iter()
            .map(|batch| (batch.start, batch.end))
            .collect()
    }

    #[test]
    fn empty_input_has_no_batches() {
        assert!(plan_batches(0, 4).is_empty());
    }

    #[test]
    fn one_block_is_represented_as_a_single_block_batch() {
        let batches = plan_batches(1, 4);
        assert_eq!(ranges(&batches), vec![(0, 1)]);
        assert!(batches[0].is_single_block());
        assert_eq!(batches[0].len(), 1);
    }

    #[test]
    fn partial_count_uses_one_block_ranges() {
        let batches = plan_batches(3, 4);
        assert_eq!(ranges(&batches), vec![(0, 1), (1, 2), (2, 3)]);
        assert!(batches.iter().all(|batch| batch.is_single_block()));
    }

    #[test]
    fn exact_worker_count_is_balanced() {
        let batches = plan_batches(4, 4);
        assert_eq!(ranges(&batches), vec![(0, 1), (1, 2), (2, 3), (3, 4)]);
        assert_eq!(batches.len(), 4);
    }

    #[test]
    fn partial_round_is_balanced_without_empty_ranges() {
        let batches = plan_batches(5, 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 5)]);
        assert!(batches.windows(2).all(|pair| pair[0].end == pair[1].start));
        assert!(batches.iter().all(|batch| batch.start < batch.end));
    }

    #[test]
    fn exact_capacity_uses_all_worker_assignments() {
        let batches = plan_batches(capacity(4), 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 6), (6, 8)]);
        assert_eq!(batches.len(), 4);
    }

    #[test]
    fn over_capacity_is_limited_to_two_blocks_per_worker() {
        let batches = plan_batches(capacity(4) + 3, 4);
        assert_eq!(ranges(&batches), vec![(0, 2), (2, 4), (4, 6), (6, 8)]);
        assert_eq!(
            batches.iter().map(|batch| batch.len()).sum::<usize>(),
            capacity(4)
        );
        assert!(batches.len() <= 4);
    }

    #[test]
    fn zero_workers_do_not_create_assignments() {
        assert!(plan_batches(4, 0).is_empty());
        assert_eq!(capacity(0), 0);
    }

    #[test]
    fn planner_never_exceeds_worker_count() {
        for worker_count in 1..=8 {
            for block_count in 0..=capacity(worker_count) + 3 {
                assert!(plan_batches(block_count, worker_count).len() <= worker_count);
            }
        }
    }
}
