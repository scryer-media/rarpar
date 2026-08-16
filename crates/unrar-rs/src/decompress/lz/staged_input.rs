//! Fixed-capacity input staging with a zeroed readable tail.

/// Logical input capacity, in bytes.
pub const LOGICAL_CAPACITY: usize = 4 * 1024 * 1024;

/// Bytes kept readable after the logical input and always maintained as zero.
pub const ZERO_TAIL: usize = 1024;

/// Errors returned when a staged-input operation cannot fit in its current space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedInputError {
    /// The operation requested more bytes than the current append space.
    #[cfg(test)]
    CapacityExceeded { requested: usize, available: usize },
    /// A read was committed beyond the space returned by [`StagedInput::read_space`].
    ReadCommitExceedsSpace { requested: usize, available: usize },
    /// More bytes were consumed than are currently logical input.
    ConsumeExceedsInput { requested: usize, available: usize },
}

/// Reusable staging storage for byte-aligned and bit-oriented input readers.
///
/// The logical input is kept in `backing[start..start + logical_len]`. The
/// bytes immediately after it are zero through the end of the readable tail.
/// Consumed prefix space is reclaimed only by [`Self::compact`].
pub struct StagedInput {
    backing: Box<[u8]>,
    start: usize,
    logical_len: usize,
}

impl StagedInput {
    /// Creates an empty staging buffer with a zeroed logical area and tail.
    pub fn new() -> Self {
        Self {
            backing: vec![0; LOGICAL_CAPACITY + ZERO_TAIL].into_boxed_slice(),
            start: 0,
            logical_len: 0,
        }
    }

    /// Returns the number of committed, unread logical bytes.
    #[inline]
    pub fn logical_len(&self) -> usize {
        self.logical_len
    }

    /// Returns the number of bytes that can currently be appended or read into.
    #[inline]
    pub fn read_space_len(&self) -> usize {
        LOGICAL_CAPACITY - self.start - self.logical_len
    }

    /// Returns only committed unread input, excluding the zero tail.
    #[inline]
    pub fn logical_input(&self) -> &[u8] {
        let end = self.start + self.logical_len;
        &self.backing[self.start..end]
    }

    /// Returns committed unread input followed by the always-zero readable tail.
    #[inline]
    pub fn padded_input(&self) -> &[u8] {
        let end = self.start + self.logical_len + ZERO_TAIL;
        &self.backing[self.start..end]
    }

    /// Appends all of `input` as committed logical input.
    #[cfg(test)]
    pub fn append(&mut self, input: &[u8]) -> Result<(), StagedInputError> {
        if input.len() > self.read_space_len() {
            return Err(StagedInputError::CapacityExceeded {
                requested: input.len(),
                available: self.read_space_len(),
            });
        }

        let begin = self.start + self.logical_len;
        let end = begin + input.len();
        self.backing[begin..end].copy_from_slice(input);
        self.logical_len += input.len();
        self.zero_tail();
        Ok(())
    }

    /// Returns writable space at the end of the logical input.
    ///
    /// Bytes written into this slice become logical input only after
    /// [`Self::commit_read`] is called with their count.
    pub fn read_space(&mut self) -> &mut [u8] {
        let begin = self.start + self.logical_len;
        &mut self.backing[begin..LOGICAL_CAPACITY]
    }

    /// Commits the first `count` bytes from the most recently returned read space.
    pub fn commit_read(&mut self, count: usize) -> Result<(), StagedInputError> {
        let available = self.read_space_len();
        if count > available {
            return Err(StagedInputError::ReadCommitExceedsSpace {
                requested: count,
                available,
            });
        }

        self.logical_len += count;
        self.zero_tail();
        Ok(())
    }

    /// Consumes a prefix of the committed unread logical input.
    pub fn consume_prefix(&mut self, count: usize) -> Result<(), StagedInputError> {
        if count > self.logical_len {
            return Err(StagedInputError::ConsumeExceedsInput {
                requested: count,
                available: self.logical_len,
            });
        }

        self.start += count;
        self.logical_len -= count;
        // `start + logical_len` is unchanged, so the tail range is the same one
        // `commit_read`/`compact` already zeroed. Re-filling it would rewrite
        // ZERO_TAIL bytes per consumed prefix for no observable effect.
        debug_assert!(self.tail_is_zero());
        Ok(())
    }

    /// Drops all staged input and restarts at the beginning of the backing store.
    ///
    /// Used when the same buffer is handed to the next member: only the tail
    /// after the now-empty logical area is re-zeroed, so reuse costs one
    /// `ZERO_TAIL` fill instead of a fresh multi-megabyte allocation.
    pub fn reset(&mut self) {
        self.start = 0;
        self.logical_len = 0;
        self.zero_tail();
    }

    /// Moves unread input to the beginning and reclaims consumed prefix space.
    pub fn compact(&mut self) {
        if self.start != 0 && self.logical_len != 0 {
            self.backing
                .copy_within(self.start..self.start + self.logical_len, 0);
        }
        self.start = 0;
        self.zero_tail();
    }

    fn zero_tail(&mut self) {
        let begin = self.start + self.logical_len;
        self.backing[begin..begin + ZERO_TAIL].fill(0);
    }

    fn tail_is_zero(&self) -> bool {
        let begin = self.start + self.logical_len;
        self.backing[begin..begin + ZERO_TAIL]
            .iter()
            .all(|&byte| byte == 0)
    }
}

impl Default for StagedInput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_tail_survives_append_and_compaction() {
        let mut staged = StagedInput::new();
        staged.append(b"abcdef").unwrap();
        staged.consume_prefix(2).unwrap();

        assert_eq!(staged.logical_input(), b"cdef");
        assert!(
            staged.padded_input()[staged.logical_len()..]
                .iter()
                .all(|&byte| byte == 0)
        );

        staged.compact();

        assert_eq!(staged.logical_input(), b"cdef");
        assert!(
            staged.padded_input()[staged.logical_len()..]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn accepts_full_logical_capacity() {
        let mut staged = StagedInput::new();
        let input = vec![0xA5; LOGICAL_CAPACITY];

        staged.append(&input).unwrap();

        assert_eq!(staged.logical_len(), LOGICAL_CAPACITY);
        assert_eq!(staged.read_space_len(), 0);
        assert_eq!(staged.logical_input(), input.as_slice());
        assert!(
            staged.padded_input()[LOGICAL_CAPACITY..]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(matches!(
            staged.append(&[1]),
            Err(StagedInputError::CapacityExceeded {
                requested: 1,
                available: 0
            })
        ));
    }

    #[test]
    fn partial_prefix_consumption_preserves_unread_input() {
        let mut staged = StagedInput::new();
        staged.append(b"0123456789").unwrap();

        staged.consume_prefix(3).unwrap();

        assert_eq!(staged.logical_len(), 7);
        assert_eq!(staged.logical_input(), b"3456789");
        assert_eq!(staged.read_space_len(), LOGICAL_CAPACITY - 10);
    }

    #[test]
    fn stale_bytes_are_not_exposed_after_consumption_and_reuse() {
        let mut staged = StagedInput::new();
        staged.append(b"old-data").unwrap();
        staged.consume_prefix(4).unwrap();
        staged.compact();

        staged.append(b"new").unwrap();

        assert_eq!(staged.logical_input(), b"datanew");
        assert_eq!(
            &staged.padded_input()[staged.logical_len()..],
            &[0; ZERO_TAIL]
        );
    }

    #[test]
    fn read_space_commits_only_the_requested_prefix() {
        let mut staged = StagedInput::new();
        let space = staged.read_space();
        space[..4].copy_from_slice(b"keep");
        space[4..9].copy_from_slice(b"stale");

        staged.commit_read(4).unwrap();

        assert_eq!(staged.logical_input(), b"keep");
        assert_eq!(
            &staged.padded_input()[staged.logical_len()..],
            &[0; ZERO_TAIL]
        );
    }

    #[test]
    fn reset_restores_full_capacity_without_exposing_previous_input() {
        let mut staged = StagedInput::new();
        staged.append(b"previous-member-input").unwrap();
        staged.consume_prefix(4).unwrap();

        staged.reset();

        assert_eq!(staged.logical_len(), 0);
        assert_eq!(staged.read_space_len(), LOGICAL_CAPACITY);
        assert!(staged.logical_input().is_empty());
        assert_eq!(staged.padded_input(), &[0; ZERO_TAIL]);

        staged.append(b"next").unwrap();

        assert_eq!(staged.logical_input(), b"next");
        assert_eq!(
            &staged.padded_input()[staged.logical_len()..],
            &[0; ZERO_TAIL]
        );
    }

    #[test]
    fn compaction_reclaims_consumed_prefix_capacity() {
        let mut staged = StagedInput::new();
        staged.append(b"prefix-data").unwrap();
        staged.consume_prefix(7).unwrap();

        assert_eq!(staged.read_space_len(), LOGICAL_CAPACITY - 11);

        staged.compact();

        assert_eq!(staged.logical_input(), b"data");
        assert_eq!(staged.read_space_len(), LOGICAL_CAPACITY - 4);
    }
}
