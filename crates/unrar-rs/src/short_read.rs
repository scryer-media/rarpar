//! How a header walk over an incomplete volume image says where it stopped.
//!
//! Two kinds of caller walk a volume's headers. One is about to decode from
//! them and needs the whole volume; for it, a stream that runs out under a
//! header is a damaged archive. The other only reports what the headers say,
//! and is handed a volume that is still arriving: for it the same event is
//! the expected stopping point, and the useful answer is *where* — the first
//! offset the image has to reach before another walk can get further.
//!
//! [`HeaderScan`] tells a walk which caller it serves; [`ShortRead`] is what
//! the second kind gets back, carrying the error the first kind would have
//! raised so that a strict parse over the same bytes still fails exactly as
//! it always has.

use std::io::Seek;

use crate::error::{RarError, RarResult};

/// What the headers a walk produces are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderScan {
    /// The headers feed the decoder. The volume must be whole: a reader with
    /// no known length is refused, a cut inside a header is an error, and a
    /// member declaring more packed bytes than the volume holds is corruption.
    ForDecode,
    /// The headers are reported, never decoded from. A volume still arriving
    /// is the expected input: the walk stops where the image ends, records a
    /// [`ShortRead`], and returns what it reached.
    ForFacts,
    /// Strict physical walk ending immediately after this many file headers.
    /// Payload reads remain the decoder's responsibility, through a reader
    /// that waits for missing bytes rather than reporting temporary EOF.
    ThroughFile(std::num::NonZeroUsize),
}

impl HeaderScan {
    pub(crate) fn reached_file_limit(self, files: usize) -> bool {
        matches!(self, Self::ThroughFile(limit) if files >= limit.get())
    }
}

/// Where a facts walk ran out of image, and what a decode-bound parse of the
/// same bytes would have raised there.
#[derive(Debug)]
pub(crate) struct ShortRead {
    /// The first offset the walk could not read: a lower bound on what the
    /// image must cover before another walk can make progress.
    pub(crate) at: u64,
    /// The error a [`HeaderScan::ForDecode`] parse raises for the same image.
    /// `None` when the image ended cleanly at a header boundary, which no
    /// parse has ever treated as an error.
    pub(crate) strict_error: Option<RarError>,
}

impl ShortRead {
    /// The image ended exactly between two headers.
    pub(crate) fn at_boundary(at: u64) -> Self {
        Self {
            at,
            strict_error: None,
        }
    }

    /// The image ended inside a header or a member's data area; `strict_error`
    /// is what a decode-bound parse says about that.
    pub(crate) fn truncated(at: u64, strict_error: RarError) -> Self {
        Self {
            at,
            strict_error: Some(strict_error),
        }
    }
}

/// Whether `error` is the reader running dry rather than the archive being
/// wrong. Only meaningful for an error raised by a *stream read*: the header
/// parsers raise [`RarError::TruncatedHeader`] for a fully read header whose
/// fields overrun its declared size too, and that is corruption.
pub(crate) fn is_short_read(error: &RarError) -> bool {
    match error {
        RarError::TruncatedHeader { .. } => true,
        RarError::Io(io) => io.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

/// The least an image must grow to before a read that just ran dry could
/// learn anything: one byte past where the reader stopped, or `floor` when
/// that is further along. Either is a lower bound — the reader stopped because
/// the byte at its position was missing.
pub(crate) fn next_needed<R: Seek>(reader: &mut R, floor: u64) -> u64 {
    match reader.stream_position() {
        Ok(position) => floor.max(position.saturating_add(1)),
        Err(_) => floor,
    }
}

/// Under [`HeaderScan::ForFacts`], turn a stream read that ran dry into a
/// recorded [`ShortRead`] and hand back `None` so the walk can stop; under
/// [`HeaderScan::ForDecode`], or for any other error, pass the error through.
///
/// `floor` is the least the next header could occupy from the offset the read
/// started at; see [`next_needed`].
pub(crate) fn absorb_short_read<R: Seek, T>(
    result: RarResult<T>,
    scan: HeaderScan,
    reader: &mut R,
    floor: u64,
    short: &mut Option<ShortRead>,
) -> RarResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if scan == HeaderScan::ForFacts && is_short_read(&error) => {
            *short = Some(ShortRead::truncated(next_needed(reader, floor), error));
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_dry_read_is_absorbed_only_for_a_facts_walk() {
        let mut reader = Cursor::new(vec![0u8; 10]);
        reader.set_position(10);
        let dry: RarResult<()> = Err(RarError::TruncatedHeader { offset: 4 });

        let mut short = None;
        let passed = absorb_short_read(dry, HeaderScan::ForFacts, &mut reader, 4 + 6, &mut short)
            .expect("a facts walk absorbs a dry read");
        assert!(passed.is_none());
        let short = short.expect("and records where it ran out");
        assert_eq!(short.at, 11, "one byte past where the reader stopped");
        assert!(matches!(
            short.strict_error,
            Some(RarError::TruncatedHeader { offset: 4 })
        ));

        let mut short = None;
        let dry: RarResult<()> = Err(RarError::TruncatedHeader { offset: 4 });
        let err = absorb_short_read(dry, HeaderScan::ForDecode, &mut reader, 10, &mut short)
            .expect_err("a decode-bound parse keeps the error");
        assert!(matches!(err, RarError::TruncatedHeader { offset: 4 }));
        assert!(short.is_none());
    }

    #[test]
    fn corruption_is_never_a_short_read() {
        let mut reader = Cursor::new(vec![0u8; 10]);
        let mut short = None;
        let corrupt: RarResult<()> = Err(RarError::CorruptArchive {
            detail: "bad".into(),
        });
        assert!(
            absorb_short_read(corrupt, HeaderScan::ForFacts, &mut reader, 0, &mut short).is_err()
        );
        assert!(short.is_none());
        assert!(!is_short_read(&RarError::InvalidSignature));
        assert!(is_short_read(&RarError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof
        ))));
        assert!(!is_short_read(&RarError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        ))));
    }

    #[test]
    fn the_floor_wins_when_the_reader_stopped_before_it() {
        let mut reader = Cursor::new(vec![0u8; 10]);
        reader.set_position(3);
        assert_eq!(next_needed(&mut reader, 9), 9);
        reader.set_position(20);
        assert_eq!(next_needed(&mut reader, 9), 21);
    }
}
