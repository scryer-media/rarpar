//! A bounds-checked cursor over a packet body.
//!
//! Every field read goes through here so that a hostile length or count can only
//! produce a [`Par3Error::MalformedPacket`], never a panic and never an
//! allocation sized from a number the input chose.

use crate::error::{Par3Error, Result};
use crate::hash::Fingerprint;

pub(crate) struct BodyReader<'a> {
    data: &'a [u8],
    pos: usize,
    packet: &'static str,
}

impl<'a> BodyReader<'a> {
    pub(crate) fn new(data: &'a [u8], packet: &'static str) -> Self {
        Self {
            data,
            pos: 0,
            packet,
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn malformed(&self, reason: impl Into<String>) -> Par3Error {
        Par3Error::MalformedPacket {
            packet: self.packet,
            reason: reason.into(),
        }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.remaining() < count {
            return Err(self.malformed(format!(
                "needs {count} more bytes at offset {}, {} left",
                self.pos,
                self.remaining()
            )));
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn i8(&mut self) -> Result<i8> {
        Ok(self.take(1)?[0] as i8)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub(crate) fn fingerprint(&mut self) -> Result<Fingerprint> {
        Ok(self.take(16)?.try_into().expect("16 bytes"))
    }

    /// Read `count` fingerprints, refusing a count the body cannot hold before
    /// any allocation happens.
    pub(crate) fn fingerprints(&mut self, count: u64, what: &str) -> Result<Vec<Fingerprint>> {
        let bytes = count.checked_mul(16).ok_or_else(|| {
            self.malformed(format!("{what} count {count} overflows the body length"))
        })?;
        if bytes > self.remaining() as u64 {
            return Err(self.malformed(format!(
                "{what} count {count} needs {bytes} bytes, {} left",
                self.remaining()
            )));
        }
        // The bound above makes `count` no larger than the remaining body, so
        // this reservation is proportional to real input.
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            out.push(self.fingerprint()?);
        }
        Ok(out)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        slice
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Par3Error::MalformedPacket {
                packet: self.packet,
                reason: format!("{} trailing bytes", self.remaining()),
            })
        }
    }
}

/// Decode a PAR3 name field: UTF-8, not NUL-terminated, and usable as a single
/// path component.
///
/// The reference implementation rewrites unusable names in place and warns; this
/// crate refuses them instead, because it hands the name back to a caller that
/// may well join it onto a base directory.
pub(crate) fn decode_name(bytes: &[u8], packet: &'static str) -> Result<String> {
    let name = std::str::from_utf8(bytes).map_err(|_| Par3Error::MalformedPacket {
        packet,
        reason: "name is not valid UTF-8".to_owned(),
    })?;
    check_name(name)?;
    Ok(name.to_owned())
}

/// Refuse names that would let a set escape the directory it is verified in.
pub(crate) fn check_name(name: &str) -> Result<()> {
    let reason = if name.is_empty() {
        Some("empty")
    } else if name == "." || name == ".." {
        Some("relative path component")
    } else if name.contains('/') {
        Some("contains a path separator")
    } else if name.contains('\\') {
        Some("contains a backslash")
    } else if name.contains('\0') {
        Some("contains a NUL byte")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(Par3Error::UnsafeName {
            name: name.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end_of_the_body() {
        let mut reader = BodyReader::new(&[1, 2, 3], "Test");
        assert_eq!(reader.u16().expect("two bytes"), 0x0201);
        assert!(reader.u32().is_err());
        assert_eq!(reader.remaining(), 1);
    }

    #[test]
    fn a_huge_fingerprint_count_does_not_allocate() {
        let mut reader = BodyReader::new(&[0u8; 32], "Test");
        assert!(reader.fingerprints(u64::MAX, "option").is_err());
        assert!(reader.fingerprints(u64::MAX / 8, "option").is_err());
        assert!(reader.fingerprints(3, "option").is_err());
        assert_eq!(reader.fingerprints(2, "option").expect("two").len(), 2);
    }

    #[test]
    fn trailing_bytes_are_reported() {
        let mut reader = BodyReader::new(&[1, 2, 3], "Test");
        assert_eq!(reader.u16().expect("two bytes"), 0x0201);
        assert!(reader.finish().is_err());
    }

    #[test]
    fn unsafe_names_are_refused() {
        for name in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(check_name(name).is_err(), "{name:?} should be refused");
        }
        for name in ["a.bin", "...", "a:b", " x ", "ファイル"] {
            assert!(check_name(name).is_ok(), "{name:?} should be accepted");
        }
    }

    #[test]
    fn non_utf8_names_are_refused() {
        assert!(decode_name(&[0xff, 0xfe], "File").is_err());
    }
}
