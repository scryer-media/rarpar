use crate::error::{Par2Error, Result};
use crate::packet::file_desc::normalize_name;
use crate::types::FileId;

/// File ID (16) plus the largest name a File Description packet may carry,
/// as UTF-16 code units.
pub(crate) const MAX_UNICODE_FILENAME_BODY_BYTES: usize = 16 + 2 * 100_000;

/// Parsed Unicode Filename packet.
///
/// An optional packet that spells a file's name in UTF-16 for the file the
/// File Description packet with the same file ID describes. The File
/// Description's own name field carries bytes of no declared encoding, so a
/// producer that writes this packet puts the real spelling here.
#[derive(Debug, Clone)]
pub struct UnicodeFilenamePacket {
    /// The file this name belongs to.
    pub file_id: FileId,
    /// The name, decoded and NFC-normalised.
    pub name: String,
}

impl UnicodeFilenamePacket {
    /// Parse a Unicode Filename packet from its body (after the 64-byte header).
    ///
    /// The name is UTF-16, little-endian unless a byte-order mark says
    /// otherwise; a mark is stripped. NUL padding to the packet's four-byte
    /// alignment is trimmed. A name that is not a whole number of code units,
    /// does not decode, is empty, or carries an interior NUL is refused, and
    /// the File Description's spelling then stands.
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 18 {
            return Err(invalid(format!(
                "body too short: {} bytes, need at least 18",
                body.len()
            )));
        }
        if body.len() > MAX_UNICODE_FILENAME_BODY_BYTES {
            return Err(invalid(format!(
                "filename payload too large: {} bytes",
                body.len()
            )));
        }
        let file_id = FileId::from_bytes(body[0..16].try_into().unwrap());
        let raw = &body[16..];
        if !raw.len().is_multiple_of(2) {
            return Err(invalid(
                "name is not a whole number of UTF-16 code units".into(),
            ));
        }
        let (raw, little_endian) = match raw {
            [0xFF, 0xFE, rest @ ..] => (rest, true),
            [0xFE, 0xFF, rest @ ..] => (rest, false),
            _ => (raw, true),
        };
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| {
                let pair = [pair[0], pair[1]];
                if little_endian {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                }
            })
            .collect();
        let decoded =
            String::from_utf16(&units).map_err(|_| invalid("name is not valid UTF-16".into()))?;
        let name = decoded.trim_end_matches('\0');
        if name.is_empty() {
            return Err(invalid("filename is empty".into()));
        }
        if name.contains('\0') {
            return Err(invalid("filename carries an interior NUL".into()));
        }
        Ok(UnicodeFilenamePacket {
            file_id,
            name: normalize_name(name),
        })
    }
}

fn invalid(reason: String) -> Par2Error {
    Par2Error::InvalidFileDescPacket {
        reason: format!("unicode filename packet: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(file_id: [u8; 16], name: &str) -> Vec<u8> {
        let mut body = file_id.to_vec();
        for unit in name.encode_utf16() {
            body.extend_from_slice(&unit.to_le_bytes());
        }
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        body
    }

    #[test]
    fn parses_a_little_endian_name_and_trims_padding() {
        let packet = UnicodeFilenamePacket::parse(&body([7; 16], "\u{c9}t\u{e9}.mkv")).unwrap();
        assert_eq!(*packet.file_id.as_bytes(), [7; 16]);
        assert_eq!(packet.name, "\u{c9}t\u{e9}.mkv");
    }

    #[test]
    fn honours_and_strips_a_big_endian_byte_order_mark() {
        let mut raw = [7u8; 16].to_vec();
        raw.extend_from_slice(&[0xFE, 0xFF]);
        for unit in "a.mkv".encode_utf16() {
            raw.extend_from_slice(&unit.to_be_bytes());
        }
        let packet = UnicodeFilenamePacket::parse(&raw).unwrap();
        assert_eq!(packet.name, "a.mkv");
    }

    #[test]
    fn normalises_to_nfc() {
        let packet = UnicodeFilenamePacket::parse(&body([7; 16], "E\u{301}t\u{e9}.mkv")).unwrap();
        assert_eq!(packet.name, "\u{c9}t\u{e9}.mkv");
    }

    #[test]
    fn refuses_names_that_do_not_decode() {
        let mut odd = [7u8; 16].to_vec();
        odd.extend_from_slice(&[b'a', 0, b'b']);
        let mut surrogate = [7u8; 16].to_vec();
        surrogate.extend_from_slice(&0xD800u16.to_le_bytes());
        surrogate.extend_from_slice(&[b'a', 0]);
        let mut interior_nul = [7u8; 16].to_vec();
        interior_nul.extend_from_slice(&[b'a', 0, 0, 0, b'b', 0, 0, 0]);
        let empty = [[7u8; 16].as_slice(), &[0, 0, 0, 0]].concat();
        for raw in [odd, surrogate, interior_nul, empty] {
            assert!(
                matches!(
                    UnicodeFilenamePacket::parse(&raw),
                    Err(Par2Error::InvalidFileDescPacket { .. })
                ),
                "{raw:02x?}"
            );
        }
    }
}
