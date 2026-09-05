//! `PAR CRE\0` — the client-identification packet.

use std::borrow::Cow;

/// The Creator packet: UTF-8 text naming the client that wrote the set.
///
/// Every PAR3 file must contain one. The specification requires a client that
/// cannot process a set to surface this text, so [`Par3Set`](crate::set::Par3Set)
/// carries it through rather than discarding it.
///
/// The bytes are retained exactly as written. Nothing guarantees a producer wrote
/// valid UTF-8, so the text is decoded lossily on demand instead of at parse
/// time — a mis-encoded creator string must not cost a caller the rest of the
/// set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatorPacket {
    bytes: Vec<u8>,
}

impl CreatorPacket {
    /// Build a Creator packet body from text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self {
            bytes: text.as_bytes().to_vec(),
        }
    }

    /// Parse a Creator packet body. The whole body is the text.
    #[must_use]
    pub fn parse(body: &[u8]) -> Self {
        Self {
            bytes: body.to_vec(),
        }
    }

    /// The raw body bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The text, with any invalid UTF-8 replaced by `U+FFFD`.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_round_trips_including_invalid_utf8() {
        let body = b"par3cmdline version 0.0.1\n\xff";
        let packet = CreatorPacket::parse(body);
        assert_eq!(packet.to_body_bytes(), body);
        assert!(packet.text().starts_with("par3cmdline version 0.0.1"));
        assert!(packet.text().ends_with('\u{fffd}'));
    }

    #[test]
    fn an_empty_body_is_legal() {
        let packet = CreatorPacket::parse(b"");
        assert_eq!(packet.text(), "");
        assert!(packet.to_body_bytes().is_empty());
    }
}
