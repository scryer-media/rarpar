//! `PAR COM\0` — a user comment.

use std::borrow::Cow;

/// The Comment packet: free UTF-8 text supplied by whoever created the set.
///
/// As with [`CreatorPacket`](crate::packet::CreatorPacket), the bytes are kept
/// verbatim and decoded lossily on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentPacket {
    bytes: Vec<u8>,
}

impl CommentPacket {
    /// Build a Comment packet body from text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self {
            bytes: text.as_bytes().to_vec(),
        }
    }

    /// Parse a Comment packet body. The whole body is the text.
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

    /// Take the body bytes, leaving nothing behind.
    ///
    /// The text a set carries is made from these, and a set is built from
    /// packets it owns; moving the bytes out means the wire copy and the text
    /// are not both live while the set is resolved.
    #[must_use]
    pub(crate) fn into_body_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the body, without decoding it.
    #[must_use]
    pub(crate) fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_round_trips() {
        let packet = CommentPacket::parse(b"rarpar oracle");
        assert_eq!(packet.text(), "rarpar oracle");
        assert_eq!(packet.to_body_bytes(), b"rarpar oracle");
    }
}
