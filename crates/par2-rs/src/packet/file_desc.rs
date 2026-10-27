use crate::error::{Par2Error, Result};
use crate::path::translate_par2_name_to_relative;
use crate::types::FileId;

const FIXED_BODY_SIZE: usize = 56;
const MAX_FILENAME_BYTES: usize = 100_000;

/// Parsed File Description packet.
#[derive(Debug, Clone)]
pub struct FileDescriptionPacket {
    /// MD5-based file identifier: MD5(hash_16k || length || name).
    pub file_id: FileId,
    /// MD5 of the entire file.
    pub hash_full: [u8; 16],
    /// MD5 of the first 16,384 bytes of the file.
    pub hash_16k: [u8; 16],
    /// File length in bytes.
    pub file_length: u64,
    /// Filesystem-safe relative path translated from [`Self::par2_name`].
    pub filename: String,
    /// The PAR2 filename decoded by [`decode_par2_name`], before
    /// filesystem-safe translation.
    pub par2_name: String,
    /// The name bytes exactly as the packet carried them, up to the first NUL.
    /// The file ID hashes these bytes, so they are the form to match on.
    pub par2_name_bytes: Vec<u8>,
}

/// Decode a PAR2 name field into text.
///
/// The field declares no encoding. Bytes that are valid UTF-8 are read as
/// UTF-8; anything else is read as ISO-8859-1, which maps every byte to a
/// character, so a name written in a Windows code page keeps one character per
/// byte instead of collapsing into replacement characters. The text is not
/// Unicode-normalised: filesystems such as ext4 treat composed and decomposed
/// spellings as different names, so the decoded spelling is the one to look
/// up on disk.
pub fn decode_par2_name(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|&byte| char::from(byte)).collect(),
    }
}

impl FileDescriptionPacket {
    /// Parse a File Description packet from its body (after the 64-byte header).
    pub fn parse(body: &[u8]) -> Result<Self> {
        // Minimum body: 16 (file_id) + 16 (hash_full) + 16 (hash_16k) + 8 (length) = 56
        // plus at least one filename byte.
        if body.len() <= FIXED_BODY_SIZE {
            return Err(Par2Error::InvalidFileDescPacket {
                reason: format!(
                    "body too short: {} bytes, need more than {FIXED_BODY_SIZE}",
                    body.len()
                ),
            });
        }

        let file_id = FileId::from_bytes(body[0..16].try_into().unwrap());
        let hash_full: [u8; 16] = body[16..32].try_into().unwrap();
        let hash_16k: [u8; 16] = body[32..48].try_into().unwrap();
        let file_length = u64::from_le_bytes(body[48..56].try_into().unwrap());
        if file_length <= 16_384 && hash_16k != hash_full {
            return Err(Par2Error::InvalidFileDescPacket {
                reason: "hash_16k must match hash_full for files <= 16KiB".to_string(),
            });
        }

        // Filename: everything after offset 56, strip null padding
        let name_bytes = &body[56..];
        if name_bytes.len() > MAX_FILENAME_BYTES {
            return Err(Par2Error::InvalidFileDescPacket {
                reason: format!("filename payload too large: {} bytes", name_bytes.len()),
            });
        }
        let name_end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        if name_end == 0 {
            return Err(Par2Error::InvalidFileDescPacket {
                reason: "filename is empty".to_string(),
            });
        }
        let par2_name_bytes = name_bytes[..name_end].to_vec();
        let par2_name = decode_par2_name(&par2_name_bytes);
        let filename = translate_par2_name_to_relative(&par2_name)?;

        Ok(FileDescriptionPacket {
            file_id,
            hash_full,
            hash_16k,
            file_length,
            filename,
            par2_name,
            par2_name_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_desc_body(
        file_id: [u8; 16],
        hash_full: [u8; 16],
        hash_16k: [u8; 16],
        file_length: u64,
        filename: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&file_id);
        body.extend_from_slice(&hash_full);
        body.extend_from_slice(&hash_16k);
        body.extend_from_slice(&file_length.to_le_bytes());
        body.extend_from_slice(filename);
        body
    }

    #[test]
    fn parse_valid_file_desc() {
        let fid = [0x11u8; 16];
        let hf = [0x22u8; 16];
        let h16 = [0x33u8; 16];
        let body = make_file_desc_body(fid, hf, h16, 102400, b"testfile.bin\x00\x00\x00\x00");

        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(*pkt.file_id.as_bytes(), fid);
        assert_eq!(pkt.hash_full, hf);
        assert_eq!(pkt.hash_16k, h16);
        assert_eq!(pkt.file_length, 102400);
        assert_eq!(pkt.filename, "testfile.bin");
    }

    #[test]
    fn parse_filename_no_null() {
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 0, b"noterm");
        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(pkt.filename, "noterm");
    }

    #[test]
    fn reject_empty_filename() {
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 0, b"\x00\x00\x00\x00");
        let err = FileDescriptionPacket::parse(&body).unwrap_err();
        assert!(matches!(err, Par2Error::InvalidFileDescPacket { .. }));
    }

    #[test]
    fn reject_too_short() {
        let body = [0u8; 40];
        let err = FileDescriptionPacket::parse(&body).unwrap_err();
        assert!(matches!(err, Par2Error::InvalidFileDescPacket { .. }));
    }

    #[test]
    fn reject_body_without_filename() {
        // Exactly 56 bytes: no filename at all
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 42, b"");
        let err = FileDescriptionPacket::parse(&body).unwrap_err();
        assert!(matches!(err, Par2Error::InvalidFileDescPacket { .. }));
    }

    #[test]
    fn translates_par2_paths_without_flattening() {
        assert_eq!(
            translate_par2_name_to_relative("../../etc/passwd").unwrap(),
            "%2E%2E/%2E%2E/etc/passwd"
        );
        assert_eq!(
            translate_par2_name_to_relative("/etc/passwd").unwrap(),
            "%2F/etc/passwd"
        );
        assert_eq!(
            translate_par2_name_to_relative("subdir/file.bin").unwrap(),
            "subdir/file.bin"
        );
        assert_eq!(
            translate_par2_name_to_relative("C:\\Users\\evil\\file.exe").unwrap(),
            format!(
                "C{}Users/evil/file.exe",
                if cfg!(windows) { "%3A/" } else { ":/" }
            )
        );
        assert_eq!(
            translate_par2_name_to_relative("normal.par2").unwrap(),
            "normal.par2"
        );
    }

    #[test]
    fn a_cp1252_name_decodes_as_iso_8859_1() {
        // "Été.mkv" in Windows-1252: 0xC9 and 0xE9 are not valid UTF-8 here.
        let raw = b"\xC9t\xE9.mkv";
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 0, raw);
        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(pkt.par2_name, "\u{c9}t\u{e9}.mkv");
        assert_eq!(pkt.filename, "\u{c9}t\u{e9}.mkv");
        assert!(!pkt.par2_name.contains('\u{fffd}'));
        assert_eq!(pkt.par2_name_bytes, raw);
    }

    #[test]
    fn a_valid_utf8_name_is_unchanged() {
        let name = "Bj\u{f6}rk \u{2013} \u{65e5}\u{672c}.mkv";
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 0, name.as_bytes());
        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(pkt.par2_name, name);
        assert_eq!(pkt.par2_name_bytes, name.as_bytes());
    }

    #[test]
    fn an_nfd_utf8_name_keeps_its_spelling() {
        // "Été.mkv" decomposed: E + U+0301, e + U+0301. On ext4 this and the
        // composed spelling are different files, so the name must not change.
        let nfd = "E\u{301}te\u{301}.mkv";
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 0, nfd.as_bytes());
        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(pkt.par2_name, nfd);
        assert_eq!(pkt.filename, nfd);
        assert_eq!(pkt.par2_name_bytes, nfd.as_bytes());
    }

    #[test]
    fn parse_path_traversal_filename() {
        let body = make_file_desc_body([0; 16], [0; 16], [0; 16], 100, b"../../etc/passwd\x00");
        let pkt = FileDescriptionPacket::parse(&body).unwrap();
        assert_eq!(pkt.par2_name, "../../etc/passwd");
        assert_eq!(pkt.filename, "%2E%2E/%2E%2E/etc/passwd");
    }
}
