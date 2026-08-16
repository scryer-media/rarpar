//! `cargo xtask test-corpus`: the signed, content-addressed test corpus.
//!
//! The binary fixtures under `crates/*/tests/fixtures/` are published to R2 as
//! per-file objects addressed by BLAKE3, described by a canonical manifest
//! that is a pure function of the checked-in ledger (`test-corpus/sources.json`),
//! the profile table (`test-corpus/profiles.json`) and the shared toolchain lock.
//! `test-corpus/lock.json` pins the one manifest a checkout hydrates from.
//!
//! See `docs/test-corpus.md` for the contract. Nothing here implements crypto:
//! digests come from `blake3`, transport from `curl`, signatures from `cosign`.

mod bench_pins;
mod checked_in;
mod commands;
mod curl;
mod generate;
mod glob;
mod ledger;
mod lock;
mod manifest;
mod profiles;
mod sigstore;
mod upstream;

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(crate) use commands::run;

pub(crate) const LEDGER_FILE: &str = "test-corpus/sources.json";
pub(crate) const PROFILES_FILE: &str = "test-corpus/profiles.json";
pub(crate) const LOCK_FILE: &str = "test-corpus/lock.json";
pub(crate) const TOOLCHAINS_FILE: &str = "bench/rarpar-bench/config/toolchains.json";

/// Object key prefixes in the bucket. Content-addressed, never rewritten.
pub(crate) const OBJECTS_PREFIX: &str = "test-corpus/objects/blake3/";
pub(crate) const MANIFESTS_PREFIX: &str = "test-corpus/manifests/blake3/";

/// The Git LFS pointer preamble. Bytes that start with this are not fixture
/// bytes, and every command here treats them as an error, never as content.
///
/// SHA-256 by specification: the pointer's `oid sha256:` line is the Git LFS
/// v1 pointer format, not a digest this tool chooses. Only the preamble is
/// matched here, so nothing downstream depends on the oid's algorithm.
const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/v1";

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) fn error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::other(message.into()))
}

pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(error(message))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// A 32-byte BLAKE3 digest in lowercase hex, which is the one digest form the
/// corpus records: ledger entries, manifest entries, object keys and lock pins.
pub(crate) fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn blake3_bytes(bytes: &[u8]) -> String {
    hex(blake3::hash(bytes).as_bytes())
}

/// Digest and size of a file, plus whether it is a Git LFS pointer rather than
/// content. Streams so the 100 MiB fixtures never sit in memory twice.
pub(crate) struct FileDigest {
    pub(crate) blake3: String,
    pub(crate) size: u64,
    pub(crate) lfs_pointer: bool,
}

pub(crate) fn digest_file(path: &Path) -> Result<FileDigest> {
    let mut file = fs::File::open(path)
        .map_err(|source| error(format!("open {}: {source}", path.display())))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut size = 0u64;
    let mut head: Vec<u8> = Vec::with_capacity(LFS_POINTER_PREFIX.len());
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| error(format!("read {}: {source}", path.display())))?;
        if read == 0 {
            break;
        }
        if head.len() < LFS_POINTER_PREFIX.len() {
            let take = (LFS_POINTER_PREFIX.len() - head.len()).min(read);
            head.extend_from_slice(&buffer[..take]);
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok(FileDigest {
        blake3: hex(hasher.finalize().as_bytes()),
        size,
        lfs_pointer: head.starts_with(LFS_POINTER_PREFIX),
    })
}

/// A repository-relative path, always `/`-separated. Ledger paths, profile
/// globs and manifest entries all use this form regardless of host OS.
pub(crate) fn repo_path(root: &Path, relative: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in relative.split('/') {
        path.push(component);
    }
    path
}

pub(crate) fn valid_repo_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains("//")
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub(crate) fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| error(format!("read {}: {source}", path.display())))
}

pub(crate) fn next_string(
    iter: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<String> {
    iter.next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| error(format!("{option} requires a UTF-8 value")))
}

pub(crate) fn next_path(
    iter: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<PathBuf> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| error(format!("{option} requires a value")))
}

/// Write `bytes` to `path` through a sibling temp file and an atomic rename, so
/// a fixture is either fully present with the verified bytes or absent.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(parent)?;
    let temp = temp_sibling(path);
    fs::write(&temp, bytes)
        .map_err(|source| error(format!("write {}: {source}", temp.display())))?;
    rename_into_place(&temp, path)
}

pub(crate) fn temp_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fixture");
    path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

pub(crate) fn rename_into_place(temp: &Path, path: &Path) -> Result<()> {
    if let Err(source) = fs::rename(temp, path) {
        // Windows refuses to rename over an existing read-only or open file;
        // remove the stale destination once and retry before giving up.
        if path.exists() {
            let _ = fs::remove_file(path);
            fs::rename(temp, path).map_err(|retry| {
                let _ = fs::remove_file(temp);
                error(format!(
                    "rename {} -> {}: {source}; retry: {retry}",
                    temp.display(),
                    path.display()
                ))
            })?;
            return Ok(());
        }
        let _ = fs::remove_file(temp);
        return fail(format!(
            "rename {} -> {}: {source}",
            temp.display(),
            path.display()
        ));
    }
    Ok(())
}

/// UTC timestamp in RFC 3339 form without pulling in a calendar crate; used
/// only for human-facing provenance fields, never for anything hashed.
pub(crate) fn utc_now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), proleptic Gregorian.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_digest_agree_with_known_answers() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        // The BLAKE3 reference vectors for the empty input and "abc".
        assert_eq!(
            blake3_bytes(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_bytes(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert!(is_blake3_hex(&blake3_bytes(b"abc")));
        assert!(!is_blake3_hex(
            "6437B3AC38465133FFB63B75273A8DB548C558465D79DB03FD359C6CD5BD9D85"
        ));
        assert!(!is_blake3_hex("abc"));
    }

    #[test]
    fn digest_file_streams_and_detects_lfs_pointers() {
        let dir = std::env::temp_dir().join(format!("xtask-corpus-digest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let content = dir.join("content.bin");
        fs::write(&content, b"abc").unwrap();
        let digest = digest_file(&content).unwrap();
        assert_eq!(digest.size, 3);
        assert_eq!(
            digest.blake3,
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert!(!digest.lfs_pointer);

        let pointer = dir.join("pointer.rar");
        fs::write(
            &pointer,
            b"version https://git-lfs.github.com/spec/v1\noid sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nsize 3\n",
        )
        .unwrap();
        assert!(digest_file(&pointer).unwrap().lfs_pointer);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn repo_relative_paths_are_strict() {
        for good in [
            "a",
            "a/b.rar",
            "crates/unrar-rs/tests/fixtures/rar5/x.part01.rar",
        ] {
            assert!(valid_repo_relative(good), "{good}");
        }
        for bad in ["", "/a", "a//b", "a/../b", "./a", "a\\b", "a/"] {
            assert!(!valid_repo_relative(bad), "{bad}");
        }
    }

    #[test]
    fn utc_timestamp_has_rfc3339_shape() {
        let stamp = utc_now_rfc3339();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
        assert!(stamp.starts_with("20"), "{stamp}");
    }

    #[test]
    fn write_atomic_replaces_existing_content() {
        let dir = std::env::temp_dir().join(format!("xtask-corpus-atomic-{}", std::process::id()));
        let path = dir.join("nested").join("fixture.rar");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(
            fs::read_dir(dir.join("nested")).unwrap().count() == 1,
            "temp file left behind"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
