use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use bytes::Bytes;

use crate::checksum::Md5State;
use crate::error::{Par2Error, Result};
use crate::evidence::FileStatFingerprint;
use crate::types::{CancellationToken, RecoveryExponent};

#[derive(Debug, Clone)]
pub enum RecoverySliceData {
    InMemory(Bytes),
    FileBacked {
        /// Shared rather than owned: one PAR2 volume can hold tens of thousands
        /// of recovery packets, and every one of them names the same file. An
        /// `Arc<Path>` lets the scanner intern the path once per volume instead
        /// of allocating a `PathBuf` per packet.
        path: Arc<Path>,
        offset: u64,
        len: usize,
        /// Packet MD5 from the header, kept so lazily-loaded payloads can be
        /// re-validated against on-disk damage before repair uses them.
        /// `None` means the payload was already validated (or is synthetic).
        packet_hash: Option<[u8; 16]>,
    },
}

/// Scanner authentications of file-backed payloads, keyed by the interned
/// volume path allocation.
///
/// The bounded file scanner hashes every recovery payload as it reads it and,
/// when the volume's stat has settled, records the fingerprint the volume had
/// when it was opened. While the path still fingerprints identically,
/// [`RecoverySliceData::validate_packet_hash`] accepts that authentication
/// instead of reading and hashing the payload again.
///
/// The record lives here rather than in [`RecoverySliceData::FileBacked`] so
/// that variant keeps exactly its public fields. Every payload of one scan
/// shares one `Arc<Path>`, and clones of a payload share it too, so the
/// allocation's address names the scan. The entry holds a `Weak` to that
/// allocation, which keeps the address from being reused while the entry
/// exists; entries whose payloads are all gone are pruned when the next scan
/// registers. A span is vouched for only when its offset, length and packet
/// hash are the ones the scan authenticated, so a payload built by hand over
/// the scanner's path is read and hashed like any other.
struct ScanAuthentication {
    path: Weak<Path>,
    fingerprint: FileStatFingerprint,
    spans: HashMap<u64, (usize, [u8; 16])>,
}

static SCAN_AUTHENTICATIONS: Mutex<Option<HashMap<usize, ScanAuthentication>>> = Mutex::new(None);

fn interned_path_key(path: &Arc<Path>) -> usize {
    Arc::as_ptr(path).cast::<u8>() as usize
}

fn record_scan_authentication(
    path: &Arc<Path>,
    offset: u64,
    len: usize,
    packet_hash: [u8; 16],
    fingerprint: FileStatFingerprint,
) {
    let mut table = SCAN_AUTHENTICATIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let table = table.get_or_insert_with(HashMap::new);
    let key = interned_path_key(path);
    if !table.contains_key(&key) {
        table.retain(|_, entry| entry.path.strong_count() > 0);
    }
    let entry = table.entry(key).or_insert_with(|| ScanAuthentication {
        path: Arc::downgrade(path),
        fingerprint: fingerprint.clone(),
        spans: HashMap::new(),
    });
    // One allocation is one scan, and one scan records one fingerprint.
    debug_assert_eq!(entry.fingerprint, fingerprint);
    entry.spans.insert(offset, (len, packet_hash));
}

pub(super) fn scan_authentication(
    path: &Arc<Path>,
    offset: u64,
    len: usize,
    packet_hash: &[u8; 16],
) -> Option<FileStatFingerprint> {
    let table = SCAN_AUTHENTICATIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let entry = table.as_ref()?.get(&interned_path_key(path))?;
    debug_assert!(std::ptr::addr_eq(entry.path.as_ptr(), Arc::as_ptr(path)));
    (entry.spans.get(&offset) == Some(&(len, *packet_hash))).then(|| entry.fingerprint.clone())
}

impl RecoverySliceData {
    pub fn in_memory(data: Bytes) -> Self {
        Self::InMemory(data)
    }

    pub fn file_backed(path: PathBuf, offset: u64, len: usize) -> Self {
        Self::file_backed_shared(Arc::from(path), offset, len, None)
    }

    pub fn file_backed_with_hash(
        path: PathBuf,
        offset: u64,
        len: usize,
        packet_hash: [u8; 16],
    ) -> Self {
        Self::file_backed_shared(Arc::from(path), offset, len, Some(packet_hash))
    }

    /// Build a file-backed slice over an already-interned path.
    pub fn file_backed_shared(
        path: Arc<Path>,
        offset: u64,
        len: usize,
        packet_hash: Option<[u8; 16]>,
    ) -> Self {
        Self::FileBacked {
            path,
            offset,
            len,
            packet_hash,
        }
    }

    /// A file-backed slice whose payload the scanner has just authenticated
    /// against `packet_hash`, with the volume fingerprinted as it was opened.
    ///
    /// The fingerprint is taken before any byte is read, so a write that
    /// lands during or after the scan moves it and sends validation back to
    /// the bytes.
    pub(crate) fn file_backed_authenticated(
        path: Arc<Path>,
        offset: u64,
        len: usize,
        packet_hash: [u8; 16],
        fingerprint: FileStatFingerprint,
    ) -> Self {
        record_scan_authentication(&path, offset, len, packet_hash, fingerprint);
        Self::FileBacked {
            path,
            offset,
            len,
            packet_hash: Some(packet_hash),
        }
    }

    /// Re-check the PAR2 packet hash covering this recovery slice.
    ///
    /// In-memory payloads were hash-validated when the packet was parsed, and
    /// file-backed payloads recorded without a hash are trusted as-is.
    /// Other file-backed payloads are re-hashed from disk here: the packet
    /// hash covers `recovery_set_id || type || exponent || payload`.
    ///
    /// The bounded file scanner authenticates every recovery payload as it
    /// reads it and records the volume's stat fingerprint (length, mtime and,
    /// on Unix, device and inode). A payload whose volume still fingerprints
    /// identically keeps that verdict without being read again; one whose
    /// volume changed, vanished or stopped being a regular file is read and
    /// hashed as before. What the fingerprint cannot see — a same-length
    /// in-place rewrite that also restores the mtime — is left to the
    /// verification of the repaired files that follows every repair.
    pub fn validate_packet_hash(
        &self,
        recovery_set_id: &[u8; 16],
        exponent: RecoveryExponent,
    ) -> io::Result<bool> {
        self.validate_packet_hash_inner(recovery_set_id, exponent, None)
            .map_err(|error| match error {
                Par2Error::Io(error) => error,
                Par2Error::Cancelled => io::Error::new(
                    io::ErrorKind::Interrupted,
                    "recovery packet hash validation was cancelled",
                ),
                error => io::Error::other(error.to_string()),
            })
    }

    pub(crate) fn validate_packet_hash_cancellable(
        &self,
        recovery_set_id: &[u8; 16],
        exponent: RecoveryExponent,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.validate_packet_hash_inner(recovery_set_id, exponent, Some(cancellation))
    }

    fn validate_packet_hash_inner(
        &self,
        recovery_set_id: &[u8; 16],
        exponent: RecoveryExponent,
        cancellation: Option<&CancellationToken>,
    ) -> Result<bool> {
        let Self::FileBacked {
            path,
            offset,
            len,
            packet_hash: Some(expected),
        } = self
        else {
            return Ok(true);
        };
        if let Some(authenticated_at) = scan_authentication(path, *offset, *len, expected)
            && FileStatFingerprint::capture_path(path).as_ref() == Some(&authenticated_at)
        {
            return Ok(true);
        }

        let mut hasher = Md5State::new();
        hasher.update(recovery_set_id);
        hasher.update(super::header::TYPE_RECOVERY);
        hasher.update(&exponent.to_le_bytes());

        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(*offset))?;
        let mut remaining = *len;
        let mut buf = vec![0u8; remaining.clamp(1, 256 * 1024)];
        while remaining > 0 {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(Par2Error::Cancelled);
            }
            let take = remaining.min(buf.len());
            file.read_exact(&mut buf[..take]).map_err(Par2Error::Io)?;
            hasher.update(&buf[..take]);
            remaining -= take;
        }
        let file_len = file
            .metadata()
            .ok()
            .map_or(*offset + *len as u64, |metadata| metadata.len());
        crate::file_cache::drop_touched_file_cache(
            &file,
            path.as_ref(),
            file_len,
            *offset,
            *len as u64,
        );
        Ok(hasher.finalize() == *expected)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::InMemory(data) => data.len(),
            Self::FileBacked { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::InMemory(data) => Some(data.as_ref()),
            Self::FileBacked { .. } => None,
        }
    }

    pub fn file_span(&self) -> Option<(&Path, u64, usize)> {
        match self {
            Self::InMemory(_) => None,
            Self::FileBacked {
                path, offset, len, ..
            } => Some((path.as_ref(), *offset, *len)),
        }
    }

    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; self.len()];
        self.read_range_padded(0, &mut out)?;
        Ok(out)
    }

    pub fn read_range_padded(&self, start: usize, dst: &mut [u8]) -> io::Result<()> {
        dst.fill(0);

        match self {
            Self::InMemory(data) => {
                if start >= data.len() {
                    return Ok(());
                }
                let end = (start + dst.len()).min(data.len());
                let copy_len = end - start;
                dst[..copy_len].copy_from_slice(&data[start..end]);
                Ok(())
            }
            Self::FileBacked {
                path, offset, len, ..
            } => {
                if start >= *len {
                    return Ok(());
                }

                let read_len = dst.len().min(*len - start);
                let mut file = File::open(path)?;
                read_exact_at_fallback(&mut file, offset + start as u64, &mut dst[..read_len])?;
                let file_len = file
                    .metadata()
                    .ok()
                    .map_or(*len as u64, |metadata| metadata.len());
                crate::file_cache::drop_touched_file_cache(
                    &file,
                    path.as_ref(),
                    file_len,
                    offset + start as u64,
                    read_len as u64,
                );
                Ok(())
            }
        }
    }
}

impl From<Bytes> for RecoverySliceData {
    fn from(value: Bytes) -> Self {
        Self::InMemory(value)
    }
}

impl From<Vec<u8>> for RecoverySliceData {
    fn from(value: Vec<u8>) -> Self {
        Self::InMemory(Bytes::from(value))
    }
}

fn read_exact_at_fallback(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}

/// Parsed Recovery Slice packet.
///
/// Contains one recovery block identified by its exponent.
/// The actual Reed-Solomon math is not performed here; we just store the data.
#[derive(Debug, Clone)]
pub struct RecoverySlicePacket {
    /// The exponent identifying this recovery block.
    pub exponent: RecoveryExponent,
    /// The recovery data (length should equal slice_size from the Main packet).
    pub data: RecoverySliceData,
}

impl RecoverySlicePacket {
    /// Parse a Recovery Slice packet from its body (after the 64-byte header).
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() <= 4 {
            return Err(Par2Error::InvalidRecoveryPacket {
                reason: format!("body too short: {} bytes, need more than 4", body.len()),
            });
        }

        let exponent = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let data = RecoverySliceData::in_memory(Bytes::copy_from_slice(&body[4..]));

        Ok(RecoverySlicePacket { exponent, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_recovery() {
        let mut body = Vec::new();
        body.extend_from_slice(&42u32.to_le_bytes());
        body.extend_from_slice(&[0xAB; 128]);

        let pkt = RecoverySlicePacket::parse(&body).unwrap();
        assert_eq!(pkt.exponent, 42);
        assert_eq!(pkt.data.len(), 128);
        assert!(pkt.data.as_bytes().unwrap().iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn reject_recovery_empty_data() {
        let body = 0u32.to_le_bytes();
        let err = RecoverySlicePacket::parse(&body).unwrap_err();
        assert!(matches!(err, Par2Error::InvalidRecoveryPacket { .. }));
    }

    #[test]
    fn reject_too_short() {
        let body = [0u8; 2];
        let err = RecoverySlicePacket::parse(&body).unwrap_err();
        assert!(matches!(err, Par2Error::InvalidRecoveryPacket { .. }));
    }

    #[test]
    fn file_backed_hash_validation_honors_cancellation() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![0xA5; 512 * 1024]).unwrap();
        let data = RecoverySliceData::file_backed_with_hash(
            file.path().to_path_buf(),
            0,
            512 * 1024,
            [0; 16],
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = data
            .validate_packet_hash_cancellable(&[0; 16], 0, &cancellation)
            .unwrap_err();
        assert!(matches!(error, Par2Error::Cancelled));
    }
}
