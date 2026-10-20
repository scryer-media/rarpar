//! A RAR5 archive as a sequence of blocks, and the two changes this crate
//! makes to one: appending and removing a caller-named service record.
//!
//! [`Rar5Container::read`] walks the block headers of one RAR5 archive or
//! volume and records where each header and data area sits, without
//! decompressing or decrypting any member. Archives with encrypted headers
//! (`-hp`) are walked with the caller's password; every header CRC is
//! checked, since the map decides where bytes are written.
//!
//! [`Rar5Container::append_service_record`] plans a service record (block
//! type 3) whose name and payload come from the caller, and
//! [`Rar5Container::remove_service_record`] plans the removal of one. Neither
//! knows or cares what the payload is: the crate never creates, rewrites or
//! compresses a member, and the only bytes it writes are the record header
//! and verbatim copies of the archive around it.
//!
//! # Record layout
//!
//! These are this crate's choices; no reference tool writes such records,
//! so each has its reason here.
//!
//! - **Position: immediately before the end-of-archive header.** Every block
//!   offset the archive records (the main header's quick-open and recovery
//!   record locators) points before it, so none moves. Alternative: after
//!   the end header, which RAR readers ignore; rejected because the record
//!   would then be no block of the archive at all.
//! - **Header flags: data area + skip-if-unknown.** The payload is the data
//!   area; skip-if-unknown asks a reader that has no use for the record to
//!   pass over it rather than fail.
//! - **File fields: no file flags (no CRC, no time), unpacked size = payload
//!   length, attributes 0, stored (compression info 0), host OS Unix.** No
//!   CRC because the header precedes the payload when it is written
//!   streaming, and a caller with its own integrity scheme loses nothing.
//!   Alternative: a CRC32 field, which would need the payload twice or a
//!   seek back.
//! - **No extra area.**
//! - **Encrypted headers (`-hp`): sealed like the archive's own headers** —
//!   a 16-byte IV, then AES-256-CBC under the archive's header key of the
//!   CRC, size and body, zero-padded to the block size. The data area stays
//!   in the clear, as for every other service record. The IV is
//!   deterministic: the first 16 bytes of HMAC-SHA256 under the archive's
//!   hash key over a domain label and the padded plaintext, so a lost or
//!   damaged record header can be rebuilt byte for byte from the archive's
//!   encryption header and the password. Alternative: a random IV, as RAR
//!   itself uses for its headers; it would make a rebuilt header differ from
//!   the one it replaces.
//!
//! # What is refused
//!
//! A locked archive (its lock asks for no modification), a second record of
//! the same name, a change at or before a block the main header's
//! quick-open or recovery-record locator names (it would move that block),
//! an archive whose headers do not walk cleanly to an end-of-archive header
//! or number more than
//! [`MAX_HEADERS_PER_VOLUME`], and a
//! self-extracting archive (the signature must be at offset 0).

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use zeroize::Zeroize;

use crate::crypto::{self, KdfCache};
use crate::error::{LimitKind, RarError, RarResult};
use crate::header::common::{self, HeaderType, RawHeader};
use crate::header::{encryption, end_archive, main_archive, service};
use crate::limits::MAX_HEADERS_PER_VOLUME;
use crate::signature::{RAR5_SIGNATURE, RAR5_SIGNATURE_LEN};
use crate::vint;

/// Header flags of an appended record: data area and skip-if-unknown.
const RECORD_FLAGS: u64 = common::flags::DATA_AREA | common::flags::SKIP_IF_UNKNOWN;
/// Host OS field of an appended record (Unix).
const RECORD_HOST_OS: u64 = 1;
/// Longest record name accepted, in bytes.
pub const MAX_RECORD_NAME: usize = 255;
/// Domain label of the sealed-header IV derivation.
const SEAL_IV_LABEL: &[u8] = b"unrar-rs sealed service record header IV v1\0";
const AES_BLOCK: usize = 16;
const COPY_BUFFER: usize = 64 << 10;

/// What a block is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Main archive header.
    Main,
    /// A member.
    File,
    /// A service record, with its name.
    Service(String),
    /// The plaintext archive encryption header of a `-hp` archive.
    Encryption,
    /// End-of-archive header.
    End,
    /// A block type this crate does not know.
    Unknown(u64),
}

/// One block of the archive: its header bytes (IV and padding included for a
/// sealed header) and its data area, in file offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// What the block is.
    pub kind: BlockKind,
    /// The header's bytes in the file.
    pub header: Range<u64>,
    /// The data area; empty when the block has none.
    pub data: Range<u64>,
    /// Common header flags.
    pub flags: u64,
}

impl Block {
    /// Header and data area together.
    pub fn range(&self) -> Range<u64> {
        self.header.start..self.data.end
    }
}

/// The keys that seal a `-hp` archive's headers. Zeroized on drop.
#[derive(Clone)]
pub struct HeaderSealing {
    key: [u8; 32],
    hash_key: [u8; 32],
}

impl std::fmt::Debug for HeaderSealing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderSealing").finish_non_exhaustive()
    }
}

impl Drop for HeaderSealing {
    fn drop(&mut self) {
        self.key.zeroize();
        self.hash_key.zeroize();
    }
}

impl HeaderSealing {
    /// Read the archive's signature and first header and, when it is the
    /// encryption header of a `-hp` archive, derive the header keys from
    /// `password`. `Ok(None)` for an archive whose headers are not sealed.
    ///
    /// The password is confirmed by the archive's password check value when
    /// it has one, and nothing past the encryption header is read, so this
    /// works on an archive whose later bytes are damaged. An archive made
    /// without a check value is confirmed by unsealing the header after the
    /// encryption header (the main header) and checking its CRC instead.
    ///
    /// # Errors
    ///
    /// [`RarError::EncryptedArchive`] when the headers are sealed and no
    /// password was given; [`RarError::InvalidPassword`] when the archive's
    /// password check rejects it or, without a check value, when the main
    /// header does not unseal (a wrong password, or a damaged main header:
    /// the two cannot be told apart).
    pub fn from_archive<R: Read + Seek>(
        reader: &mut R,
        password: Option<&str>,
        kdf: &KdfCache,
    ) -> RarResult<Option<Self>> {
        let Some(header) = read_encryption_header(reader)? else {
            return Ok(None);
        };
        let password = password.ok_or(RarError::EncryptedArchive)?;
        let sealing = Self::derive(&header, password, kdf)?;
        if header.check_data.is_none() {
            let at = reader.stream_position()?;
            sealing.confirm(reader, at)?;
        }
        Ok(Some(sealing))
    }

    /// Confirm the keys by unsealing the header at `at`. Any failure is
    /// reported as [`RarError::InvalidPassword`]: under a wrong key the
    /// "header" is noise, and what fails first (size, CRC, length) is chance.
    fn confirm<R: Read + Seek>(&self, reader: &mut R, at: u64) -> RarResult<()> {
        reader.seek(SeekFrom::Start(at))?;
        read_sealed_header(reader, at, &self.key)
            .map(drop)
            .map_err(|_| RarError::InvalidPassword)
    }

    fn derive(
        header: &encryption::EncryptionHeader,
        password: &str,
        kdf: &KdfCache,
    ) -> RarResult<Self> {
        let material = kdf.derive_material_rar5(password, &header.salt, header.kdf_count)?;
        if let Some(check) = &header.check_data
            && !kdf.verify_password_rar5(password, &header.salt, header.kdf_count, check)
        {
            return Err(RarError::InvalidPassword);
        }
        Ok(Self {
            key: material.key,
            hash_key: material.hash_key,
        })
    }
}

/// Whether the archive's headers are sealed (`-hp`), from its signature and
/// first header alone.
pub fn headers_sealed<R: Read + Seek>(reader: &mut R) -> RarResult<bool> {
    Ok(read_encryption_header(reader)?.is_some())
}

fn read_signature_at_zero<R: Read + Seek>(reader: &mut R) -> RarResult<()> {
    reader.seek(SeekFrom::Start(0))?;
    let mut signature = [0u8; RAR5_SIGNATURE_LEN];
    reader
        .read_exact(&mut signature)
        .map_err(|_| RarError::InvalidSignature)?;
    if signature != RAR5_SIGNATURE {
        return Err(RarError::InvalidSignature);
    }
    Ok(())
}

fn read_encryption_header<R: Read + Seek>(
    reader: &mut R,
) -> RarResult<Option<encryption::EncryptionHeader>> {
    read_signature_at_zero(reader)?;
    let raw = read_plain_header(reader)?.ok_or(RarError::TruncatedHeader {
        offset: RAR5_SIGNATURE_LEN as u64,
    })?;
    match raw.header_type {
        HeaderType::Encryption => Ok(Some(encryption::parse(&raw)?)),
        _ => Ok(None),
    }
}

/// A plaintext header with its CRC checked.
fn read_plain_header<R: Read + Seek>(reader: &mut R) -> RarResult<Option<RawHeader>> {
    let Some(raw) = common::read_raw_header(reader)? else {
        return Ok(None);
    };
    let computed = header_crc(raw.header_size, raw.header_size_vint_len, &raw.body);
    if computed != raw.crc32 {
        return Err(RarError::HeaderCrcMismatch {
            expected: raw.crc32,
            actual: computed,
        });
    }
    Ok(Some(raw))
}

fn header_crc(size: u64, size_len: usize, body: &[u8]) -> u32 {
    let mut hasher = crate::Hasher::new();
    hasher.update(&common::vint_encode_for_crc(size, size_len));
    hasher.update(body);
    hasher.finalize()
}

/// The block map of one RAR5 archive or volume.
#[derive(Clone, Debug)]
pub struct Rar5Container {
    /// Blocks in file order, from the first header after the signature to
    /// the end-of-archive header.
    pub blocks: Vec<Block>,
    /// Volume number (0 for the first) when the archive is a volume.
    pub volume: Option<u64>,
    /// The end-of-archive header says another volume follows.
    pub more_volumes: bool,
    /// Solid archive.
    pub solid: bool,
    /// Locked archive.
    pub locked: bool,
    /// The main header announces a recovery record.
    pub recovery_record: bool,
    /// Where the main header's locator says the quick-open record starts.
    pub quick_open_at: Option<u64>,
    /// Where the main header's locator says the recovery record starts.
    pub recovery_record_at: Option<u64>,
    /// File length.
    pub len: u64,
    sealing: Option<HeaderSealing>,
}

impl Rar5Container {
    /// Walk the archive at `path`. See [`Self::read`].
    pub fn open(path: &Path, password: Option<&str>, kdf: &KdfCache) -> RarResult<Self> {
        Self::read(&mut BufReader::new(File::open(path)?), password, kdf)
    }

    /// Walk the block headers of the RAR5 archive `reader` holds, from the
    /// signature (which must be at offset 0) to the end-of-archive header.
    /// `password` unseals a `-hp` archive's headers and is ignored otherwise.
    ///
    /// # Errors
    ///
    /// [`RarError::InvalidSignature`] for anything but RAR5 at offset 0;
    /// [`RarError::EncryptedArchive`] for sealed headers without a password;
    /// [`RarError::InvalidPassword`] for a wrong password, as
    /// [`HeaderSealing::from_archive`] confirms it;
    /// [`RarError::HeaderCrcMismatch`] for any damaged header;
    /// [`RarError::CorruptArchive`] or [`RarError::TruncatedHeader`] for a
    /// walk that ends without an end-of-archive header or runs past the file;
    /// [`RarError::ResourceLimit`] for more than
    /// [`MAX_HEADERS_PER_VOLUME`]
    /// blocks.
    pub fn read<R: Read + Seek>(
        reader: &mut R,
        password: Option<&str>,
        kdf: &KdfCache,
    ) -> RarResult<Self> {
        let len = reader.seek(SeekFrom::End(0))?;
        let sealing = HeaderSealing::from_archive(reader, password, kdf)?;
        let mut map = Self {
            blocks: Vec::new(),
            volume: None,
            more_volumes: false,
            solid: false,
            locked: false,
            recovery_record: false,
            quick_open_at: None,
            recovery_record_at: None,
            len,
            sealing,
        };
        let mut at = RAR5_SIGNATURE_LEN as u64;
        loop {
            if map.blocks.len() >= MAX_HEADERS_PER_VOLUME {
                return Err(RarError::resource_limit(
                    LimitKind::HeadersPerVolume,
                    map.blocks.len() as u64 + 1,
                    MAX_HEADERS_PER_VOLUME as u64,
                    None,
                ));
            }
            reader.seek(SeekFrom::Start(at))?;
            let (raw, header_end) = match &map.sealing {
                Some(sealing) if at != RAR5_SIGNATURE_LEN as u64 => {
                    read_sealed_header(reader, at, &sealing.key)?
                }
                _ => {
                    let raw = read_plain_header(reader)?.ok_or_else(|| missing_end(at))?;
                    let end = reader.stream_position()?;
                    (raw, end)
                }
            };
            let data_end = header_end
                .checked_add(raw.data_area_size)
                .filter(|end| *end <= len)
                .ok_or_else(|| RarError::CorruptArchive {
                    detail: format!("block at offset {at} runs past the end of the file"),
                })?;
            if header_end > len {
                return Err(missing_end(at));
            }
            let kind = match raw.header_type {
                HeaderType::MainArchive => {
                    let main = main_archive::parse(&raw)?;
                    map.volume = main.is_volume.then_some(main.volume_number.unwrap_or(0));
                    map.solid = main.is_solid;
                    map.locked = main.is_locked;
                    map.recovery_record = main.has_recovery_record;
                    map.quick_open_at = main.quick_open_offset;
                    map.recovery_record_at = main.recovery_record_offset;
                    BlockKind::Main
                }
                HeaderType::File => BlockKind::File,
                HeaderType::Service => {
                    let name = service::parse(&raw, header_end)?.service_name().to_owned();
                    BlockKind::Service(name)
                }
                HeaderType::Encryption => BlockKind::Encryption,
                HeaderType::EndArchive => {
                    map.more_volumes = end_archive::parse(&raw)?.more_volumes;
                    BlockKind::End
                }
                HeaderType::Unknown(kind) => BlockKind::Unknown(kind),
            };
            let end = kind == BlockKind::End;
            map.blocks.push(Block {
                kind,
                header: at..header_end,
                data: header_end..data_end,
                flags: raw.flags,
            });
            if end {
                return Ok(map);
            }
            at = data_end;
        }
    }

    /// The archive's headers are sealed (`-hp`).
    pub fn headers_sealed(&self) -> bool {
        self.sealing.is_some()
    }

    /// The header keys of a `-hp` archive.
    pub fn sealing(&self) -> Option<&HeaderSealing> {
        self.sealing.as_ref()
    }

    /// The end-of-archive header.
    pub fn end_header(&self) -> Range<u64> {
        self.blocks
            .last()
            .map(|block| block.header.clone())
            .expect("a walked archive ends with its end header")
    }

    /// Service records named `name`, in file order.
    pub fn service_records<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Block> + 'a {
        self.blocks
            .iter()
            .filter(move |block| matches!(&block.kind, BlockKind::Service(n) if n == name))
    }

    /// Plan a service record named `name` carrying `payload_len` bytes, placed
    /// immediately before the end-of-archive header and, for a `-hp`
    /// archive, sealed with the archive's header key. Nothing is written.
    ///
    /// # Errors
    ///
    /// [`RarError::ModificationRefused`] for a locked archive, a record of
    /// that name already present, an empty or over-long name, a locator in
    /// the main header that points at or past the end header (whose target
    /// the record would move), or a record that would take the archive past
    /// `u64::MAX` bytes.
    pub fn append_service_record(
        &self,
        name: &str,
        payload_len: u64,
    ) -> RarResult<ServiceRecordAppend> {
        if self.locked {
            return Err(refused("the archive is locked"));
        }
        if self.service_records(name).next().is_some() {
            return Err(refused(format!(
                "the archive already holds a {name} record"
            )));
        }
        let at = self.end_header().start;
        self.check_locators(at)?;
        let header = service_record_header(name, payload_len, self.sealing.as_ref())?;
        let output_len = (header.len() as u64)
            .checked_add(payload_len)
            .and_then(|record| record.checked_add(self.len))
            .ok_or_else(|| refused("the record would make the archive too long"))?;
        Ok(ServiceRecordAppend {
            at,
            header,
            payload_len,
            archive_len: self.len,
            output_len,
        })
    }

    /// Refuse a change at `at` when a main-header locator points at or past
    /// it: the change would move the block the locator names.
    fn check_locators(&self, at: u64) -> RarResult<()> {
        for (what, target) in [
            ("quick-open", self.quick_open_at),
            ("recovery record", self.recovery_record_at),
        ] {
            if target.is_some_and(|target| target >= at) {
                return Err(refused(format!(
                    "the main header's {what} locator points at or past offset {at}, \
                     which the change would move"
                )));
            }
        }
        Ok(())
    }

    /// Plan the removal of the one service record named `name`. Nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// [`RarError::ModificationRefused`] for a locked archive, when the
    /// archive holds no record of that name or more than one, or when a
    /// locator in the main header points at or past the record.
    pub fn remove_service_record(&self, name: &str) -> RarResult<ServiceRecordRemoval> {
        if self.locked {
            return Err(refused("the archive is locked"));
        }
        let mut records = self.service_records(name);
        let record = records
            .next()
            .ok_or_else(|| refused(format!("the archive holds no {name} record")))?;
        if records.next().is_some() {
            return Err(refused(format!(
                "the archive holds more than one {name} record"
            )));
        }
        self.check_locators(record.header.start)?;
        Ok(ServiceRecordRemoval {
            record: record.range(),
            archive_len: self.len,
        })
    }
}

fn missing_end(at: u64) -> RarError {
    RarError::CorruptArchive {
        detail: format!("no end-of-archive header after offset {at}"),
    }
}

fn refused(detail: impl Into<String>) -> RarError {
    RarError::ModificationRefused {
        detail: detail.into(),
    }
}

/// One sealed header at `at`: its raw form and the offset its data area
/// starts at.
fn read_sealed_header<R: Read + Seek>(
    reader: &mut R,
    at: u64,
    key: &[u8; 32],
) -> RarResult<(RawHeader, u64)> {
    let mut iv = [0u8; AES_BLOCK];
    let mut first = [0u8; AES_BLOCK];
    reader
        .read_exact(&mut iv)
        .and_then(|()| reader.read_exact(&mut first))
        .map_err(|_| missing_end(at))?;
    let mut decryptor = crypto::CbcDecryptor::new(key, &iv);
    decryptor.decrypt_blocks(&mut first);
    let stored = u32::from_le_bytes(first[..4].try_into().expect("four bytes"));
    let (size, size_len) = vint::read_vint(&first[4..])?;
    common::validate_header_size(at, size, size_len)?;
    let total = 4 + size_len + size as usize;
    let aligned = total.next_multiple_of(AES_BLOCK);
    let mut plain = Vec::with_capacity(aligned);
    plain.extend_from_slice(&first);
    if aligned > AES_BLOCK {
        let mut rest = vec![0u8; aligned - AES_BLOCK];
        reader.read_exact(&mut rest).map_err(|_| missing_end(at))?;
        decryptor.decrypt_blocks(&mut rest);
        plain.extend_from_slice(&rest);
    }
    let body = plain[4 + size_len..total].to_vec();
    let computed = header_crc(size, size_len, &body);
    if computed != stored {
        return Err(RarError::HeaderCrcMismatch {
            expected: stored,
            actual: computed,
        });
    }
    let raw = common::parse_raw_header_from_parts(at, stored, size, size_len, body)?;
    Ok((raw, at + (AES_BLOCK + aligned) as u64))
}

fn vint_len(value: u64) -> u64 {
    (64 - value.max(1).leading_zeros() as u64).div_ceil(7)
}

fn check_name(name: &str) -> RarResult<()> {
    if name.is_empty() || name.len() > MAX_RECORD_NAME || name.contains('\0') {
        return Err(refused(format!(
            "a service record name is 1 to {MAX_RECORD_NAME} bytes without NUL"
        )));
    }
    Ok(())
}

/// The vint fields of a record header, from its type field to the name
/// length; the name's bytes follow them.
fn record_fields(name_len: usize, payload_len: u64) -> [u64; 9] {
    [
        3, // service header
        RECORD_FLAGS,
        payload_len, // data area size
        0,           // file flags: no time, no CRC
        payload_len, // unpacked size
        0,           // attributes
        0,           // compression info: stored
        RECORD_HOST_OS,
        name_len as u64,
    ]
}

/// The plaintext header body of a record, from its type field on.
fn record_body(name: &str, payload_len: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 + name.len());
    for field in record_fields(name.len(), payload_len) {
        body.extend_from_slice(&vint::encode_vint(field));
    }
    body.extend_from_slice(name.as_bytes());
    body
}

/// Length of the header [`service_record_header`] builds, without building
/// it. A caller sizing what follows the header needs only this.
pub fn service_record_header_len(name_len: usize, payload_len: u64, sealed: bool) -> u64 {
    let body = record_fields(name_len, payload_len)
        .into_iter()
        .map(vint_len)
        .sum::<u64>()
        + name_len as u64;
    let plain = 4 + vint_len(body) + body;
    if sealed {
        AES_BLOCK as u64 + plain.next_multiple_of(AES_BLOCK as u64)
    } else {
        plain
    }
}

/// The header of a service record named `name` with a `payload_len`-byte
/// data area, as [`Rar5Container::append_service_record`] writes it (see the
/// module documentation for the layout and its reasons). With `sealing`, the
/// header is sealed for a `-hp` archive; the same inputs always give the
/// same bytes.
pub fn service_record_header(
    name: &str,
    payload_len: u64,
    sealing: Option<&HeaderSealing>,
) -> RarResult<Vec<u8>> {
    check_name(name)?;
    let body = record_body(name, payload_len);
    let size = body.len() as u64;
    let size_vint = vint::encode_vint(size);
    let mut header = Vec::with_capacity(4 + size_vint.len() + body.len() + 2 * AES_BLOCK);
    header.extend_from_slice(&header_crc(size, size_vint.len(), &body).to_le_bytes());
    header.extend_from_slice(&size_vint);
    header.extend_from_slice(&body);
    let Some(sealing) = sealing else {
        return Ok(header);
    };
    header.resize(header.len().next_multiple_of(AES_BLOCK), 0);
    let mut labelled = Vec::with_capacity(SEAL_IV_LABEL.len() + header.len());
    labelled.extend_from_slice(SEAL_IV_LABEL);
    labelled.extend_from_slice(&header);
    let mac = crypto::hmac_sha256(&sealing.hash_key, &labelled);
    let iv: [u8; AES_BLOCK] = mac[..AES_BLOCK].try_into().expect("sixteen bytes");
    crypto::encrypt_cipher_range(&sealing.key, &iv, &mut header)?;
    let mut sealed = Vec::with_capacity(AES_BLOCK + header.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&header);
    Ok(sealed)
}

/// Copy `range` of `from` to `out` in 64 KiB reads, refusing a short source.
fn copy_range<R: Read + Seek, W: Write + ?Sized>(
    from: &mut R,
    range: Range<u64>,
    out: &mut W,
) -> RarResult<()> {
    from.seek(SeekFrom::Start(range.start))?;
    let mut buffer = vec![0u8; (range.end - range.start).min(COPY_BUFFER as u64) as usize];
    let mut remaining = range.end - range.start;
    while remaining != 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        from.read_exact(&mut buffer[..take])
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => RarError::CorruptArchive {
                    detail: "the archive is shorter than when it was walked".into(),
                },
                _ => error.into(),
            })?;
        out.write_all(&buffer[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

fn check_len<R: Seek>(archive: &mut R, expected: u64) -> RarResult<()> {
    if archive.seek(SeekFrom::End(0))? != expected {
        return Err(refused("the archive changed length since it was walked"));
    }
    Ok(())
}

/// A planned service record append: the archive's bytes up to the record
/// position, the record header, the caller's payload, then the rest of the
/// archive (the end-of-archive header and anything after it).
///
/// The output is written in three steps so a caller can produce the payload
/// in between from wherever it comes: [`Self::copy_before`],
/// [`Self::header`] (written by the caller or by [`Self::write_header`]),
/// the payload, and [`Self::copy_after`]. [`Self::write`] does all of it
/// from a payload reader.
///
/// The archive a plan is written from must be the one it was planned on.
/// The copies check its length only, before writing anything; a same-length
/// change goes unnoticed, so callers hold the archive unchanged in between.
/// An error part way leaves `out` partly written; callers write to a staging
/// file and discard it on error.
#[derive(Clone, Debug)]
pub struct ServiceRecordAppend {
    at: u64,
    header: Vec<u8>,
    payload_len: u64,
    archive_len: u64,
    output_len: u64,
}

impl ServiceRecordAppend {
    /// Offset in the archive the record goes at: the end header's start.
    pub fn at(&self) -> u64 {
        self.at
    }

    /// The record header bytes.
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Payload length the header declares.
    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// The record, header and payload, in output offsets.
    pub fn record(&self) -> Range<u64> {
        self.at..self.at + self.header.len() as u64 + self.payload_len
    }

    /// Length of the archive with the record.
    pub fn output_len(&self) -> u64 {
        self.output_len
    }

    /// Copy the archive's bytes before the record position to `out`.
    pub fn copy_before<R: Read + Seek, W: Write + ?Sized>(
        &self,
        archive: &mut R,
        out: &mut W,
    ) -> RarResult<()> {
        check_len(archive, self.archive_len)?;
        copy_range(archive, 0..self.at, out)
    }

    /// Write the record header to `out`.
    pub fn write_header<W: Write + ?Sized>(&self, out: &mut W) -> RarResult<()> {
        out.write_all(&self.header)?;
        Ok(())
    }

    /// Copy the archive's bytes from the record position on to `out`.
    pub fn copy_after<R: Read + Seek, W: Write + ?Sized>(
        &self,
        archive: &mut R,
        out: &mut W,
    ) -> RarResult<()> {
        check_len(archive, self.archive_len)?;
        copy_range(archive, self.at..self.archive_len, out)
    }

    /// Write the whole archive with the record to `out`, the payload read
    /// from `payload`, which must hold exactly [`Self::payload_len`] bytes.
    /// Returns the bytes written.
    pub fn write<R: Read + Seek, P: Read, W: Write + ?Sized>(
        &self,
        archive: &mut R,
        payload: &mut P,
        out: &mut W,
    ) -> RarResult<u64> {
        self.copy_before(archive, out)?;
        self.write_header(out)?;
        let copied = io::copy(&mut payload.by_ref().take(self.payload_len), out)?;
        let mut probe = [0u8; 1];
        if copied != self.payload_len || payload.read(&mut probe)? != 0 {
            return Err(refused(
                "the payload length differs from the planned length",
            ));
        }
        self.copy_after(archive, out)?;
        Ok(self.output_len())
    }
}

/// A planned removal of one service record: the archive's bytes with the
/// record (header and data area) left out.
#[derive(Clone, Debug)]
pub struct ServiceRecordRemoval {
    record: Range<u64>,
    archive_len: u64,
}

impl ServiceRecordRemoval {
    /// The record's bytes in the archive.
    pub fn record(&self) -> Range<u64> {
        self.record.clone()
    }

    /// Length of the archive without the record.
    pub fn output_len(&self) -> u64 {
        self.archive_len - (self.record.end - self.record.start)
    }

    /// Write the archive without the record to `out`. Returns the bytes
    /// written.
    pub fn write<R: Read + Seek, W: Write + ?Sized>(
        &self,
        archive: &mut R,
        out: &mut W,
    ) -> RarResult<u64> {
        check_len(archive, self.archive_len)?;
        copy_range(archive, 0..self.record.start, out)?;
        copy_range(archive, self.record.end..self.archive_len, out)?;
        Ok(self.output_len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicted_lengths_match_built_headers() {
        let sealing = HeaderSealing {
            key: [7; 32],
            hash_key: [9; 32],
        };
        for name in ["PAR3", "x", &"n".repeat(MAX_RECORD_NAME)] {
            for payload in [0, 1, 127, 128, 16_383, 16_384, 1 << 40, u64::MAX >> 1] {
                let plain = service_record_header(name, payload, None).unwrap();
                assert_eq!(
                    plain.len() as u64,
                    service_record_header_len(name.len(), payload, false)
                );
                let sealed = service_record_header(name, payload, Some(&sealing)).unwrap();
                assert_eq!(
                    sealed.len() as u64,
                    service_record_header_len(name.len(), payload, true)
                );
                assert_eq!(
                    sealed,
                    service_record_header(name, payload, Some(&sealing)).unwrap(),
                    "sealing is deterministic"
                );
            }
        }
    }

    #[test]
    fn plain_header_parses_as_the_service_record_it_declares() {
        let header = service_record_header("PAR3", 1000, None).unwrap();
        let raw = common::read_raw_header(&mut io::Cursor::new(&header))
            .unwrap()
            .unwrap();
        assert_eq!(
            raw.crc32,
            header_crc(raw.header_size, raw.header_size_vint_len, &raw.body)
        );
        assert_eq!(raw.header_type, HeaderType::Service);
        assert_eq!(raw.data_area_size, 1000);
        let parsed = service::parse(&raw, header.len() as u64).unwrap();
        assert_eq!(parsed.service_name(), "PAR3");
    }

    #[test]
    fn sealed_header_unseals_with_the_archive_key() {
        let sealing = HeaderSealing {
            key: [3; 32],
            hash_key: [4; 32],
        };
        let header = service_record_header("PAR3", 4242, Some(&sealing)).unwrap();
        let (raw, end) =
            read_sealed_header(&mut io::Cursor::new(&header), 0, &sealing.key).unwrap();
        assert_eq!(end, header.len() as u64);
        assert_eq!(raw.data_area_size, 4242);
        let parsed = service::parse(&raw, end).unwrap();
        assert_eq!(parsed.service_name(), "PAR3");
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/rar5")
                .join(name),
        )
        .unwrap()
    }

    /// An archive without a password check value is confirmed on its main
    /// header, and whatever a wrong key makes of that header (a bad size, a
    /// bad CRC, a length past the file) is a wrong password, so a caller
    /// trying candidates moves on to the next one.
    #[test]
    fn a_wrong_key_on_the_main_header_is_an_invalid_password() {
        let kdf = KdfCache::new();
        for name in [
            "rar5_hp_lz.rar",
            "rar5_hp_store.rar",
            "rar5_hp_recovery_volumes.part1.rar",
        ] {
            let bytes = fixture(name);
            let mut reader = io::Cursor::new(&bytes);
            let header = read_encryption_header(&mut reader).unwrap().unwrap();
            let at = reader.stream_position().unwrap();
            HeaderSealing::derive(&header, "secretpass", &kdf)
                .unwrap()
                .confirm(&mut reader, at)
                .unwrap();
            for wrong in ["", "secretpas", "SECRETPASS", "testpass123"] {
                let material = kdf
                    .derive_material_rar5(wrong, &header.salt, header.kdf_count)
                    .unwrap();
                let sealing = HeaderSealing {
                    key: material.key,
                    hash_key: material.hash_key,
                };
                assert!(
                    matches!(
                        sealing.confirm(&mut reader, at),
                        Err(RarError::InvalidPassword)
                    ),
                    "{name} with {wrong:?}"
                );
                assert!(matches!(
                    Rar5Container::read(&mut io::Cursor::new(&bytes), Some(wrong), &kdf),
                    Err(RarError::InvalidPassword)
                ));
            }
        }
    }

    /// A change at or before a block a main-header locator names would move
    /// that block, and is refused.
    #[test]
    fn a_change_that_moves_a_located_block_is_refused() {
        let bytes = fixture("rar5_recovery.rar");
        let kdf = KdfCache::new();
        let map = Rar5Container::read(&mut io::Cursor::new(&bytes), None, &kdf).unwrap();
        let rr = map.recovery_record_at.expect("the fixture locates its RR");
        assert!(map.append_service_record("PAR3", 1).is_ok());
        let mut moved = map.clone();
        moved.recovery_record_at = Some(moved.end_header().start);
        assert!(matches!(
            moved.append_service_record("PAR3", 1),
            Err(RarError::ModificationRefused { .. })
        ));
        let mut moved = map.clone();
        moved.quick_open_at = Some(u64::MAX);
        assert!(matches!(
            moved.append_service_record("PAR3", 1),
            Err(RarError::ModificationRefused { .. })
        ));
        // Removing the RR itself would move what its locator names.
        assert!(matches!(
            map.remove_service_record("RR"),
            Err(RarError::ModificationRefused { .. })
        ));
        assert!(rr < map.end_header().start);
    }

    /// A sealed header is rebuilt on repair, possibly by a build on the other
    /// crypto backend, so both backends must seal to the same bytes. The
    /// expected digest is pinned and checked under each backend.
    #[test]
    fn sealed_headers_are_the_same_bytes_on_every_backend() {
        let sealing = HeaderSealing {
            key: [3; 32],
            hash_key: [4; 32],
        };
        let header = service_record_header("PAR3", 4242, Some(&sealing)).unwrap();
        let digest = crypto::hmac_sha256(&[0; 32], &header);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "cdcd5142b4cf7d72f190cc62d9b85e4e709fffe46f00e664dfa398c4120928ac"
        );
    }

    #[test]
    fn bad_names_are_refused() {
        for name in ["", "a\0b", &"n".repeat(MAX_RECORD_NAME + 1)] {
            assert!(matches!(
                service_record_header(name, 1, None),
                Err(RarError::ModificationRefused { .. })
            ));
        }
    }
}
