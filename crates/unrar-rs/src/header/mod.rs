//! Header parsing dispatcher for RAR5 archives.
//!
//! Iterates through all headers in a RAR5 archive, dispatching to
//! type-specific parsers.

pub mod common;
pub mod compression_info;
pub mod encryption;
pub mod end_archive;
pub mod extra;
pub mod file;
pub mod main_archive;
pub mod service;

use std::io::{Read, Seek, SeekFrom};

use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::error::{RarError, RarResult};
use crate::vint;
use common::{HeaderType, RawHeader};

/// A parsed header from the archive.
#[derive(Debug, Clone)]
pub enum Header {
    MainArchive(main_archive::MainArchiveHeader),
    File(file::FileHeader),
    Service(service::ServiceHeader),
    Encryption(encryption::EncryptionHeader),
    EndArchive(end_archive::EndArchiveHeader),
    /// Unknown header type that was skipped.
    Unknown(u64),
}

/// File-level encryption parameters from extra records.
#[derive(Debug, Clone)]
pub struct FileEncryptionParams {
    pub version: u64,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check_data: Option<[u8; 12]>,
    /// Whether the record's flags claim a password-check value at all.
    ///
    /// Distinct from `check_data.is_some()`: the parser drops a check value
    /// whose trailing SHA-256 tag does not match, so a claimed-but-unusable
    /// check reads as `psw_check_present` with `check_data: None`. A caller
    /// deciding whether a wrong password can be detected before decrypting
    /// needs `check_data`; one reporting *why* it cannot needs both.
    pub psw_check_present: bool,
    /// When true, CRC32 and BLAKE2 hashes in the header are HMAC-transformed
    /// and cannot be verified without HashKey from the RAR5 KDF chain.
    pub use_hash_mac: bool,
}

/// A file header enriched with extra record data.
#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub header: file::FileHeader,
    pub is_encrypted: bool,
    pub file_encryption: Option<FileEncryptionParams>,
    pub hash: Option<crate::types::FileHash>,
    pub redirection: Option<Redirection>,
    pub owner: Option<crate::types::UnixOwnerInfo>,
}

/// A service header enriched with extra record data.
#[derive(Debug, Clone)]
pub struct ParsedService {
    pub header: service::ServiceHeader,
    pub is_encrypted: bool,
    pub file_encryption: Option<FileEncryptionParams>,
    pub hash: Option<crate::types::FileHash>,
}

/// Redirection info from extra records (symlinks/hardlinks).
#[derive(Debug, Clone)]
pub struct Redirection {
    pub redir_type: RedirectionType,
    pub target: String,
    pub target_raw: Option<Vec<u8>>,
    pub target_is_directory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectionType {
    UnixSymlink,
    WindowsSymlink,
    WindowsJunction,
    Hardlink,
    FileCopy,
    Unknown(u64),
}

impl From<u64> for RedirectionType {
    fn from(value: u64) -> Self {
        match value {
            1 => RedirectionType::UnixSymlink,
            2 => RedirectionType::WindowsSymlink,
            3 => RedirectionType::WindowsJunction,
            4 => RedirectionType::Hardlink,
            5 => RedirectionType::FileCopy,
            other => RedirectionType::Unknown(other),
        }
    }
}

/// Result of parsing all headers in a single volume.
#[derive(Debug)]
pub struct ParsedHeaders {
    /// The main archive header (always present in a valid archive).
    pub main: Option<main_archive::MainArchiveHeader>,
    /// All file headers found, enriched with extra record data.
    pub files: Vec<ParsedFile>,
    /// All service headers found, enriched with extra record data.
    pub services: Vec<ParsedService>,
    /// Encryption header, if present.
    pub encryption: Option<encryption::EncryptionHeader>,
    /// End of archive header, if present.
    pub end: Option<end_archive::EndArchiveHeader>,
    /// Whether the archive is encrypted at the header level.
    pub is_encrypted: bool,
    /// Whether the headers above were read out of the archive's Quick Open
    /// cache rather than off the physical header chain.
    ///
    /// `true` only when the whole result came from the `QO` service block;
    /// `false` whenever the physical walk produced it — including when a `QO`
    /// block was present but rejected, and whenever
    /// [`HeaderParseOptions::allow_quick_open`] was `false`.
    ///
    /// **Cache-derived headers are not authoritative.** The RAR5 format binds
    /// no `QO` record to the physical header it claims to describe, and the
    /// specification itself warns that the cached copies may deliberately
    /// differ from the real ones. A caller deciding where bytes are written —
    /// member names, data offsets, what is admitted downstream — must treat a
    /// `true` here as "re-read physically before trusting this", and can skip
    /// that second walk when it is `false`.
    ///
    /// This is the provenance answer; the presence of a locator record is not.
    /// A main header can carry a Quick Open locator whose cache was then
    /// rejected, so `quick_open_offset.is_some()` says only that a locator
    /// exists, never that these headers came from it.
    pub headers_from_quick_open: bool,
}

fn empty_parsed_headers() -> ParsedHeaders {
    ParsedHeaders {
        main: None,
        files: Vec::new(),
        services: Vec::new(),
        encryption: None,
        end: None,
        is_encrypted: false,
        headers_from_quick_open: false,
    }
}

/// Options controlling how the header walk reads an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderParseOptions {
    /// Whether the parser may answer from the archive's Quick Open cache.
    ///
    /// RAR can store a copy of every header in a `QO` service block near the
    /// end of the archive, pointed at by a locator record in the main header.
    /// When that block is present and parses cleanly through its cached
    /// end-of-archive record, a reader can list the archive's contents from
    /// that one block instead of seeking past every member's data area — which
    /// is why it is consulted by default.
    ///
    /// The cache is not authoritative. Nothing in the format binds a `QO`
    /// record to the physical header it claims to describe, so the two can
    /// disagree — through staleness, or because the archive was crafted to
    /// disagree. A forged cache can name a member that the physical walk never
    /// sees, or point an honest-looking name at different data. A caller that
    /// makes security or routing decisions from the parse result — which
    /// members exist, where their data lives, what gets admitted downstream —
    /// should set this to `false` and pay for the full physical walk.
    pub allow_quick_open: bool,
}

impl Default for HeaderParseOptions {
    /// Quick Open enabled — the long-standing behavior of
    /// [`parse_all_headers`].
    ///
    /// Written by hand rather than derived: `#[derive(Default)]` yields `false`
    /// for a `bool`, which would silently opt every existing caller out of
    /// Quick Open and turn a performance choice into an accidental one.
    fn default() -> Self {
        Self {
            allow_quick_open: true,
        }
    }
}

/// Parse all headers from a RAR5 archive stream.
///
/// The reader should be positioned right after the RAR5 signature (8 bytes in).
/// If a password is provided, archive-level encryption (encrypted headers) will
/// be decrypted. Without a password, encountering an encryption header returns
/// `Err(RarError::EncryptedArchive)`.
///
/// Parses under [`HeaderParseOptions::default()`], so the archive's Quick Open
/// cache is used when present. Callers that must not trust that cache should
/// use [`parse_all_headers_with_options`].
pub fn parse_all_headers<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
) -> RarResult<ParsedHeaders> {
    parse_all_headers_with_options(reader, password, HeaderParseOptions::default())
}

/// Parse all headers from a RAR5 archive stream under explicit `options`.
///
/// Same contract as [`parse_all_headers`], which is exactly this function with
/// [`HeaderParseOptions::default()`]. Pass
/// `HeaderParseOptions { allow_quick_open: false }` to require that every
/// returned header came from the physical header walk, never from the
/// archive's non-authoritative (and forgeable) Quick Open cache.
pub fn parse_all_headers_with_options<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
    options: HeaderParseOptions,
) -> RarResult<ParsedHeaders> {
    let kdf_cache = crate::crypto::KdfCache::new();
    parse_all_headers_with_kdf_cache_and_options(reader, password, &kdf_cache, options)
}

/// Parse all headers reusing a caller-owned RAR5 KDF cache.
///
/// Uses [`HeaderParseOptions::default()`]; see
/// [`parse_all_headers_with_kdf_cache_and_options`] to choose otherwise.
pub(crate) fn parse_all_headers_with_kdf_cache<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
    kdf_cache: &crate::crypto::KdfCache,
) -> RarResult<ParsedHeaders> {
    parse_all_headers_with_kdf_cache_and_options(
        reader,
        password,
        kdf_cache,
        HeaderParseOptions::default(),
    )
}

/// Parse all headers reusing a caller-owned RAR5 KDF cache, under explicit
/// `options`.
pub(crate) fn parse_all_headers_with_kdf_cache_and_options<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
    kdf_cache: &crate::crypto::KdfCache,
    options: HeaderParseOptions,
) -> RarResult<ParsedHeaders> {
    match walk_all_headers(reader, password, kdf_cache, options)? {
        HeaderWalk::Parsed(parsed) => Ok(parsed),
        HeaderWalk::HeaderEncrypted(_) => Err(RarError::EncryptedArchive),
    }
}

/// Read a header-encrypted (`-hp`) RAR5 stream's archive encryption record
/// **with no password**.
///
/// The reader should be positioned right after the RAR5 signature, exactly as
/// for [`parse_all_headers`].
///
/// `-hp` withholds *layout* facts, not *keying* facts: the type-4 record is
/// plaintext, and the walk parses it before it consults the password. This is
/// the accessor for it — [`parse_all_headers`] discards it along with the rest
/// of the result when it refuses.
///
/// - `Ok(Some(header))` — the stream is `-hp` and this is what it states.
/// - `Ok(None)` — the walk completed without meeting a type-4 record, so the
///   stream's headers are readable and there is nothing archive-level to key.
///   A `-p` (file-data-only) archive answers `None`: its crypt records are
///   per file header, not archive level.
/// - `Err(_)` — the stream could not be walked that far, or the record itself
///   is one this build refuses (an encryption version it does not implement, or
///   a KDF count over [`crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX`]). A refusal is
///   deliberately *not* flattened into `None`: "no archive encryption" and "an
///   archive encryption this build will not derive from" are different answers
///   and a caller that keys from this must not conflate them.
///
/// Quick Open is suppressed. The cache is forgeable and this walk exists to
/// report what the physical stream states.
pub fn parse_header_encryption<R: Read + Seek>(
    reader: &mut R,
) -> RarResult<Option<encryption::EncryptionHeader>> {
    let kdf_cache = crate::crypto::KdfCache::new();
    let walk = walk_all_headers(
        reader,
        None,
        &kdf_cache,
        HeaderParseOptions {
            allow_quick_open: false,
        },
    )?;
    Ok(match walk {
        HeaderWalk::HeaderEncrypted(encryption) => Some(encryption),
        HeaderWalk::Parsed(_) => None,
    })
}

/// Where the plaintext header walk stopped.
///
/// Split out of [`parse_all_headers_with_kdf_cache_and_options`] so the
/// archive's own type-4 record can be *returned* rather than dropped on the way
/// to `Err(EncryptedArchive)`. Nothing about the walk changes; only what the
/// caller is allowed to see when it stops at an encryption header it has no
/// password for.
enum HeaderWalk {
    Parsed(ParsedHeaders),
    /// A type-4 archive encryption record was reached with no password. Every
    /// header past it is ciphertext; this record is not.
    HeaderEncrypted(encryption::EncryptionHeader),
}

fn walk_all_headers<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
    kdf_cache: &crate::crypto::KdfCache,
    options: HeaderParseOptions,
) -> RarResult<HeaderWalk> {
    let mut result = empty_parsed_headers();

    // Parse plaintext headers until we hit an encryption header or end.
    loop {
        let raw = match common::read_raw_header(reader)? {
            Some(raw) => raw,
            None => {
                debug!("reached EOF while reading headers");
                return Ok(HeaderWalk::Parsed(result));
            }
        };

        debug!(
            "header type={:?} flags={:#x} size={} data_size={} at offset={}",
            raw.header_type, raw.flags, raw.header_size, raw.data_area_size, raw.offset
        );

        let data_offset = raw.offset + 4 + raw.header_size_vint_len as u64 + raw.header_size;

        match raw.header_type {
            HeaderType::Encryption => {
                let enc = encryption::parse(&raw)?;
                debug!(
                    "encryption header: version={} kdf_count={}",
                    enc.version, enc.kdf_count
                );
                result.encryption = Some(enc.clone());
                result.is_encrypted = true;

                let pwd = match password {
                    Some(p) => p,
                    // The record itself is plaintext and is handed back rather
                    // than dropped: `-hp` withholds the layout, not the keying
                    // facts. `parse_all_headers` turns this into
                    // `Err(EncryptedArchive)` exactly as it always did.
                    None => return Ok(HeaderWalk::HeaderEncrypted(enc)),
                };

                if let Some(check_data) = enc.check_data
                    && !kdf_cache.verify_password_rar5(pwd, &enc.salt, enc.kdf_count, &check_data)
                {
                    return Err(RarError::InvalidPassword);
                }

                // Derive key (IV comes per-header from stream, not PBKDF2).
                let mut key = kdf_cache.derive_key_rar5(pwd, &enc.salt, enc.kdf_count)?;

                // Parse remaining headers — each has its own IV + padded encryption.
                let encrypted_result = parse_encrypted_headers(reader, &key, &mut result);
                key.zeroize();
                encrypted_result?;
                return Ok(HeaderWalk::Parsed(result));
            }
            HeaderType::EndArchive => {
                let end = end_archive::parse(&raw)?;
                debug!("end of archive: more_volumes={}", end.more_volumes);
                result.end = Some(end);
                return Ok(HeaderWalk::Parsed(result));
            }
            HeaderType::MainArchive => {
                dispatch_header(&raw, data_offset, &mut result)?;
                // The QuickOpen cache can disagree with the physical headers,
                // so a caller that opted out gets the physical walk only.
                if options.allow_quick_open
                    && let Some(quick_open) =
                        try_parse_quick_open_headers(reader, &result, password, kdf_cache)?
                {
                    // This is the one path that answers from the cache, so it
                    // is the one path whose result is flagged cache-derived.
                    // `parse_quick_open_records` sets the flag where it builds
                    // the result; this pins that it did.
                    debug_assert!(
                        quick_open.headers_from_quick_open,
                        "headers answered from the QuickOpen cache must be flagged as such"
                    );
                    return Ok(HeaderWalk::Parsed(quick_open));
                }
                common::skip_data_area(reader, &raw)?;
            }
            _ => {
                dispatch_header(&raw, data_offset, &mut result)?;
                common::skip_data_area(reader, &raw)?;
            }
        }
    }
}

/// Parse headers from an encrypted archive (after the encryption header).
///
/// Each encrypted header has its own layout:
///   [16-byte IV] [header data padded to 16-byte boundary]
/// The header data is AES-256-CBC encrypted using the archive key and per-header IV.
fn parse_encrypted_headers<R: Read + Seek>(
    reader: &mut R,
    key: &[u8; 32],
    result: &mut ParsedHeaders,
) -> RarResult<()> {
    loop {
        let header_start = reader.stream_position().map_err(RarError::Io)?;

        // Read per-header 16-byte IV.
        let mut iv = [0u8; 16];
        match reader.read_exact(&mut iv) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("reached EOF reading encrypted header IV");
                break;
            }
            Err(e) => return Err(RarError::Io(e)),
        }

        // Read and decrypt first AES block (16 bytes) to determine header size.
        let mut block0 = [0u8; 16];
        reader.read_exact(&mut block0).map_err(RarError::Io)?;

        let mut decryptor = crate::crypto::CbcDecryptor::new(key, &iv);
        let mut dec0 = block0;
        decryptor.decrypt_blocks(&mut dec0);

        // Parse CRC32 (4 bytes LE) and header_size vint from decrypted data.
        let stored_crc = u32::from_le_bytes(dec0[0..4].try_into().unwrap());
        let (header_size, vint_len) = match vint::read_vint(&dec0[4..]) {
            Ok(v) => v,
            Err(_) => {
                debug!(
                    "failed to parse header_size vint in encrypted header — likely end of headers"
                );
                break;
            }
        };

        if header_size == 0 {
            debug!(
                "zero header size in encrypted header at offset {header_start} — likely end of headers"
            );
            break;
        }

        common::validate_header_size(header_start, header_size, vint_len)?;

        // Total header bytes = CRC(4) + vint_len + body(header_size).
        let total = 4 + vint_len + header_size as usize;
        let aligned = (total + 15) & !15;

        // Read and decrypt remaining blocks if needed.
        let mut decrypted = Vec::with_capacity(aligned);
        decrypted.extend_from_slice(&dec0);

        if aligned > 16 {
            let remaining = aligned - 16;
            let mut more = vec![0u8; remaining];
            reader.read_exact(&mut more).map_err(RarError::Io)?;
            decryptor.decrypt_blocks(&mut more);
            decrypted.extend_from_slice(&more);
        }

        // Extract the body (header_size bytes after CRC + vint).
        let body_start = 4 + vint_len;
        let body_end = body_start + header_size as usize;
        if body_end > decrypted.len() {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "encrypted header body extends beyond decrypted data ({body_end} > {})",
                    decrypted.len()
                ),
            });
        }
        let body = decrypted[body_start..body_end].to_vec();

        // CRC32 check over header_size vint encoding + body.
        let vint_encoded = common::vint_encode_for_crc(header_size, vint_len);
        let computed_crc = {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&vint_encoded);
            hasher.update(&body);
            hasher.finalize()
        };

        if computed_crc != stored_crc {
            debug!(
                "CRC mismatch in encrypted header at offset {} (expected {:#x}, got {:#x}) — likely wrong password",
                header_start, stored_crc, computed_crc
            );
            return Err(RarError::HeaderCrcMismatch {
                expected: stored_crc,
                actual: computed_crc,
            });
        }

        // Build RawHeader from decrypted data.
        let raw = common::parse_raw_header_from_parts(
            header_start,
            stored_crc,
            header_size,
            vint_len,
            body,
        )?;

        debug!(
            "encrypted header type={:?} flags={:#x} size={} data_size={} at offset={}",
            raw.header_type, raw.flags, raw.header_size, raw.data_area_size, raw.offset
        );

        // Data offset: past the aligned encrypted header block, in the file stream.
        let data_offset = header_start + 16 + aligned as u64;

        match raw.header_type {
            HeaderType::EndArchive => {
                let end = end_archive::parse(&raw)?;
                debug!("end of archive: more_volumes={}", end.more_volumes);
                result.end = Some(end);
                break;
            }
            _ => {
                dispatch_header(&raw, data_offset, result)?;
                // Skip data area (not part of the encrypted header block).
                // Via `common::skip_data_area` so the `i64` range check applies
                // here too: `data_area_size` is an unbounded vint, and a value
                // above `i64::MAX` would otherwise seek the scan *backwards*
                // (the RAR4 shape of this bug is fuzz reproducer
                // `timeout-a8693f23`).
                common::skip_data_area(reader, &raw)?;
            }
        }
    }
    Ok(())
}

/// Dispatch a parsed header to the appropriate type-specific handler.
fn dispatch_header(raw: &RawHeader, data_offset: u64, result: &mut ParsedHeaders) -> RarResult<()> {
    match raw.header_type {
        HeaderType::MainArchive => {
            let main = main_archive::parse(raw)?;
            debug!(
                "main archive: volume={} solid={} vol_num={:?}",
                main.is_volume, main.is_solid, main.volume_number
            );
            result.main = Some(main);
        }
        HeaderType::File => {
            let mut file_hdr = file::parse(raw, data_offset)?;
            let (is_encrypted, file_encryption, hash, redirection, owner) =
                apply_extra_records(raw, extra::ExtraAreaOwner::File, &mut file_hdr);
            debug!(
                "file: name={:?} size={:?} method={:?} encrypted={}",
                file_hdr.name, file_hdr.unpacked_size, file_hdr.compression.method, is_encrypted
            );
            result.files.push(ParsedFile {
                header: file_hdr,
                is_encrypted,
                file_encryption,
                hash,
                redirection,
                owner,
            });
        }
        HeaderType::Service => {
            let svc = parse_service_from_raw(raw, data_offset)?;
            debug!("service: name={:?}", svc.header.service_name());
            result.services.push(svc);
        }
        HeaderType::Unknown(type_val) => {
            warn!("unknown header type {} at offset {}", type_val, raw.offset);
            if raw.flags & common::flags::SKIP_IF_UNKNOWN == 0 {
                return Err(RarError::CorruptArchive {
                    detail: format!("unknown header type {type_val} at offset {}", raw.offset),
                });
            }
        }
        // Encryption and EndArchive are handled by the caller.
        _ => {}
    }
    Ok(())
}

fn try_parse_quick_open_headers<R: Read + Seek>(
    reader: &mut R,
    parsed: &ParsedHeaders,
    password: Option<&str>,
    kdf_cache: &crate::crypto::KdfCache,
) -> RarResult<Option<ParsedHeaders>> {
    let Some(main) = parsed.main.as_ref() else {
        return Ok(None);
    };
    let Some(quick_open_offset) = main.quick_open_offset else {
        return Ok(None);
    };

    let restore_pos = reader.stream_position().map_err(RarError::Io)?;
    let attempt =
        parse_quick_open_headers_at(reader, quick_open_offset, main.clone(), password, kdf_cache);
    reader
        .seek(SeekFrom::Start(restore_pos))
        .map_err(RarError::Io)?;

    match attempt {
        Ok(parsed) => Ok(parsed),
        Err(error) => {
            debug!(
                "RAR5 QuickOpen at offset {} was unusable; falling back to full header scan: {}",
                quick_open_offset, error
            );
            Ok(None)
        }
    }
}

fn parse_quick_open_headers_at<R: Read + Seek>(
    reader: &mut R,
    quick_open_offset: u64,
    main: main_archive::MainArchiveHeader,
    password: Option<&str>,
    kdf_cache: &crate::crypto::KdfCache,
) -> RarResult<Option<ParsedHeaders>> {
    reader
        .seek(SeekFrom::Start(quick_open_offset))
        .map_err(RarError::Io)?;
    let Some(qopen_raw) = common::read_raw_header(reader)? else {
        return Ok(None);
    };
    if qopen_raw.header_type != HeaderType::Service {
        return Ok(None);
    }

    let qopen_data_offset =
        qopen_raw.offset + 4 + qopen_raw.header_size_vint_len as u64 + qopen_raw.header_size;
    let qopen_service = parse_service_from_raw(&qopen_raw, qopen_data_offset)?;
    if qopen_service.header.service_name() != "QO" {
        return Ok(None);
    }
    if qopen_service.header.inner.compression.method != crate::types::CompressionMethod::Store {
        return Ok(None);
    }

    if qopen_service.is_encrypted {
        return parse_encrypted_quick_open_records(
            reader,
            &qopen_raw,
            &qopen_service,
            password,
            quick_open_offset,
            main,
            kdf_cache,
        );
    }

    let unpacked_size = qopen_service
        .header
        .inner
        .unpacked_size
        .unwrap_or(qopen_raw.data_area_size);

    parse_quick_open_records(
        reader,
        unpacked_size,
        qopen_raw.offset,
        quick_open_offset,
        main,
    )
}

fn parse_encrypted_quick_open_records<R: Read>(
    reader: &mut R,
    qopen_raw: &RawHeader,
    qopen_service: &ParsedService,
    password: Option<&str>,
    quick_open_offset: u64,
    main: main_archive::MainArchiveHeader,
    kdf_cache: &crate::crypto::KdfCache,
) -> RarResult<Option<ParsedHeaders>> {
    let Some(password) = password else {
        return Ok(None);
    };
    let Some(encryption) = qopen_service.file_encryption.as_ref() else {
        return Ok(None);
    };
    if encryption.version != 0 {
        return Ok(None);
    }
    if let Some(check_data) = encryption.check_data.as_ref()
        && !kdf_cache.verify_password_rar5(
            password,
            &encryption.salt,
            encryption.kdf_count,
            check_data,
        )
    {
        return Ok(None);
    }

    let unpacked_size = qopen_service
        .header
        .inner
        .unpacked_size
        .unwrap_or(qopen_raw.data_area_size);
    if !qopen_raw.data_area_size.is_multiple_of(16) {
        return Ok(None);
    }

    let mut key = kdf_cache.derive_key_rar5(password, &encryption.salt, encryption.kdf_count)?;
    let limited = reader.take(qopen_raw.data_area_size);
    let mut decrypted_reader =
        crate::crypto::DecryptingReader::new_rar5(limited, &key, &encryption.iv);
    key.zeroize();

    parse_quick_open_records(
        &mut decrypted_reader,
        unpacked_size,
        qopen_raw.offset,
        quick_open_offset,
        main,
    )
}

fn parse_quick_open_records<R: Read>(
    reader: &mut R,
    remaining: u64,
    qopen_header_offset: u64,
    quick_open_offset: u64,
    main: main_archive::MainArchiveHeader,
) -> RarResult<Option<ParsedHeaders>> {
    let mut remaining = remaining;
    let mut result = empty_parsed_headers();
    result.main = Some(main);
    // Every header this function appends is a cached copy, so the provenance
    // is fixed here at construction rather than at the return: the value is
    // then true of the result at every point it exists, encrypted `QO` block
    // included (that path decrypts into this same builder).
    result.headers_from_quick_open = true;

    while let Some(raw) = read_quick_open_record(reader, &mut remaining, qopen_header_offset)? {
        let data_offset = raw.offset + 4 + raw.header_size_vint_len as u64 + raw.header_size;
        match raw.header_type {
            HeaderType::Encryption => return Ok(None),
            HeaderType::EndArchive => {
                let end = end_archive::parse(&raw)?;
                result.end = Some(end);
                debug!(
                    "loaded {} files and {} services from RAR5 QuickOpen at offset {}",
                    result.files.len(),
                    result.services.len(),
                    quick_open_offset
                );
                return Ok(Some(result));
            }
            _ => dispatch_header(&raw, data_offset, &mut result)?,
        }
    }

    Ok(None)
}

fn read_quick_open_record<R: Read>(
    reader: &mut R,
    remaining: &mut u64,
    qopen_header_offset: u64,
) -> RarResult<Option<RawHeader>> {
    if *remaining == 0 {
        return Ok(None);
    }
    if *remaining < 5 {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen record is too short".into(),
        });
    }

    let mut stored_crc_bytes = [0u8; 4];
    read_quick_open_exact(reader, remaining, &mut stored_crc_bytes)?;
    let stored_crc = u32::from_le_bytes(stored_crc_bytes);
    let size_vint = read_quick_open_vint(reader, remaining)?;
    let (body_size, body_size_vint_len) = vint::read_vint(&size_vint)?;
    if body_size_vint_len != size_vint.len() || body_size == 0 {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen record has invalid body size".into(),
        });
    }
    common::validate_header_size(qopen_header_offset, body_size, body_size_vint_len)?;
    if body_size > common::MAX_HEADER_BODY {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "RAR5 QuickOpen record body size {} exceeds maximum {}",
                body_size,
                common::MAX_HEADER_BODY
            ),
        });
    }
    if body_size > *remaining {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "RAR5 QuickOpen record body size {} exceeds remaining payload {}",
                body_size, *remaining
            ),
        });
    }

    let body_len = usize::try_from(body_size).map_err(|_| RarError::CorruptArchive {
        detail: format!("RAR5 QuickOpen record body size {body_size} does not fit in memory"),
    })?;
    let mut body = vec![0u8; body_len];
    read_quick_open_exact(reader, remaining, &mut body)?;

    let computed_crc = {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&size_vint);
        hasher.update(&body);
        hasher.finalize()
    };
    if computed_crc != stored_crc {
        return Err(RarError::HeaderCrcMismatch {
            expected: stored_crc,
            actual: computed_crc,
        });
    }

    let mut pos = 0usize;
    let (_flags, read) = vint::read_vint(body.get(pos..).unwrap_or(&[]))?;
    pos += read;
    let (offset_from_qopen, read) = vint::read_vint(body.get(pos..).unwrap_or(&[]))?;
    pos += read;
    let (cached_header_size, read) = vint::read_vint(body.get(pos..).unwrap_or(&[]))?;
    pos += read;

    if cached_header_size > common::MAX_HEADER_BODY {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "RAR5 QuickOpen cached header size {} exceeds maximum {}",
                cached_header_size,
                common::MAX_HEADER_BODY
            ),
        });
    }
    let cached_len = usize::try_from(cached_header_size).map_err(|_| RarError::CorruptArchive {
        detail: format!(
            "RAR5 QuickOpen cached header size {cached_header_size} does not fit in memory"
        ),
    })?;
    let cached_end = pos
        .checked_add(cached_len)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR5 QuickOpen cached header length overflowed".into(),
        })?;
    if cached_end > body.len() {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen cached header extends beyond record body".into(),
        });
    }

    let original_offset = qopen_header_offset
        .checked_sub(offset_from_qopen)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: format!(
                "RAR5 QuickOpen offset {} exceeds QOpen header offset {}",
                offset_from_qopen, qopen_header_offset
            ),
        })?;
    parse_quick_open_cached_header(&body[pos..cached_end], original_offset).map(Some)
}

fn read_quick_open_exact<R: Read>(
    reader: &mut R,
    remaining: &mut u64,
    buf: &mut [u8],
) -> RarResult<()> {
    let len = u64::try_from(buf.len()).map_err(|_| RarError::CorruptArchive {
        detail: "RAR5 QuickOpen read length does not fit in u64".into(),
    })?;
    if len > *remaining {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen record exceeds service payload".into(),
        });
    }
    reader.read_exact(buf).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            RarError::CorruptArchive {
                detail: "truncated RAR5 QuickOpen payload".into(),
            }
        } else {
            RarError::Io(error)
        }
    })?;
    *remaining -= len;
    Ok(())
}

fn read_quick_open_vint<R: Read>(reader: &mut R, remaining: &mut u64) -> RarResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        if *remaining == 0 || bytes.len() >= 10 {
            return Err(RarError::CorruptArchive {
                detail: "truncated RAR5 QuickOpen vint".into(),
            });
        }
        let mut byte = [0u8; 1];
        read_quick_open_exact(reader, remaining, &mut byte)?;
        bytes.push(byte[0]);
        if byte[0] & 0x80 == 0 {
            return Ok(bytes);
        }
    }
}

fn parse_quick_open_cached_header(bytes: &[u8], offset: u64) -> RarResult<RawHeader> {
    if bytes.len() < 5 {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen cached header is too short".into(),
        });
    }
    let stored_crc = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let (header_size, header_size_vint_len) = vint::read_vint(&bytes[4..])?;
    if header_size == 0 {
        return Err(RarError::CorruptArchive {
            detail: format!("RAR5 QuickOpen cached header has invalid size {header_size}"),
        });
    }
    common::validate_header_size(offset, header_size, header_size_vint_len)?;
    let body_start = 4 + header_size_vint_len;
    let body_len = usize::try_from(header_size).map_err(|_| RarError::CorruptArchive {
        detail: format!("RAR5 QuickOpen cached header size {header_size} does not fit in memory"),
    })?;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR5 QuickOpen cached header body length overflowed".into(),
        })?;
    if body_end != bytes.len() {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 QuickOpen cached header size does not match record payload".into(),
        });
    }

    common::parse_raw_header_from_parts(
        offset,
        stored_crc,
        header_size,
        header_size_vint_len,
        bytes[body_start..body_end].to_vec(),
    )
}

pub(crate) fn parse_service_from_raw(
    raw: &RawHeader,
    data_offset: u64,
) -> RarResult<ParsedService> {
    let mut svc = service::parse(raw, data_offset)?;
    let (is_encrypted, file_encryption, hash, _, _) =
        apply_extra_records(raw, extra::ExtraAreaOwner::Service, &mut svc.inner);
    Ok(ParsedService {
        header: svc,
        is_encrypted,
        file_encryption,
        hash,
    })
}

/// Extract encryption status, encryption params, BLAKE2 hash, and redirection info from extra records.
fn apply_extra_records(
    raw: &RawHeader,
    owner: extra::ExtraAreaOwner,
    header: &mut file::FileHeader,
) -> (
    bool,
    Option<FileEncryptionParams>,
    Option<crate::types::FileHash>,
    Option<Redirection>,
    Option<crate::types::UnixOwnerInfo>,
) {
    let Some(ea_bytes) = common::extra_area_bytes(raw) else {
        return (false, None, None, None, None);
    };
    let Ok(records) = extra::parse_extra_area(ea_bytes, owner) else {
        return (false, None, None, None, None);
    };

    let mut is_encrypted = false;
    let mut file_encryption = None;
    let mut hash = None;
    let mut redirection = None;
    let mut owner = None;

    for record in &records {
        match record {
            extra::ExtraRecord::FileEncryption {
                version,
                kdf_count,
                salt,
                iv,
                check_data,
                enc_flags,
                ..
            } => {
                is_encrypted = true;
                file_encryption = Some(FileEncryptionParams {
                    version: *version,
                    kdf_count: *kdf_count,
                    salt: *salt,
                    iv: *iv,
                    check_data: *check_data,
                    psw_check_present: enc_flags & extra::FHEXTRA_CRYPT_PSWCHECK != 0,
                    use_hash_mac: enc_flags & 0x0002 != 0,
                });
            }
            extra::ExtraRecord::FileHash(file_hash) => {
                hash = Some(file_hash.clone());
            }
            extra::ExtraRecord::FileTime {
                mtime,
                ctime,
                atime,
            } => {
                if let Some(value) = *mtime {
                    header.mtime = Some(value);
                }
                if let Some(value) = *ctime {
                    header.ctime = Some(value);
                }
                if let Some(value) = *atime {
                    header.atime = Some(value);
                }
            }
            extra::ExtraRecord::FileVersion { version } if *version != 0 => {
                header.version = Some(*version);
                header.name.push(';');
                header.name.push_str(&version.to_string());
            }
            extra::ExtraRecord::Redirection {
                redir_type,
                target,
                target_raw,
                target_is_directory,
            } => {
                redirection = Some(Redirection {
                    redir_type: RedirectionType::from(*redir_type),
                    target: target.clone(),
                    target_raw: Some(target_raw.clone()),
                    target_is_directory: *target_is_directory,
                });
            }
            extra::ExtraRecord::UnixOwner { owner: unix_owner } => {
                owner = Some(unix_owner.clone());
            }
            extra::ExtraRecord::ServiceData(data) => {
                header.service_subdata = Some(data.clone());
            }
            _ => {}
        }
    }

    (is_encrypted, file_encryption, hash, redirection, owner)
}

/// Get extra records for a file header from its raw header's extra area.
pub fn parse_file_extra_records(raw: &RawHeader) -> RarResult<Vec<extra::ExtraRecord>> {
    if let Some(ea_bytes) = common::extra_area_bytes(raw) {
        let owner = if raw.header_type == HeaderType::Service {
            extra::ExtraAreaOwner::Service
        } else {
            extra::ExtraAreaOwner::File
        };
        extra::parse_extra_area(ea_bytes, owner)
    } else {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_aes256_cbc_for_test;

    const RAR5_SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\0";

    fn fixture_path(parts: &[&str]) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for part in parts {
            path.push(part);
        }
        path
    }

    #[test]
    fn rar5_hp_encrypted_headers_use_shared_kdf_cache() {
        let path = fixture_path(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"]);
        let data = std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read checked-in fixture {}: {err}",
                path.display()
            )
        });
        let cache = crate::crypto::KdfCache::new();
        assert_eq!(cache.rar5_cached_entry_count(), 0);

        let mut cursor = std::io::Cursor::new(data);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed =
            parse_all_headers_with_kdf_cache(&mut cursor, Some("secretpass"), &cache).unwrap();

        assert!(parsed.is_encrypted);
        assert!(!parsed.files.is_empty());
        assert!(
            cache.rar5_cached_entry_count() > 0,
            "encrypted RAR5 header parsing should populate the caller-provided KDF cache"
        );
    }

    /// A type-4 archive encryption header, built the way a `-hp` writer does.
    fn build_test_crypt_header(kdf_count: u8, salt: [u8; 16], check: Option<[u8; 8]>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(0)); // AES-256.
        body.extend_from_slice(&vint::encode_vint(u64::from(check.is_some())));
        body.push(kdf_count);
        body.extend_from_slice(&salt);
        if let Some(check) = check {
            body.extend_from_slice(&check);
            body.extend_from_slice(&crate::crypto::sha256_digest(&check)[..4]);
        }
        build_test_raw_header(4, 0, &body, &[], None)
    }

    /// The E4 surfacing: the type-4 record comes out with no password, and
    /// `parse_all_headers` still refuses exactly as it did.
    ///
    /// Held against a synthetic header rather than only the fixture so the
    /// *values* can be pinned: a `parse_header_encryption` that returned a
    /// default-constructed record would pass a `.is_some()` test and fail this
    /// one, and a caller proving password candidates against a defaulted salt
    /// would verify the first thing it tried.
    #[test]
    fn header_encryption_record_is_readable_with_no_password() {
        let salt = [0x27u8; 16];
        let check = [0x91u8; 8];
        let mut image = RAR5_SIGNATURE.to_vec();
        image.extend_from_slice(&build_test_crypt_header(11, salt, Some(check)));
        // Whatever follows is ciphertext to a reader with no key; the walk must
        // stop at the record above without touching it.
        image.extend_from_slice(&[0xEE; 256]);

        let mut cursor = std::io::Cursor::new(image.clone());
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let surfaced = parse_header_encryption(&mut cursor)
            .expect("the type-4 record is plaintext")
            .expect("a `-hp` stream states one");
        assert_eq!(surfaced.kdf_count, 11);
        assert_eq!(surfaced.salt, salt);
        assert!(surfaced.has_password_check);
        assert_eq!(
            surfaced.check_data.map(|data| data[..8].to_vec()),
            Some(check.to_vec())
        );

        // Unchanged behaviour for the ordinary entry point.
        let mut cursor = std::io::Cursor::new(image);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        assert!(matches!(
            parse_all_headers(&mut cursor, None),
            Err(RarError::EncryptedArchive)
        ));
    }

    /// A stream with no type-4 record answers `None` — the non-vacuity for the
    /// test above, and the answer every `-p` archive gives.
    #[test]
    fn a_stream_without_archive_encryption_surfaces_no_record() {
        let mut image = RAR5_SIGNATURE.to_vec();
        image.extend_from_slice(&build_test_raw_header(
            1,
            0,
            &vint::encode_vint(0),
            &[],
            None,
        ));
        image.extend_from_slice(&build_test_file_header("member.bin", 0, 0));

        let mut cursor = std::io::Cursor::new(image);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        assert!(parse_header_encryption(&mut cursor).unwrap().is_none());
    }

    /// The KDF ceiling is the crate's, and a record over it is an **error**,
    /// never `None`.
    ///
    /// `lg2_count` is the archive's claim, so an unbounded one lets a hostile
    /// post decide how much PBKDF2 a password-candidate loop runs.
    /// [`crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX`] bounds it before the salt is
    /// even read. Flattening the refusal to `None` would be the dangerous
    /// shape: a caller would read it as "not header-encrypted" and keep waiting
    /// for a layout that is never coming.
    #[test]
    fn an_archive_kdf_count_over_the_ceiling_refuses_rather_than_reporting_none() {
        let mut image = RAR5_SIGNATURE.to_vec();
        image.extend_from_slice(&build_test_crypt_header(
            crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX + 1,
            [0x27; 16],
            None,
        ));

        let mut cursor = std::io::Cursor::new(image);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        assert!(matches!(
            parse_header_encryption(&mut cursor),
            Err(RarError::UnsupportedEncryptionKdf { count, max })
                if count == crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX + 1
                    && max == crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX
        ));

        // At the ceiling it is accepted, so the refusal above is the bound
        // discriminating rather than the record never parsing.
        let mut image = RAR5_SIGNATURE.to_vec();
        image.extend_from_slice(&build_test_crypt_header(
            crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX,
            [0x27; 16],
            None,
        ));
        let mut cursor = std::io::Cursor::new(image);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        assert_eq!(
            parse_header_encryption(&mut cursor)
                .unwrap()
                .map(|record| record.kdf_count),
            Some(crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX)
        );
    }

    fn build_test_extra_record(record_type: u64, body: &[u8]) -> Vec<u8> {
        let type_bytes = vint::encode_vint(record_type);
        let mut out = Vec::new();
        out.extend_from_slice(&vint::encode_vint((type_bytes.len() + body.len()) as u64));
        out.extend_from_slice(&type_bytes);
        out.extend_from_slice(body);
        out
    }

    fn build_test_raw_header(
        header_type: u64,
        common_flags: u64,
        type_body: &[u8],
        extra: &[u8],
        data_area_size: Option<u64>,
    ) -> Vec<u8> {
        let mut flags = common_flags;
        if !extra.is_empty() {
            flags |= common::flags::EXTRA_AREA;
        }
        if data_area_size.is_some() {
            flags |= common::flags::DATA_AREA;
        }

        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(header_type));
        body.extend_from_slice(&vint::encode_vint(flags));
        if !extra.is_empty() {
            body.extend_from_slice(&vint::encode_vint(extra.len() as u64));
        }
        if let Some(data_area_size) = data_area_size {
            body.extend_from_slice(&vint::encode_vint(data_area_size));
        }
        body.extend_from_slice(type_body);
        body.extend_from_slice(extra);

        let size = vint::encode_vint(body.len() as u64);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&size);
        hasher.update(&body);
        let crc = hasher.finalize();

        let mut out = Vec::new();
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(&body);
        out
    }

    fn build_test_main_with_qopen_locator(qopen_offset_from_main: u64) -> Vec<u8> {
        let mut locator_body = Vec::new();
        locator_body.extend_from_slice(&vint::encode_vint(0x01)); // LOCATOR_QLIST.
        locator_body.extend_from_slice(&vint::encode_vint(qopen_offset_from_main));
        let extra = build_test_extra_record(0x01, &locator_body); // LOCATOR.
        build_test_raw_header(1, 0, &vint::encode_vint(0), &extra, None)
    }

    fn build_test_file_header(name: &str, unpacked_size: u64, data_size: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(0)); // file flags.
        body.extend_from_slice(&vint::encode_vint(unpacked_size));
        body.extend_from_slice(&vint::encode_vint(0)); // attributes.
        body.extend_from_slice(&vint::encode_vint(0)); // RAR5 Store.
        body.extend_from_slice(&vint::encode_vint(1)); // Unix host OS.
        body.extend_from_slice(&vint::encode_vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        build_test_raw_header(2, 0, &body, &[], Some(data_size))
    }

    fn build_test_end_header() -> Vec<u8> {
        build_test_raw_header(5, 0, &vint::encode_vint(0), &[], None)
    }

    fn build_test_qopen_service(payload: &[u8]) -> Vec<u8> {
        build_test_qopen_service_with_sizes(payload.len() as u64, payload.len() as u64)
    }

    fn build_test_qopen_service_with_sizes(unpacked_size: u64, data_area_size: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(0)); // service flags.
        body.extend_from_slice(&vint::encode_vint(unpacked_size));
        body.extend_from_slice(&vint::encode_vint(0)); // attributes.
        body.extend_from_slice(&vint::encode_vint(0)); // RAR5 Store.
        body.extend_from_slice(&vint::encode_vint(1)); // Unix host OS.
        body.extend_from_slice(&vint::encode_vint(2));
        body.extend_from_slice(b"QO");
        build_test_raw_header(3, 0, &body, &[], Some(data_area_size))
    }

    fn build_test_encrypted_qopen_service(
        plaintext_payload: &[u8],
        encrypted_payload: &[u8],
        salt: &[u8; 16],
        iv: &[u8; 16],
        kdf_count: u8,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(0)); // service flags.
        body.extend_from_slice(&vint::encode_vint(plaintext_payload.len() as u64));
        body.extend_from_slice(&vint::encode_vint(0)); // attributes.
        body.extend_from_slice(&vint::encode_vint(0)); // RAR5 Store.
        body.extend_from_slice(&vint::encode_vint(1)); // Unix host OS.
        body.extend_from_slice(&vint::encode_vint(2));
        body.extend_from_slice(b"QO");

        let mut encryption_body = Vec::new();
        encryption_body.extend_from_slice(&vint::encode_vint(0)); // encryption version.
        encryption_body.extend_from_slice(&vint::encode_vint(0)); // encryption flags.
        encryption_body.push(kdf_count);
        encryption_body.extend_from_slice(salt);
        encryption_body.extend_from_slice(iv);
        let extra = build_test_extra_record(extra::record_type::FILE_ENCRYPTION, &encryption_body);

        build_test_raw_header(3, 0, &body, &extra, Some(encrypted_payload.len() as u64))
    }

    fn build_test_qopen_record(
        qopen_header_offset: u64,
        original_header_offset: u64,
        cached_header: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vint::encode_vint(0)); // flags, unused here.
        body.extend_from_slice(&vint::encode_vint(
            qopen_header_offset - original_header_offset,
        ));
        body.extend_from_slice(&vint::encode_vint(cached_header.len() as u64));
        body.extend_from_slice(cached_header);

        let size = vint::encode_vint(body.len() as u64);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&size);
        hasher.update(&body);
        let crc = hasher.finalize();

        let mut out = Vec::new();
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(&body);
        out
    }

    fn build_test_qopen_record_with_raw_size(size: &[u8], body: &[u8]) -> Vec<u8> {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(size);
        hasher.update(body);
        let crc = hasher.finalize();

        let mut out = Vec::new();
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(size);
        out.extend_from_slice(body);
        out
    }

    fn encrypt_first_cbc_block(key: &[u8; 32], iv: &[u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
        encrypt_aes256_cbc_for_test(key, iv, &plaintext)
            .try_into()
            .expect("single AES block encrypt returns one block")
    }

    fn encrypt_cbc_blocks(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let padded_len = if plaintext.is_empty() {
            0
        } else {
            plaintext.len().div_ceil(16) * 16
        };
        let mut padded = plaintext.to_vec();
        padded.resize(padded_len, 0);
        encrypt_aes256_cbc_for_test(key, iv, &padded)
    }

    #[test]
    fn quick_open_cached_headers_are_used_without_scanning_data_area() {
        let qopen_offset = 256u64;
        let cached_file_offset = 96u64;
        let cached_end_offset = 160u64;

        let cached_file = build_test_file_header("cached.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_file_offset,
            &cached_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_end_offset,
            &cached_end,
        ));

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&build_test_main_with_qopen_locator(qopen_offset - 8));
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_qopen_service(&qopen_payload));
        archive.extend_from_slice(&qopen_payload);

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, None).unwrap();

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].header.name, "cached.bin");
        assert_eq!(
            parsed.files[0].header.data_offset,
            cached_file_offset + cached_file.len() as u64
        );
        assert!(parsed.end.is_some());
    }

    #[test]
    fn quick_open_uses_unpacked_size_not_data_area_size_like_rar_behavior() {
        let qopen_offset = 256u64;
        let cached_file_offset = 96u64;
        let cached_end_offset = 160u64;

        let cached_file = build_test_file_header("cached.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_file_offset,
            &cached_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_end_offset,
            &cached_end,
        ));
        let valid_qopen_len = qopen_payload.len() as u64;
        qopen_payload.extend_from_slice(b"trailing bytes outside QO UnpSize");

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&build_test_main_with_qopen_locator(qopen_offset - 8));
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_qopen_service_with_sizes(
            valid_qopen_len,
            qopen_payload.len() as u64,
        ));
        archive.extend_from_slice(&qopen_payload);

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, None).unwrap();

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].header.name, "cached.bin");
        assert!(parsed.end.is_some());
    }

    #[test]
    fn quick_open_record_size_vint_longer_than_three_bytes_is_rejected_like_rar_behavior() {
        let size = [0x81, 0x80, 0x80, 0x00];
        let record = build_test_qopen_record_with_raw_size(&size, &[0]);
        let mut cursor = std::io::Cursor::new(record.as_slice());
        let mut remaining = record.len() as u64;

        let result = read_quick_open_record(&mut cursor, &mut remaining, 256);

        assert!(
            matches!(result, Err(RarError::CorruptArchive { ref detail }) if detail.contains("header size vint")),
            "expected long QuickOpen record size vint to be rejected, got {result:?}"
        );
    }

    #[test]
    fn quick_open_cached_header_size_vint_longer_than_three_bytes_is_rejected_like_rar_behavior() {
        let size = [0x81, 0x80, 0x80, 0x00];
        let cached_header = build_test_qopen_record_with_raw_size(&size, &[0]);

        let result = parse_quick_open_cached_header(&cached_header, 96);

        assert!(
            matches!(result, Err(RarError::CorruptArchive { ref detail }) if detail.contains("header size vint")),
            "expected long cached header size vint to be rejected, got {result:?}"
        );
    }

    #[test]
    fn quick_open_crc_error_falls_back_to_physical_headers() {
        let qopen_offset = 256u64;
        let main = build_test_main_with_qopen_locator(qopen_offset - 8);
        let physical_file = build_test_file_header("physical.bin", 0, 0);
        let physical_end = build_test_end_header();

        let cached_end = build_test_end_header();
        let mut bad_qopen_record = build_test_qopen_record(qopen_offset, 160, &cached_end);
        *bad_qopen_record.last_mut().unwrap() ^= 0xff;

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&main);
        let physical_file_offset = archive.len() as u64;
        archive.extend_from_slice(&physical_file);
        archive.extend_from_slice(&physical_end);
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_qopen_service(&bad_qopen_record));
        archive.extend_from_slice(&bad_qopen_record);

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, None).unwrap();

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].header.name, "physical.bin");
        assert_eq!(
            parsed.files[0].header.data_offset,
            physical_file_offset + physical_file.len() as u64
        );
        assert!(parsed.end.is_some());
    }

    /// Build an archive whose QuickOpen cache disagrees with its physical
    /// headers: the `QO` block faithfully echoes the one real member and then
    /// appends `forged.bin`, which no physical header describes.
    ///
    /// Returns the archive bytes and the data offset the physical walk should
    /// report for `physical.bin`.
    fn build_test_archive_with_forged_quick_open_member() -> (Vec<u8>, u64) {
        let qopen_offset = 256u64;
        let forged_file_offset = 160u64;
        let cached_end_offset = 200u64;

        let main = build_test_main_with_qopen_locator(qopen_offset - 8);
        let physical_file = build_test_file_header("physical.bin", 0, 0);
        let physical_end = build_test_end_header();
        let physical_file_offset = RAR5_SIGNATURE.len() as u64 + main.len() as u64;

        let forged_file = build_test_file_header("forged.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            physical_file_offset,
            &physical_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            forged_file_offset,
            &forged_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_end_offset,
            &cached_end,
        ));

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&main);
        archive.extend_from_slice(&physical_file);
        archive.extend_from_slice(&physical_end);
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_qopen_service(&qopen_payload));
        archive.extend_from_slice(&qopen_payload);

        (archive, physical_file_offset + physical_file.len() as u64)
    }

    fn parsed_file_names(parsed: &ParsedHeaders) -> Vec<&str> {
        parsed
            .files
            .iter()
            .map(|file| file.header.name.as_str())
            .collect()
    }

    #[test]
    fn header_parse_options_default_keeps_quick_open_enabled() {
        assert!(
            HeaderParseOptions::default().allow_quick_open,
            "the hand-written Default must preserve QuickOpen, not fall back to bool's false"
        );
    }

    #[test]
    fn quick_open_records_that_disagree_with_physical_headers_are_adopted_by_default() {
        let (archive, _) = build_test_archive_with_forged_quick_open_member();

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, None).unwrap();

        // Pins today's default: a clean QuickOpen cache wins outright, so a
        // member present only in the `QO` block is reported as if it were real.
        assert_eq!(parsed_file_names(&parsed), ["physical.bin", "forged.bin"]);
        assert!(parsed.end.is_some());
        assert!(
            parsed.headers_from_quick_open,
            "headers taken from the cache must say so"
        );
    }

    /// Build an archive whose `QO` block is shaped the way `rar` actually
    /// writes one: file records only, with no cached end-of-archive record to
    /// terminate them. Alongside it sits a complete physical header chain.
    ///
    /// The cached member deliberately carries a different name from the
    /// physical one. Real `rar` echoes the real headers faithfully, so this
    /// divergence is not realistic — it is what makes the assertion
    /// non-vacuous, by making a cache-derived answer visibly different from a
    /// physically walked one.
    ///
    /// Returns the archive bytes and the data offset the physical walk should
    /// report for `silver.horizon.mkv`.
    fn build_test_archive_with_end_less_quick_open_cache() -> (Vec<u8>, u64) {
        let qopen_offset = 256u64;
        let cached_file_offset = 160u64;

        let main = build_test_main_with_qopen_locator(qopen_offset - 8);
        let physical_file = build_test_file_header("silver.horizon.mkv", 0, 0);
        let physical_end = build_test_end_header();
        let physical_file_offset = RAR5_SIGNATURE.len() as u64 + main.len() as u64;

        let cached_file = build_test_file_header("silver.horizon.nfo", 4, 4);
        let qopen_payload = build_test_qopen_record(qopen_offset, cached_file_offset, &cached_file);

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&main);
        archive.extend_from_slice(&physical_file);
        archive.extend_from_slice(&physical_end);
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_qopen_service(&qopen_payload));
        archive.extend_from_slice(&qopen_payload);

        (archive, physical_file_offset + physical_file.len() as u64)
    }

    #[test]
    fn quick_open_cache_without_an_end_record_is_rejected_and_reports_physical_provenance() {
        let (archive, physical_data_offset) = build_test_archive_with_end_less_quick_open_cache();

        let mut cursor = std::io::Cursor::new(archive.clone());
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, None).unwrap();

        // The shape every real `rar`-written archive has: the cache is there,
        // it is well formed, and it is still refused for want of an end
        // record — so the walk that produced these headers was the physical
        // one, and the flag must not claim otherwise.
        assert_eq!(parsed_file_names(&parsed), ["silver.horizon.mkv"]);
        assert_eq!(parsed.files[0].header.data_offset, physical_data_offset);
        assert!(parsed.end.is_some());
        assert!(
            !parsed.headers_from_quick_open,
            "a rejected cache leaves the result physically walked"
        );

        // A locator is present all the same, which is exactly why the locator
        // cannot stand in for provenance.
        assert!(
            parsed
                .main
                .as_ref()
                .is_some_and(|main| main.quick_open_offset.is_some()),
            "non-vacuity: this archive really does carry a QuickOpen locator"
        );

        // And the headers are the ones an opted-out parse returns, field for
        // field on the parts a caller routes bytes by.
        let mut opted_out = std::io::Cursor::new(archive);
        opted_out
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let physical = parse_all_headers_with_options(
            &mut opted_out,
            None,
            HeaderParseOptions {
                allow_quick_open: false,
            },
        )
        .unwrap();
        assert_eq!(parsed_file_names(&parsed), parsed_file_names(&physical));
        assert_eq!(
            parsed
                .files
                .iter()
                .map(|file| (file.header.data_offset, file.header.data_size))
                .collect::<Vec<_>>(),
            physical
                .files
                .iter()
                .map(|file| (file.header.data_offset, file.header.data_size))
                .collect::<Vec<_>>()
        );
        assert!(!physical.headers_from_quick_open);
    }

    #[test]
    fn volume_facts_carry_quick_open_provenance_rather_than_locator_presence() {
        let (adopted_archive, _) = build_test_archive_with_forged_quick_open_member();
        let adopted = crate::archive::RarArchive::parse_volume_facts(
            std::io::Cursor::new(adopted_archive),
            None,
        )
        .unwrap();
        assert!(adopted.headers_from_quick_open);

        let (rejected_archive, _) = build_test_archive_with_end_less_quick_open_cache();
        let rejected = crate::archive::RarArchive::parse_volume_facts(
            std::io::Cursor::new(rejected_archive),
            None,
        )
        .unwrap();
        assert!(
            !rejected.headers_from_quick_open,
            "facts from a rejected cache are physically walked"
        );

        // Both volumes carry a locator, so the two facts differ only in
        // provenance — the distinction the field exists to draw.
        assert!(adopted.quick_open_offset.is_some());
        assert!(rejected.quick_open_offset.is_some());
    }

    #[test]
    fn quick_open_can_be_disabled_so_only_physical_headers_are_returned() {
        let (archive, physical_data_offset) = build_test_archive_with_forged_quick_open_member();

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers_with_options(
            &mut cursor,
            None,
            HeaderParseOptions {
                allow_quick_open: false,
            },
        )
        .unwrap();

        assert_eq!(parsed_file_names(&parsed), ["physical.bin"]);
        assert_eq!(parsed.files[0].header.data_offset, physical_data_offset);
        assert!(parsed.end.is_some());
        assert!(
            !parsed.headers_from_quick_open,
            "an opted-out parse is physical even where a usable cache exists"
        );
    }

    #[test]
    fn encrypted_quick_open_uses_password_and_avoids_physical_scan() {
        let qopen_offset = 512u64;
        let cached_file_offset = 96u64;
        let cached_end_offset = 160u64;

        let cached_file = build_test_file_header("encrypted-cached.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_file_offset,
            &cached_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_end_offset,
            &cached_end,
        ));

        let password = "quick-open-pass";
        let salt = [0x41; 16];
        let iv = [0x82; 16];
        let kdf_count = 4;
        let (key, _) = crate::crypto::derive_key(password, &salt, kdf_count).unwrap();
        let encrypted_payload = encrypt_cbc_blocks(&key, &iv, &qopen_payload);

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&build_test_main_with_qopen_locator(qopen_offset - 8));
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_encrypted_qopen_service(
            &qopen_payload,
            &encrypted_payload,
            &salt,
            &iv,
            kdf_count,
        ));
        archive.extend_from_slice(&encrypted_payload);

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let cache = crate::crypto::KdfCache::new();
        assert_eq!(cache.rar5_cached_entry_count(), 0);
        let parsed = parse_all_headers_with_kdf_cache(&mut cursor, Some(password), &cache).unwrap();

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].header.name, "encrypted-cached.bin");
        assert_eq!(
            parsed.files[0].header.data_offset,
            cached_file_offset + cached_file.len() as u64
        );
        assert!(parsed.end.is_some());
        assert!(
            parsed.headers_from_quick_open,
            "an encrypted cache is still a cache"
        );
        assert!(
            cache.rar5_cached_entry_count() > 0,
            "encrypted QuickOpen should use the caller-provided RAR5 KDF cache"
        );
    }

    #[test]
    fn encrypted_quick_open_streams_data_area_above_header_body_cap() {
        let qopen_offset = 512u64;
        let cached_file_offset = 96u64;
        let cached_end_offset = 160u64;

        let cached_file = build_test_file_header("large-encrypted-qo.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_file_offset,
            &cached_file,
        ));
        qopen_payload.extend_from_slice(&build_test_qopen_record(
            qopen_offset,
            cached_end_offset,
            &cached_end,
        ));

        let password = "quick-open-pass";
        let salt = [0x15; 16];
        let iv = [0x96; 16];
        let kdf_count = 4;
        let (key, _) = crate::crypto::derive_key(password, &salt, kdf_count).unwrap();
        let mut encrypted_payload = encrypt_cbc_blocks(&key, &iv, &qopen_payload);
        encrypted_payload.resize(common::MAX_HEADER_BODY as usize + 16, 0);

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&build_test_main_with_qopen_locator(qopen_offset - 8));
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_encrypted_qopen_service(
            &qopen_payload,
            &encrypted_payload,
            &salt,
            &iv,
            kdf_count,
        ));
        archive.extend_from_slice(&encrypted_payload);

        let mut cursor = std::io::Cursor::new(archive);
        cursor
            .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
            .unwrap();
        let parsed = parse_all_headers(&mut cursor, Some(password)).unwrap();

        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].header.name, "large-encrypted-qo.bin");
        assert_eq!(
            parsed.files[0].header.data_offset,
            cached_file_offset + cached_file.len() as u64
        );
        assert!(parsed.end.is_some());
    }

    #[test]
    fn encrypted_quick_open_without_or_wrong_password_falls_back_to_physical_headers() {
        let qopen_offset = 512u64;
        let main = build_test_main_with_qopen_locator(qopen_offset - 8);
        let physical_file = build_test_file_header("physical.bin", 0, 0);
        let physical_end = build_test_end_header();

        let cached_file = build_test_file_header("encrypted-cached.bin", 4, 4);
        let cached_end = build_test_end_header();
        let mut qopen_payload = Vec::new();
        qopen_payload.extend_from_slice(&build_test_qopen_record(qopen_offset, 96, &cached_file));
        qopen_payload.extend_from_slice(&build_test_qopen_record(qopen_offset, 160, &cached_end));

        let password = "quick-open-pass";
        let salt = [0x23; 16];
        let iv = [0x64; 16];
        let kdf_count = 4;
        let (key, _) = crate::crypto::derive_key(password, &salt, kdf_count).unwrap();
        let encrypted_payload = encrypt_cbc_blocks(&key, &iv, &qopen_payload);

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR5_SIGNATURE);
        archive.extend_from_slice(&main);
        let physical_file_offset = archive.len() as u64;
        archive.extend_from_slice(&physical_file);
        archive.extend_from_slice(&physical_end);
        archive.resize(qopen_offset as usize, 0);
        archive.extend_from_slice(&build_test_encrypted_qopen_service(
            &qopen_payload,
            &encrypted_payload,
            &salt,
            &iv,
            kdf_count,
        ));
        archive.extend_from_slice(&encrypted_payload);

        for supplied_password in [None, Some("wrong-pass")] {
            let mut cursor = std::io::Cursor::new(archive.clone());
            cursor
                .seek(SeekFrom::Start(RAR5_SIGNATURE.len() as u64))
                .unwrap();
            let parsed = parse_all_headers(&mut cursor, supplied_password).unwrap();

            assert_eq!(parsed.files.len(), 1);
            assert_eq!(parsed.files[0].header.name, "physical.bin");
            assert_eq!(
                parsed.files[0].header.data_offset,
                physical_file_offset + physical_file.len() as u64
            );
            assert!(parsed.end.is_some());
            assert!(
                !parsed.headers_from_quick_open,
                "an unopenable encrypted cache leaves the result physically walked"
            );
        }
    }

    #[test]
    fn encrypted_header_size_above_cap_is_rejected() {
        let oversized = common::MAX_HEADER_BODY + 1;
        let size_vint = vint::encode_vint(oversized);

        let mut decrypted = [0u8; 16];
        decrypted[4..4 + size_vint.len()].copy_from_slice(&size_vint);

        let key = [0u8; 32];
        let iv = [0u8; 16];
        let ciphertext = encrypt_first_cbc_block(&key, &iv, decrypted);

        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&ciphertext);

        let mut cursor = std::io::Cursor::new(payload);
        let mut parsed = ParsedHeaders {
            main: None,
            files: Vec::new(),
            services: Vec::new(),
            encryption: None,
            end: None,
            is_encrypted: true,
            headers_from_quick_open: false,
        };

        let result = parse_encrypted_headers(&mut cursor, &key, &mut parsed);
        assert!(
            matches!(result, Err(RarError::CorruptArchive { ref detail }) if detail.contains("header size vint")),
            "expected non-canonical header-size vint to be rejected, got: {result:?}"
        );
    }
}
