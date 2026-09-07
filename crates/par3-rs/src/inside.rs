//! Container boundary inspection for explicit PAR-inside operations.
//!
//! This module does not decompress members. It validates the framing needed to
//! preserve archive bytes and refuses ambiguous trailing data before planning
//! insertion. Container checksums are not PAR3 verification evidence.

use std::ops::Range;

use crc_fast::{CrcAlgorithm, Digest};

use crate::runtime::{EngineError, EngineResult, ExecutionOptions};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};

/// Supported standalone container framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerKind {
    /// Single-disk ZIP with a conventional end record.
    Zip,
    /// Single-disk ZIP with ZIP64 end records.
    Zip64,
    /// 7z signature header and checked next-header range.
    SevenZip,
}

/// Work limits for container inspection, independent of archive member sizes.
#[derive(Clone, Debug)]
pub struct ContainerLimits {
    /// Maximum central-directory entries to inspect.
    pub entries: u64,
    /// Cumulative header bytes read, including repeated boundary probes.
    pub read_bytes: u64,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            entries: 1_000_000,
            read_bytes: 64 << 20,
        }
    }
}

/// Validated original framing, bound to a source generation.
#[derive(Clone, Debug)]
pub struct ContainerLayout {
    kind: ContainerKind,
    source: SourceId,
    snapshot: SourceSnapshot,
    footer: Range<u64>,
    read_bytes: u64,
}

impl ContainerLayout {
    /// Inspect a plain archive before insertion. Multi-disk ZIP, self-extracting
    /// wrappers, unknown trailing data, and malformed framing are refused.
    /// Compressed members remain opaque; this is not an archive content test.
    pub fn inspect(
        access: &dyn SourceAccess,
        source: SourceId,
        options: &ExecutionOptions,
        limits: &ContainerLimits,
    ) -> EngineResult<Self> {
        options.validate()?;
        let snapshot = access.snapshot(source)?.ok_or(EngineError::Unavailable {
            source_id: source,
            offset: 0,
        })?;
        let mut reader = Inspector {
            access,
            source,
            snapshot,
            options,
            remaining: limits.read_bytes,
        };
        let mut signature = [0; 8];
        reader.read(0, &mut signature)?;
        let (kind, footer) = if signature[..6] == *b"7z\xbc\xaf\x27\x1c" {
            reader.seven_zip()?
        } else if signature[..4] == *b"PK\x03\x04"
            || signature[..4] == *b"PK\x05\x06"
            || signature[..4] == *b"PK\x06\x06"
        {
            reader.zip(limits.entries)?
        } else {
            return Err(EngineError::Unsupported(
                "container signature or self-extracting wrapper",
            ));
        };
        ensure_snapshot(access, source, snapshot)?;
        Ok(Self {
            kind,
            source,
            snapshot,
            footer,
            read_bytes: limits.read_bytes - reader.remaining,
        })
    }

    /// Detected container format.
    pub fn kind(&self) -> ContainerKind {
        self.kind
    }
    /// Original source identity.
    pub fn source(&self) -> SourceId {
        self.source
    }
    /// Generation and length which were inspected.
    pub fn snapshot(&self) -> SourceSnapshot {
        self.snapshot
    }
    /// ZIP footer group to duplicate after embedded protection. Empty for 7z.
    pub fn footer(&self) -> Range<u64> {
        self.footer.clone()
    }
    /// Actual header bytes read by inspection.
    pub fn read_bytes(&self) -> u64 {
        self.read_bytes
    }
}

struct Inspector<'a> {
    access: &'a dyn SourceAccess,
    source: SourceId,
    snapshot: SourceSnapshot,
    options: &'a ExecutionOptions,
    remaining: u64,
}

fn unsupported() -> EngineError {
    EngineError::Unsupported("malformed or ambiguous container layout")
}
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("fixed field"))
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed field"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed field"))
}

impl Inspector<'_> {
    fn read(&mut self, at: u64, bytes: &mut [u8]) -> EngineResult<()> {
        self.options.cancel.check()?;
        if at
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.snapshot.len)
        {
            return Err(unsupported());
        }
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .ok_or(EngineError::ResourceLimit("container inspection bytes"))?;
        read_exact_at(self.access, self.source, at, bytes)
    }

    fn seven_zip(&mut self) -> EngineResult<(ContainerKind, Range<u64>)> {
        let mut header = [0; 32];
        self.read(0, &mut header)?;
        if header[6] != 0 {
            return Err(EngineError::Unsupported("7z major version"));
        }
        let mut crc = Digest::new(CrcAlgorithm::Crc32IsoHdlc);
        crc.update(&header[12..]);
        if crc.finalize() as u32 != u32_at(&header, 8) {
            return Err(unsupported());
        }
        let at = 32u64
            .checked_add(u64_at(&header, 12))
            .ok_or_else(unsupported)?;
        let len = u64_at(&header, 20);
        if at.checked_add(len) != Some(self.snapshot.len) {
            return Err(unsupported());
        }
        let size = self.options.stripe_bytes.min(64 << 10);
        let _memory = self.options.memory.reserve(size)?;
        let mut buffer = vec![0; size];
        let mut crc = Digest::new(CrcAlgorithm::Crc32IsoHdlc);
        let mut position = 0;
        while position < len {
            let take = (len - position).min(size as u64) as usize;
            self.read(at + position, &mut buffer[..take])?;
            if position == 0 && !matches!(buffer[0], 0x01 | 0x17) {
                return Err(unsupported());
            }
            crc.update(&buffer[..take]);
            position += take as u64;
        }
        if crc.finalize() as u32 != u32_at(&header, 28) {
            return Err(unsupported());
        }
        Ok((
            ContainerKind::SevenZip,
            self.snapshot.len..self.snapshot.len,
        ))
    }

    fn zip(&mut self, max_entries: u64) -> EngineResult<(ContainerKind, Range<u64>)> {
        let length = self.snapshot.len.min(65535 + 22) as usize;
        if length < 22 {
            return Err(unsupported());
        }
        let _memory = self.options.memory.reserve(length + 65536)?;
        let mut tail = vec![0; length];
        let base = self.snapshot.len - length as u64;
        self.read(base, &mut tail)?;
        let mut candidate = None;
        for offset in 0..=length - 22 {
            if tail[offset..offset + 4] == *b"PK\x05\x06"
                && offset + 22 + u16_at(&tail, offset + 20) as usize == length
                && candidate.replace(offset).is_some()
            {
                return Err(unsupported());
            }
        }
        let offset = candidate.ok_or_else(unsupported)?;
        let end = &tail[offset..];
        if u16_at(end, 4) != 0 || u16_at(end, 6) != 0 || u16_at(end, 8) != u16_at(end, 10) {
            return Err(unsupported());
        }
        let mut entries = u16_at(end, 10) as u64;
        let mut central_size = u32_at(end, 12) as u64;
        let mut central = u32_at(end, 16) as u64;
        let mut footer = base + offset as u64;
        let mut kind = ContainerKind::Zip;
        if entries == 65535 || central_size == u32::MAX as u64 || central == u32::MAX as u64 {
            let locator_at = footer.checked_sub(20).ok_or_else(unsupported)?;
            let mut locator = [0; 20];
            self.read(locator_at, &mut locator)?;
            if locator[..4] != *b"PK\x06\x07"
                || u32_at(&locator, 4) != 0
                || u32_at(&locator, 16) != 1
            {
                return Err(unsupported());
            }
            let record_at = u64_at(&locator, 8);
            let mut record = [0; 56];
            self.read(record_at, &mut record)?;
            if record[..4] != *b"PK\x06\x06"
                || u64_at(&record, 4) != 44
                || record_at.checked_add(56) != Some(locator_at)
                || u32_at(&record, 16) != 0
                || u32_at(&record, 20) != 0
                || u64_at(&record, 24) != u64_at(&record, 32)
            {
                return Err(unsupported());
            }
            let actual_entries = u64_at(&record, 32);
            let actual_size = u64_at(&record, 40);
            let actual_central = u64_at(&record, 48);
            if (entries != 65535 && entries != actual_entries)
                || (central_size != u32::MAX as u64 && central_size != actual_size)
                || (central != u32::MAX as u64 && central != actual_central)
            {
                return Err(unsupported());
            }
            entries = actual_entries;
            central_size = actual_size;
            central = actual_central;
            footer = record_at;
            kind = ContainerKind::Zip64;
        }
        if central.checked_add(central_size) != Some(footer) {
            return Err(unsupported());
        }
        if entries > max_entries {
            return Err(EngineError::ResourceLimit("ZIP directory entries"));
        }
        let mut at = central;
        let mut extra = vec![0; 65535];
        for _ in 0..entries {
            let mut record = [0; 46];
            self.read(at, &mut record)?;
            if record[..4] != *b"PK\x01\x02" || u16_at(&record, 34) != 0 {
                return Err(unsupported());
            }
            let name_len = u16_at(&record, 28) as u64;
            let extra_len = u16_at(&record, 30) as usize;
            let comment_len = u16_at(&record, 32) as u64;
            let next = at
                .checked_add(46 + name_len + extra_len as u64 + comment_len)
                .ok_or_else(unsupported)?;
            if next > footer {
                return Err(unsupported());
            }
            let mut local = u32_at(&record, 42) as u64;
            let mut compressed = u32_at(&record, 20) as u64;
            if local == u32::MAX as u64
                || compressed == u32::MAX as u64
                || u32_at(&record, 24) == u32::MAX
            {
                self.read(at + 46 + name_len, &mut extra[..extra_len])?;
                let mut cursor = 0;
                let mut found = false;
                while cursor + 4 <= extra_len {
                    let tag = u16_at(&extra, cursor);
                    let size = u16_at(&extra, cursor + 2) as usize;
                    cursor += 4;
                    if cursor + size > extra_len {
                        return Err(unsupported());
                    }
                    if tag == 1 {
                        if found {
                            return Err(unsupported());
                        }
                        found = true;
                        let payload = &extra[cursor..cursor + size];
                        let mut field = 0;
                        for (needed, target) in [
                            (u32_at(&record, 24) == u32::MAX, 0),
                            (compressed == u32::MAX as u64, 1),
                            (local == u32::MAX as u64, 2),
                        ] {
                            if needed {
                                if field + 8 > payload.len() {
                                    return Err(unsupported());
                                }
                                let value = u64_at(payload, field);
                                if target == 1 {
                                    compressed = value;
                                }
                                if target == 2 {
                                    local = value;
                                }
                                field += 8;
                            }
                        }
                    }
                    cursor += size;
                }
                if !found || cursor != extra_len {
                    return Err(unsupported());
                }
            }
            let mut local_header = [0; 30];
            self.read(local, &mut local_header)?;
            if local_header[..4] != *b"PK\x03\x04"
                || u16_at(&local_header, 8) != u16_at(&record, 10)
                || u16_at(&local_header, 6) != u16_at(&record, 8)
            {
                return Err(unsupported());
            }
            let payload = local
                .checked_add(
                    30 + u16_at(&local_header, 26) as u64 + u16_at(&local_header, 28) as u64,
                )
                .ok_or_else(unsupported)?;
            if payload
                .checked_add(compressed)
                .is_none_or(|end| end > central)
            {
                return Err(unsupported());
            }
            at = next;
        }
        if at != footer {
            return Err(unsupported());
        }
        Ok((kind, footer..self.snapshot.len))
    }
}
