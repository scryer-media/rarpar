//! Versioned evidence persistence; the host retains the digest in trusted storage.
use super::{ExtentVerdict, FileEvidence};
use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::source::{SourceId, SourceSnapshot};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"P3EV\x01\0\0\0";
const HEADER: usize = 73;

/// Versioned checkpoint produced from sealed evidence, with charged storage.
///
/// Keep `digest()` in a trusted host manifest bound to the job. The bytes may
/// then be stored elsewhere. The digest is an integrity anchor, not a signature:
/// recomputing it from untrusted replay bytes does not establish authenticity.
/// The engine separately checks the current layout, binding, length and source
/// generation on replay. Provider generations must remain meaningful after restart.
#[derive(Debug)]
pub struct EvidenceCheckpoint {
    bytes: Vec<u8>,
    digest: [u8; 32],
    _reservation: Reservation,
}

impl EvidenceCheckpoint {
    /// Stable versioned bytes; no partially hashed data or hasher internals.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Persist this value in trusted job metadata before trusting replay bytes.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Charged storage released when this checkpoint is dropped.
    pub fn retained_bytes(&self) -> usize {
        self._reservation.bytes()
    }
}

impl FileEvidence {
    /// Export complete verdicts for durable replay. Incomplete hashing work is
    /// not serialized. The host owns persistence and authenticity of the digest.
    pub fn checkpoint(&self, options: &ExecutionOptions) -> EngineResult<EvidenceCheckpoint> {
        let _progress = options.stage(crate::runtime::Stage::Checkpoint)?;
        let size = HEADER
            .checked_add(self.verdicts.len())
            .ok_or(EngineError::ResourceLimit("evidence checkpoint"))?;
        let cost = size
            .checked_add(256)
            .ok_or(EngineError::ResourceLimit("evidence checkpoint"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained evidence checkpoint"));
        }
        let reservation = options.memory.reserve(cost)?;
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.layout);
        for value in [
            self.file as u64,
            self.source.0,
            self.snapshot.generation,
            self.snapshot.len,
            self.expected_len,
            self.verdicts.len() as u64,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.push(match self.whole_matches {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        for verdict in self.verdicts.iter() {
            options.cancel.check()?;
            bytes.push(match verdict {
                ExtentVerdict::Unknown => 0,
                ExtentVerdict::Intact => 1,
                ExtentVerdict::Damaged => 2,
                ExtentVerdict::Unprotected => 3,
            });
        }
        let digest = digest(&bytes, options)?;
        Ok(EvidenceCheckpoint {
            bytes,
            digest,
            _reservation: reservation,
        })
    }

    pub(crate) fn from_checkpoint(
        bytes: &[u8],
        trusted_digest: [u8; 32],
        layout: &BlockLayout,
        options: &ExecutionOptions,
    ) -> EngineResult<Self> {
        let _progress = options.stage(crate::runtime::Stage::Checkpoint)?;
        if bytes.len() > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained evidence checkpoint"));
        }
        if digest(bytes, options)? != trusted_digest {
            return Err(EngineError::InvalidState(
                "evidence checkpoint digest mismatch",
            ));
        }
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err(EngineError::Unsupported("evidence checkpoint version"));
        }
        let number = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded header"));
        let file = usize::try_from(number(24))
            .map_err(|_| EngineError::InvalidState("checkpoint file index"))?;
        let count = usize::try_from(number(64))
            .map_err(|_| EngineError::ResourceLimit("checkpoint extents"))?;
        let description = layout
            .files
            .get(file)
            .ok_or(EngineError::InvalidState("checkpoint file index"))?;
        if bytes[8..24] != layout.identity
            || number(56) != description.len
            || count != description.extents.len()
            || bytes.len() - HEADER != count
        {
            return Err(EngineError::InvalidState(
                "checkpoint belongs to another layout",
            ));
        }
        let whole_matches = match bytes[72] {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(EngineError::InvalidState("checkpoint whole-file verdict")),
        };
        if whole_matches.is_some() && description.fingerprint == [0; 16] {
            return Err(EngineError::InvalidState(
                "checkpoint has no whole-file fingerprint",
            ));
        }
        let snapshot = SourceSnapshot {
            generation: number(40),
            len: number(48),
        };
        let cost = count
            .checked_mul(8)
            .and_then(|n| n.checked_add(4096))
            .ok_or(EngineError::ResourceLimit("verification evidence"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained verification evidence"));
        }
        let reservation = options.memory.reserve(cost)?;
        let mut verdicts = Vec::with_capacity(count);
        for (state, extent) in bytes[HEADER..].iter().zip(&description.extents) {
            options.cancel.check()?;
            let verdict = match state {
                0 => ExtentVerdict::Unknown,
                1 => ExtentVerdict::Intact,
                2 => ExtentVerdict::Damaged,
                3 => ExtentVerdict::Unprotected,
                _ => return Err(EngineError::InvalidState("checkpoint extent verdict")),
            };
            if matches!(extent.kind, ExtentKind::Unprotected)
                != (verdict == ExtentVerdict::Unprotected)
                || (verdict == ExtentVerdict::Intact && extent.range.end > snapshot.len)
            {
                return Err(EngineError::InvalidState(
                    "checkpoint extent contradicts layout",
                ));
            }
            verdicts.push(verdict);
        }
        Ok(Self {
            layout: layout.identity,
            file,
            source: SourceId(number(32)),
            snapshot,
            verdicts: verdicts.into(),
            whole_matches,
            expected_len: description.len,
            _reservation: Arc::new(reservation),
        })
    }
}

fn digest(bytes: &[u8], options: &ExecutionOptions) -> EngineResult<[u8; 32]> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 engine evidence checkpoint digest v1\0");
    for part in bytes.chunks(64 << 10) {
        options.cancel.check()?;
        hash.update(part);
    }
    Ok(*hash.finalize().as_bytes())
}
