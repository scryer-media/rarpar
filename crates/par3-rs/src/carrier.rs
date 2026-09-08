//! Explicit recovery-carrier reconstruction from authenticated packet layouts.

use crate::runtime::{EngineFile as File, OpenBudgeted};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::fft::{FftCodec, FftGeometry};
use crate::gf::Field;
use crate::ingest::{IngestedPacket, PayloadKind};
use crate::packet::{PacketBody, PacketHeader, PacketType};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::session::{Par3RepairSession, block_range};
use crate::{Fingerprint, FingerprintHasher, InputSetId};

enum Entry {
    Metadata(Vec<u8>),
    Payload {
        kind: PayloadKind,
        length: u64,
        expected: Option<Fingerprint>,
    },
}

/// Whether output restores an authenticated original layout or is a new carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierRestoration {
    /// Every original packet boundary, order, length and fingerprint is known.
    Exact,
    /// The caller explicitly requested a valid replacement carrier.
    Replacement,
}

/// Retained manifest and resource plan for one carrier.
pub struct CarrierPlan {
    id: InputSetId,
    entries: Vec<Entry>,
    restoration: CarrierRestoration,
    bytes: u64,
    scratch_rows: usize,
    _reservation: Reservation,
}

/// Successful reconstruction, with no claim of exact restoration for replacements.
#[derive(Debug)]
pub struct CarrierReport {
    /// Explicit destination installed after validation.
    pub path: PathBuf,
    /// Exact original or explicitly requested replacement.
    pub restoration: CarrierRestoration,
    /// Distinct recovery packets regenerated.
    pub recovery_packets: usize,
}

impl CarrierPlan {
    /// Capture a complete, ordered sequence of authenticated packets from one
    /// carrier. Gaps, trailing bytes, mixed sources and incomplete captures are
    /// refused; filenames never supply missing layout information.
    pub fn capture(packets: &[IngestedPacket], options: &ExecutionOptions) -> EngineResult<Self> {
        let end = packets
            .first()
            .ok_or(EngineError::InvalidState("empty carrier capture"))?
            .origin()
            .snapshot
            .len;
        Self::capture_range(packets, 0..end, options)
    }

    pub(crate) fn capture_range(
        packets: &[IngestedPacket],
        range: std::ops::Range<u64>,
        options: &ExecutionOptions,
    ) -> EngineResult<Self> {
        options.validate()?;
        let first = packets
            .first()
            .ok_or(EngineError::InvalidState("empty carrier capture"))?;
        let origin = first.origin();
        if range.start >= range.end || range.end > origin.snapshot.len {
            return Err(EngineError::InvalidState("invalid carrier capture range"));
        }
        let mut next = range.start;
        let mut cost = 0usize;
        for packet in packets {
            let at = packet.origin();
            if !at.same_carrier(&origin)
                || at.offset != next
                || packet.input_set_id() != first.input_set_id()
            {
                return Err(EngineError::InvalidState(
                    "carrier layout is incomplete or ambiguous",
                ));
            }
            next = next
                .checked_add(at.length)
                .ok_or(EngineError::ResourceLimit("carrier length"))?;
            cost = cost
                .checked_add(packet.metadata().map_or(512, |packet| {
                    (packet.len() as usize)
                        .saturating_mul(2)
                        .saturating_add(512)
                }))
                .ok_or(EngineError::ResourceLimit("carrier manifest"))?;
        }
        if next != range.end {
            return Err(EngineError::InvalidState(
                "carrier capture does not cover its full length",
            ));
        }
        if cost > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained carrier manifest"));
        }
        let reservation = options.memory.reserve(cost)?;
        let entries: Vec<Entry> = packets
            .iter()
            .map(|packet| match (packet.metadata(), packet.payload()) {
                (Some(metadata), _) => Entry::Metadata(metadata.to_bytes()),
                (_, Some(payload)) => Entry::Payload {
                    kind: payload.kind(),
                    length: payload.len(),
                    expected: Some(packet.hash()),
                },
                _ => unreachable!("authenticated packet kind"),
            })
            .collect();
        Ok(Self {
            id: first.input_set_id(),
            scratch_rows: Self::count_recovery(&entries),
            entries,
            restoration: CarrierRestoration::Exact,
            bytes: next - range.start,
            _reservation: reservation,
        })
    }

    /// Explicitly request a valid replacement with selected indices from an
    /// authenticated matrix. This never claims restoration of an unknown layout.
    pub fn replacement(
        session: &mut Par3RepairSession,
        matrix: Fingerprint,
        indices: &[u64],
    ) -> EngineResult<Self> {
        Self::replacement_inner(session, matrix, indices, false)
    }

    pub(crate) fn replacement_preserving(
        session: &mut Par3RepairSession,
        matrix: Fingerprint,
        indices: &[u64],
    ) -> EngineResult<Self> {
        Self::replacement_inner(session, matrix, indices, true)
    }

    fn replacement_inner(
        session: &mut Par3RepairSession,
        matrix: Fingerprint,
        indices: &[u64],
        preserve: bool,
    ) -> EngineResult<Self> {
        session.assess()?;
        let set = session
            .set
            .as_ref()
            .ok_or(EngineError::InvalidState("metadata is incomplete"))?;
        if !set
            .matrix_packets()
            .iter()
            .any(|packet| packet.hash() == matrix)
        {
            return Err(EngineError::InvalidState("unknown replacement matrix"));
        }
        let cost = session
            .input
            .retained_bytes()
            .checked_add(
                indices
                    .len()
                    .checked_mul(512)
                    .ok_or(EngineError::ResourceLimit("replacement indices"))?,
            )
            .ok_or(EngineError::ResourceLimit("replacement manifest"))?;
        if cost > session.options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained replacement manifest"));
        }
        let reservation = session.options.memory.reserve(cost)?;
        let mut entries: Vec<Entry> = session
            .input
            .packets()
            .filter_map(|packet| {
                packet
                    .metadata()
                    .map(|packet| Entry::Metadata(packet.to_bytes()))
            })
            .collect();
        if preserve {
            for payload in session.input.payloads() {
                entries.push(Entry::Payload {
                    kind: payload.kind(),
                    length: payload.len(),
                    expected: Some(payload.packet_hash()),
                });
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for &index in indices {
            if !seen.insert(index) {
                return Err(EngineError::InvalidState(
                    "duplicate replacement recovery index",
                ));
            }
            let kind = PayloadKind::Recovery {
                root: set.root_hash(),
                matrix,
                index,
            };
            if entries.iter().any(
                |entry| matches!(entry, Entry::Payload { kind: existing, .. } if *existing == kind),
            ) {
                continue;
            }
            entries.push(Entry::Payload {
                kind,
                length: set.block_size(),
                expected: None,
            });
        }
        let bytes = entries
            .iter()
            .try_fold(0u64, |sum, entry| {
                sum.checked_add(match entry {
                    Entry::Metadata(bytes) => bytes.len() as u64,
                    Entry::Payload { length, kind, .. } => {
                        length.checked_add(if matches!(kind, PayloadKind::Data { .. }) {
                            56
                        } else {
                            88
                        })?
                    }
                })
            })
            .ok_or(EngineError::ResourceLimit("replacement length"))?;
        Ok(Self {
            id: set.input_set_id(),
            scratch_rows: Self::count_recovery(&entries),
            entries,
            restoration: CarrierRestoration::Replacement,
            bytes,
            _reservation: reservation,
        })
    }

    /// Exact final carrier size.
    #[must_use]
    pub fn output_bytes(&self) -> u64 {
        self.bytes
    }
    /// How the resulting carrier may be described to the caller.
    #[must_use]
    pub fn restoration(&self) -> CarrierRestoration {
        self.restoration
    }

    /// Required scratch bytes for recovery equations. Data packets are read
    /// directly from verified logical blocks and need no recovery scratch.
    pub fn scratch_bytes(&self, block_size: u64) -> EngineResult<u64> {
        block_size
            .checked_mul(self.scratch_rows as u64)
            .ok_or(EngineError::ResourceLimit("carrier scratch size"))
    }

    fn count_recovery(entries: &[Entry]) -> usize {
        // Construction already reserves the manifest and indexing workspace.
        // Requirement queries must allocate nothing, including concurrent calls.
        let unique: std::collections::BTreeSet<_> = entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Payload {
                    kind: PayloadKind::Recovery { matrix, index, .. },
                    ..
                } => Some((*matrix, *index)),
                _ => None,
            })
            .collect();
        unique.len()
    }

    /// Rebuild into a separate destination. All required logical source blocks
    /// must already be verified or available through authenticated Data packets.
    /// Exact captures require every regenerated packet hash to match the original.
    pub fn execute(
        &self,
        session: &mut Par3RepairSession,
        destination: &Path,
        scratch_directory: &Path,
    ) -> EngineResult<CarrierReport> {
        let mut progress = session.options.stage(crate::runtime::Stage::Carrier)?;
        let assessment = session.assess()?;
        if !assessment.lost_blocks.is_empty() {
            return Err(EngineError::InvalidState(
                "reconstruct source blocks before regenerating recovery",
            ));
        }
        let set = session
            .set
            .as_ref()
            .ok_or(EngineError::InvalidState("metadata is incomplete"))?;
        if set.input_set_id() != self.id {
            return Err(EngineError::InvalidState(
                "carrier belongs to another input set",
            ));
        }
        if session.options.open_handles < 3 {
            return Err(EngineError::ResourceLimit(
                "carrier reconstruction requires three handles",
            ));
        }
        if destination.try_exists()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "carrier destination exists",
            )
            .into());
        }
        let _reuse_memory = session.options.memory.reserve(
            self.entries
                .len()
                .checked_mul(256)
                .ok_or(EngineError::ResourceLimit("carrier reuse map"))?,
        )?;
        let mut reusable = BTreeMap::new();
        for entry in &self.entries {
            let Entry::Payload {
                expected: Some(hash),
                ..
            } = entry
            else {
                continue;
            };
            if reusable.contains_key(hash) {
                continue;
            }
            if let Some(payload) = session
                .input
                .packets()
                .find(|packet| packet.hash() == *hash)
                .and_then(|packet| packet.payload())
            {
                match payload.validate(&session.options) {
                    Ok(()) => {
                        reusable.insert(*hash, payload);
                    }
                    Err(
                        EngineError::Unavailable { .. }
                        | EngineError::SourceChanged { .. }
                        | EngineError::Format(crate::Par3Error::PacketHashMismatch { .. }),
                    ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let mut slots = BTreeMap::new();
        for entry in &self.entries {
            if let Entry::Payload {
                kind,
                length,
                expected,
            } = entry
            {
                if *length > set.block_size() {
                    return Err(EngineError::InvalidState(
                        "carrier payload exceeds block size",
                    ));
                }
                match *kind {
                    PayloadKind::Recovery {
                        root,
                        matrix,
                        index,
                    } => {
                        if root != set.root_hash() {
                            return Err(EngineError::InvalidState("carrier recovery root differs"));
                        }
                        if !expected.is_some_and(|hash| reusable.contains_key(&hash)) {
                            let next = slots.len();
                            slots.entry((matrix, index)).or_insert(next);
                        }
                    }
                    PayloadKind::Data { index } if index >= set.block_count() => {
                        return Err(EngineError::InvalidState(
                            "carrier Data index exceeds layout",
                        ));
                    }
                    PayloadKind::Data { .. } => {}
                }
            }
        }
        let _work = session.options.memory.reserve(
            slots
                .len()
                .checked_mul(256)
                .ok_or(EngineError::ResourceLimit("carrier equations"))?,
        )?;
        let scratch_file = crate::session_repair::ScratchFile::new(
            &scratch_directory.join("carrier-spool"),
            &session.options,
        )?;
        let mut scratch = OpenOptions::new()
            .read(true)
            .write(true)
            .open_budgeted(scratch_file.path(), &session.options)?;
        scratch.set_len(
            (slots.len() as u64)
                .checked_mul(set.block_size())
                .ok_or(EngineError::ResourceLimit("carrier scratch size"))?,
        )?;
        for matrix in slots
            .keys()
            .map(|key| key.0)
            .collect::<std::collections::BTreeSet<_>>()
        {
            let packet = set
                .matrix_packets()
                .iter()
                .find(|packet| packet.hash() == matrix)
                .ok_or(EngineError::InvalidState(
                    "carrier matrix metadata is unavailable",
                ))?;
            match packet.body() {
                PacketBody::CauchyMatrix(description) => {
                    let range = block_range(description.range, set.block_count())?;
                    let _field =
                        session
                            .options
                            .memory
                            .reserve(if set.galois_field().size == 2 {
                                512 << 10
                            } else {
                                4096
                            })?;
                    match crate::gf::for_set(&set.galois_field())? {
                        crate::gf::AnyField::Gf8(field) => {
                            encode_cauchy(session, matrix, range, &slots, &mut scratch, field)?
                        }
                        crate::gf::AnyField::Gf16(field) => {
                            encode_cauchy(session, matrix, range, &slots, &mut scratch, field)?
                        }
                    }
                }
                PacketBody::FftMatrix(description) => {
                    let range = block_range(description.range, set.block_count())?;
                    let cohorts = description
                        .interleave
                        .checked_add(1)
                        .ok_or(EngineError::InvalidState("carrier cohort overflow"))?;
                    let geometry = FftGeometry::new(
                        (range.end - range.start).div_ceil(cohorts),
                        description.max_recovery_blocks_log2,
                    )?;
                    geometry.validate_field(set.galois_field())?;
                    let stripe = session.options.stripe_bytes.min(64 << 10);
                    let _buffer = session.options.memory.reserve(stripe)?;
                    let mut covered = vec![0; stripe];
                    let mut options = session.options.clone();
                    options.stripe_bytes = stripe;
                    let codec = FftCodec::new(geometry, options)?;
                    let mut groups = BTreeMap::<u64, Vec<u64>>::new();
                    for &(hash, index) in slots.keys() {
                        if hash == matrix {
                            groups
                                .entry(index % cohorts)
                                .or_default()
                                .push(index / cohorts);
                        }
                    }
                    for (cohort, indices) in groups {
                        let first =
                            range.start + (cohort + cohorts - range.start % cohorts) % cohorts;
                        let begin = *indices.first().expect("cohort indices") as usize;
                        let end = *indices.last().expect("cohort indices") as usize + 1;
                        codec.encode(
                            set.block_size(),
                            begin,
                            end - begin,
                            |index, offset, out| {
                                let block = first + index as u64 * cohorts;
                                if block >= range.end {
                                    out.fill(0);
                                    Ok(())
                                } else {
                                    session.read_block(
                                        block,
                                        offset,
                                        out,
                                        &mut covered[..out.len()],
                                    )
                                }
                            },
                            |index, offset, bytes| {
                                if let Some(slot) =
                                    slots.get(&(matrix, cohort + index as u64 * cohorts))
                                {
                                    scratch.seek(SeekFrom::Start(
                                        *slot as u64 * set.block_size() + offset,
                                    ))?;
                                    scratch.write_all(bytes)?;
                                }
                                Ok(())
                            },
                        )?;
                    }
                }
                _ => return Err(EngineError::Unsupported("carrier matrix execution")),
            }
        }
        let output_file = crate::session_repair::ScratchFile::new(destination, &session.options)?;
        let temporary = output_file.path();
        let mut out = OpenOptions::new()
            .write(true)
            .open_budgeted(temporary, &session.options)?;
        let stripe = session.options.stripe_bytes.min(64 << 10);
        let _buffers = session.options.memory.reserve(
            stripe
                .checked_mul(2)
                .and_then(|n| n.checked_add(512))
                .ok_or(EngineError::ResourceLimit("carrier output buffers"))?,
        )?;
        let mut bytes = vec![0; stripe];
        let mut covered = vec![0; stripe];
        for entry in &self.entries {
            session.options.cancel.check()?;
            let Entry::Payload {
                kind,
                length,
                expected,
            } = entry
            else {
                if let Entry::Metadata(bytes) = entry {
                    out.write_all(bytes)?;
                }
                continue;
            };
            let mut prefix = Vec::new();
            let packet_type = match *kind {
                PayloadKind::Data { index } => {
                    prefix.extend_from_slice(&index.to_le_bytes());
                    PacketType::Data
                }
                PayloadKind::Recovery {
                    root,
                    matrix,
                    index,
                } => {
                    prefix.extend_from_slice(&root);
                    prefix.extend_from_slice(&matrix);
                    prefix.extend_from_slice(&index.to_le_bytes());
                    PacketType::RecoveryData
                }
            };
            let mut header = PacketHeader {
                hash: [0; 16],
                length: 48 + prefix.len() as u64 + length,
                input_set_id: self.id,
                packet_type,
            };
            let mut encoded = Vec::with_capacity(48);
            header.write(&mut encoded);
            let mut hash = FingerprintHasher::new();
            hash.update(&encoded[24..]);
            hash.update(&prefix);
            for pass in 0..2 {
                if pass == 1 {
                    header.hash = hash.finalize();
                    if expected.is_some_and(|expected| expected != header.hash) {
                        return Err(EngineError::InvalidState(
                            "regenerated packet differs from authenticated original",
                        ));
                    }
                    encoded.clear();
                    header.write(&mut encoded);
                    out.write_all(&encoded)?;
                    out.write_all(&prefix)?;
                }
                let mut offset = 0;
                while offset < *length {
                    session.options.cancel.check()?;
                    let take = (length - offset).min(stripe as u64) as usize;
                    if let Some(payload) = expected.and_then(|hash| reusable.get(&hash)) {
                        if payload.read_at(offset, &mut bytes[..take])? != take {
                            return Err(EngineError::InvalidState("reused carrier payload length"));
                        }
                    } else {
                        match *kind {
                            PayloadKind::Data { index } => session.read_block(
                                index,
                                offset,
                                &mut bytes[..take],
                                &mut covered[..take],
                            )?,
                            PayloadKind::Recovery { matrix, index, .. } => {
                                scratch.seek(SeekFrom::Start(
                                    slots[&(matrix, index)] as u64 * set.block_size() + offset,
                                ))?;
                                scratch.read_exact(&mut bytes[..take])?;
                            }
                        }
                    }
                    if pass == 0 {
                        hash.update(&bytes[..take]);
                    } else {
                        out.write_all(&bytes[..take])?;
                        progress.advance(take as u64);
                    }
                    offset += take as u64;
                }
            }
        }
        out.sync_all()?;
        drop(out);
        if std::fs::metadata(temporary)?.len() != self.bytes {
            return Err(EngineError::InvalidState("rebuilt carrier length differs"));
        }
        session.options.cancel.check()?;
        std::fs::hard_link(temporary, destination)?;
        drop(scratch);
        Ok(CarrierReport {
            path: destination.to_owned(),
            restoration: self.restoration,
            recovery_packets: slots.len(),
        })
    }
}

fn encode_cauchy<F: Field>(
    session: &Par3RepairSession,
    matrix: Fingerprint,
    range: std::ops::Range<u64>,
    slots: &BTreeMap<(Fingerprint, u64), usize>,
    scratch: &mut File,
    field: F,
) -> EngineResult<()> {
    let _progress = session.options.stage(crate::runtime::Stage::Encode)?;
    let set = session.set.as_ref().expect("prepared set");
    let stripe = session.options.stripe_bytes.min(64 << 10);
    let stripe = stripe / F::SYMBOL_BYTES * F::SYMBOL_BYTES;
    if stripe == 0 || !set.block_size().is_multiple_of(F::SYMBOL_BYTES as u64) {
        return Err(EngineError::InvalidState("carrier field alignment"));
    }
    let _buffers = session.options.memory.reserve(
        stripe
            .checked_mul(3)
            .ok_or(EngineError::ResourceLimit("carrier encoding stripes"))?,
    )?;
    let mut input = vec![0; stripe];
    let mut covered = vec![0; stripe];
    let mut output = vec![0; stripe];
    for (&(hash, index), &slot) in slots {
        if hash != matrix {
            continue;
        }
        let mut offset = 0;
        while offset < set.block_size() {
            let take = (set.block_size() - offset).min(stripe as u64) as usize;
            output.fill(0);
            for block in range.clone() {
                session.options.cancel.check()?;
                session.read_block(block, offset, &mut input[..take], &mut covered[..take])?;
                let factor = crate::cauchy::element(&field, block, index)?;
                field.mul_acc(&mut output[..take], &input[..take], factor);
            }
            scratch.seek(SeekFrom::Start(slot as u64 * set.block_size() + offset))?;
            scratch.write_all(&output[..take])?;
            offset += take as u64;
        }
    }
    Ok(())
}
