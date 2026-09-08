//! Explicit self-repair from an authenticated embedded carrier manifest.

use crate::runtime::{EngineFile as File, OpenBudgeted};
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{ContainerKind, ContainerLayout, ContainerLimits};
use crate::Fingerprint;
use crate::carrier::CarrierPlan;
use crate::ingest::IngestedPacket;
use crate::layout::ExtentKind;
use crate::packet::PacketBody;
use crate::runtime::{EngineError, EngineResult};
use crate::session::Par3RepairSession;
use crate::source::{DiskSourceAccess, SourceAccess, SourceId, SourceSnapshot};

/// A known embedded packet layout. Capture it while all packet boundaries are
/// available, then retain it across missing carrier ranges and source changes.
/// Missing packet order or lengths cannot be inferred from a volume filename.
pub struct SelfRepairPlan {
    carrier: CarrierPlan,
    identity: Fingerprint,
    gap: Range<u64>,
    length: u64,
    limits: ContainerLimits,
}

/// A separately installed, verified archive with its original packet layout.
#[derive(Debug)]
pub struct SelfRepairReport {
    /// Destination explicitly selected by the caller.
    pub path: PathBuf,
    /// Container framing validated after reconstruction.
    pub kind: ContainerKind,
    /// Lost logical blocks reconstructed, counting aliases once.
    pub reconstructed_blocks: u64,
    /// Distinct recovery packets regenerated from verified source blocks.
    pub recovery_packets: usize,
}

impl SelfRepairPlan {
    /// Capture all authenticated packets in their original carrier order.
    /// The session supplies the authenticated File layout. Only a single-file,
    /// single-gap, Cauchy insertion layout is accepted. Archive framing is checked
    /// after protected data reconstruction, so damaged headers can be repaired.
    pub fn capture(
        session: &mut Par3RepairSession,
        packets: &[IngestedPacket],
        limits: ContainerLimits,
    ) -> EngineResult<Self> {
        let layout = session
            .layout()?
            .ok_or(EngineError::InvalidState("incomplete embedded metadata"))?;
        let set = session.set.as_ref().expect("resolved set");
        if layout.files.len() != 1
            || set
                .matrix_packets()
                .iter()
                .any(|packet| !matches!(packet.body(), PacketBody::CauchyMatrix(_)))
        {
            return Err(EngineError::Unsupported(
                "embedded single-file Cauchy layout",
            ));
        }
        let file = &layout.files[0];
        let mut gaps = file
            .extents
            .iter()
            .filter(|extent| matches!(extent.kind, ExtentKind::Unprotected));
        let gap = gaps
            .next()
            .ok_or(EngineError::InvalidState(
                "embedded layout has no packet gap",
            ))?
            .range
            .clone();
        if gaps.next().is_some() || gap.start == 0 || gap.end > file.len {
            return Err(EngineError::Unsupported("ambiguous embedded packet gaps"));
        }
        if packets
            .iter()
            .any(|packet| packet.input_set_id() != set.input_set_id())
        {
            return Err(EngineError::InvalidState(
                "embedded packets belong to another set",
            ));
        }
        let carrier = CarrierPlan::capture_range(packets, gap.clone(), &session.options)?;
        Ok(Self {
            carrier,
            identity: layout.identity,
            gap,
            length: file.len,
            limits,
        })
    }

    /// Full staged archive bytes required before installation.
    pub fn output_bytes(&self) -> u64 {
        self.length
    }

    /// Auxiliary carrier and equation scratch, excluding the staged archive.
    pub fn scratch_bytes(&self, block_size: u64) -> EngineResult<u64> {
        self.carrier
            .scratch_bytes(block_size)?
            .checked_add(self.carrier.output_bytes())
            .ok_or(EngineError::ResourceLimit("self-repair scratch size"))
    }

    /// Restore to an absent destination, preserving the authenticated original
    /// packet bytes. The source remains read-only. An unknown original packet
    /// layout must be handled as an explicitly requested replacement carrier.
    pub fn execute(
        &self,
        session: &mut Par3RepairSession,
        destination: &Path,
        scratch_directory: &Path,
    ) -> EngineResult<SelfRepairReport> {
        let layout = session
            .layout()?
            .ok_or(EngineError::InvalidState("incomplete embedded metadata"))?;
        if layout.identity != self.identity {
            return Err(EngineError::InvalidState("self-repair layout changed"));
        }
        match std::fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "self-repair output exists",
                )
                .into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let options = session.options.clone();
        options.validate()?;
        let size = options.stripe_bytes.min(64 << 10);
        let _buffer = options.memory.reserve(size + 4096)?;
        let mut buffer = vec![0; size];
        let staging = crate::session_repair::ScratchFile::new(destination, &options)?;
        let temporary = staging.path().to_owned();
        // Reserve a unique scratch name; installation remains exclusive if
        // another caller independently creates the derived carrier path.
        let scratch_marker = crate::session_repair::ScratchFile::new(
            &scratch_directory.join("self-repair"),
            &options,
        )?;
        let carrier_output = scratch_marker.path().with_extension("carrier");
        let mut carrier_installed = false;
        let result = (|| {
            let reconstructed_blocks = crate::session_repair::stage_embedded(session, &temporary)?;
            let mut disk = DiskSourceAccess::with_options(options.clone());
            disk.insert(SourceId(0), temporary.clone());
            let disk = Arc::new(disk);
            let mut verified = Par3RepairSession::new(
                session.set.as_ref().expect("set").input_set_id(),
                disk.clone(),
                options.clone(),
            )?;
            // Recovery packets may be preserved after reauthentication. Data
            // regeneration consumes only the newly verified archive.
            for packet in session.input.packets().filter(|packet| {
                packet.metadata().is_some()
                    || packet.payload().is_some_and(|payload| {
                        matches!(payload.kind(), crate::ingest::PayloadKind::Recovery { .. })
                    })
            }) {
                verified.merge(packet.clone())?;
            }
            verified.bind_file(&layout.files[0].path, SourceId(0))?;
            if !verified.assess()?.files[0].complete {
                return Err(EngineError::InvalidState(
                    "rebuilt embedded data is incomplete",
                ));
            }
            let prefix = Prefix {
                access: disk.as_ref(),
                length: self.gap.start,
            };
            let container = ContainerLayout::inspect(&prefix, SourceId(0), &options, &self.limits)?;
            let footer = container.footer();
            if self.length - self.gap.end != footer.end - footer.start {
                return Err(EngineError::Unsupported(
                    "embedded footer duplication length",
                ));
            }
            let report = self
                .carrier
                .execute(&mut verified, &carrier_output, scratch_directory)?;
            carrier_installed = true;
            let mut carrier = File::open(&carrier_output, &options)?;
            let mut output = OpenOptions::new()
                .read(true)
                .write(true)
                .open_budgeted(&temporary, &options)?;
            output.seek(SeekFrom::Start(self.gap.start))?;
            let mut remaining = self.gap.end - self.gap.start;
            while remaining != 0 {
                options.cancel.check()?;
                let take = remaining.min(size as u64) as usize;
                carrier.read_exact(&mut buffer[..take])?;
                output.write_all(&buffer[..take])?;
                remaining -= take as u64;
            }
            output.sync_all()?;
            drop(output);
            // Filling unprotected bytes changes the disk generation; verify the
            // installed candidate again against the protected layout and footer.
            let proof = crate::evidence::verify_source(
                layout.clone(),
                0,
                disk.as_ref(),
                SourceId(0),
                &options,
            )?;
            if !proof.protected_complete() {
                return Err(EngineError::InvalidState(
                    "self-repair final verification failed",
                ));
            }
            let mut at = 0;
            let mut duplicate = [0u8; 4096];
            while at < footer.end - footer.start {
                options.cancel.check()?;
                let take =
                    (footer.end - footer.start - at).min(size.min(duplicate.len()) as u64) as usize;
                crate::source::read_exact_at(
                    disk.as_ref(),
                    SourceId(0),
                    footer.start + at,
                    &mut buffer[..take],
                )?;
                crate::source::read_exact_at(
                    disk.as_ref(),
                    SourceId(0),
                    self.gap.end + at,
                    &mut duplicate[..take],
                )?;
                if buffer[..take] != duplicate[..take] {
                    return Err(EngineError::Unsupported(
                        "embedded ZIP footer differs from original",
                    ));
                }
                at += take as u64;
            }
            options.cancel.check()?;
            std::fs::hard_link(&temporary, destination)?;
            Ok(SelfRepairReport {
                path: destination.to_owned(),
                kind: container.kind(),
                reconstructed_blocks,
                recovery_packets: report.recovery_packets,
            })
        })();
        if carrier_installed {
            let _ = std::fs::remove_file(&carrier_output);
        }
        result
    }
}

struct Prefix<'a> {
    access: &'a dyn SourceAccess,
    length: u64,
}
impl SourceAccess for Prefix<'_> {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok(self
            .access
            .snapshot(source)?
            .map(|snapshot| SourceSnapshot {
                len: snapshot.len.min(self.length),
                ..snapshot
            }))
    }
    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let take = self.length.saturating_sub(offset).min(out.len() as u64) as usize;
        if take == 0 {
            return Ok(0);
        }
        self.access.read_at(source, offset, &mut out[..take])
    }
    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok(self
            .access
            .next_available(source, offset)?
            .and_then(|range| {
                let end = range.end.min(self.length);
                (range.start < end).then_some(range.start..end)
            }))
    }
}
