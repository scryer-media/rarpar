//! Staged PAR-inside insertion without recompressing archive members.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{ContainerLayout, ContainerLimits};
use crate::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
use crate::ingest::{IncrementalSet, PacketScanner, ScanEvent};
use crate::runtime::{EngineError, EngineResult};
use crate::source::{
    DiskSourceAccess, SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at,
};

/// Exact storage requirements, available before any output is created.
#[derive(Clone, Debug)]
pub struct InsertionRequirements {
    /// Complete archive after insertion, including any duplicated ZIP footer.
    pub output_bytes: u64,
    /// Original archive bytes, copied without recompression.
    pub original_bytes: u64,
    /// Embedded metadata and recovery bytes.
    pub protection_bytes: u64,
    /// Peak auxiliary disk bytes, excluding the staged output archive.
    pub scratch_bytes: u64,
    /// Logical input blocks, counting the duplicate footer only once.
    pub blocks: u64,
}

/// Cauchy insertion plan bound to an inspected source generation.
pub struct InsertionPlan {
    access: Arc<dyn SourceAccess>,
    layout: ContainerLayout,
    plan: CreationPlan,
    options: CreationOptions,
    requirements: InsertionRequirements,
}

impl InsertionPlan {
    /// Validate a plain ZIP/ZIP64 or 7z archive and plan embedded protection.
    /// `name` is the relative file name recorded in the set. Recovery count must
    /// be positive; FFT and Data packet insertion are explicitly refused.
    pub fn build(
        access: Arc<dyn SourceAccess>,
        source: SourceId,
        name: &str,
        options: CreationOptions,
        limits: &ContainerLimits,
    ) -> EngineResult<Self> {
        if options.codec != CreationCodec::Cauchy
            || options.store_data
            || options.recovery_count == 0
        {
            return Err(EngineError::Unsupported(
                "PAR-inside requires Cauchy recovery without Data packets",
            ));
        }
        let layout = ContainerLayout::inspect(access.as_ref(), source, &options.execution, limits)?;
        let footer = layout.footer();
        let views = Arc::new(ArchiveViews {
            access: access.clone(),
            source,
            snapshot: layout.snapshot(),
            split: footer.start,
        });
        let mut sources = vec![CreationSource {
            name: name.to_owned(),
            source: SourceId(0),
        }];
        if !footer.is_empty() {
            sources.push(CreationSource {
                name: if name == ".footer" {
                    ".footer2"
                } else {
                    ".footer"
                }
                .into(),
                source: SourceId(1),
            });
        }
        let mut plan = CreationPlan::build(views, &sources, options.clone())?;
        let protection_bytes = plan.embedded_layout()?;
        let output_bytes = layout
            .snapshot()
            .len
            .checked_add(protection_bytes)
            .and_then(|size| size.checked_add(footer.end - footer.start))
            .ok_or(EngineError::ResourceLimit("embedded output length"))?;
        let scratch_bytes = plan
            .requirements()
            .scratch_bytes
            .checked_add(protection_bytes)
            .and_then(|size| size.checked_add(plan.requirements().metadata_bytes))
            .ok_or(EngineError::ResourceLimit("embedded scratch length"))?;
        let requirements = InsertionRequirements {
            output_bytes,
            original_bytes: layout.snapshot().len,
            protection_bytes,
            scratch_bytes,
            blocks: plan.requirements().blocks,
        };
        Ok(Self {
            access,
            layout,
            plan,
            options,
            requirements,
        })
    }

    /// Inspect storage requirements before execution.
    pub fn requirements(&self) -> &InsertionRequirements {
        &self.requirements
    }

    /// Stage insertion to a separate, absent output. The caller supplies a
    /// dedicated existing scratch directory. The original archive is read-only.
    /// Final PAR3 verification precedes exclusive output installation.
    pub fn execute(&self, destination: &Path, scratch_directory: &Path) -> EngineResult<PathBuf> {
        let options = &self.options.execution;
        options.validate()?;
        ensure_snapshot(
            self.access.as_ref(),
            self.layout.source(),
            self.layout.snapshot(),
        )?;
        match std::fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(
                    io::Error::new(io::ErrorKind::AlreadyExists, "embedded output exists").into(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Admission before the first creation operation. Creation and final
        // verification independently admit their codec and metadata workspaces.
        let size = options.stripe_bytes.min(64 << 10);
        let _memory = options.memory.reserve(size)?;
        let mut buffer = vec![0; size];
        let carriers = self
            .plan
            .execute(&scratch_directory.join("inside-parity"), scratch_directory)?;
        if carriers.len() != 2 {
            return Err(EngineError::InvalidState("embedded carrier layout"));
        }
        let temporary = crate::session_repair::stage_path(destination)?;
        let result = (|| -> EngineResult<()> {
            let mut output = OpenOptions::new().write(true).open(&temporary)?;
            let mut copy_range = |range: Range<u64>| -> EngineResult<()> {
                let mut at = range.start;
                while at < range.end {
                    options.cancel.check()?;
                    let take = (range.end - at).min(size as u64) as usize;
                    read_exact_at(
                        self.access.as_ref(),
                        self.layout.source(),
                        at,
                        &mut buffer[..take],
                    )?;
                    output.write_all(&buffer[..take])?;
                    at += take as u64;
                }
                Ok(())
            };
            copy_range(0..self.layout.snapshot().len)?;
            let mut carrier = File::open(&carriers[1])?;
            loop {
                options.cancel.check()?;
                let count = carrier.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                output.write_all(&buffer[..count])?;
            }
            let footer = self.layout.footer();
            let mut at = footer.start;
            while at < footer.end {
                options.cancel.check()?;
                let take = (footer.end - at).min(size as u64) as usize;
                read_exact_at(
                    self.access.as_ref(),
                    self.layout.source(),
                    at,
                    &mut buffer[..take],
                )?;
                output.write_all(&buffer[..take])?;
                at += take as u64;
            }
            output.sync_all()?;
            if output.metadata()?.len() != self.requirements.output_bytes {
                return Err(EngineError::InvalidState("embedded output size"));
            }
            drop(output);
            drop(carrier);
            ensure_snapshot(
                self.access.as_ref(),
                self.layout.source(),
                self.layout.snapshot(),
            )?;
            self.verify_staged(&temporary, &carriers[0])?;
            std::fs::hard_link(&temporary, destination)?;
            Ok(())
        })();
        // These paths were created exclusively by this invocation; they are
        // disposable staging, and no failed output has been installed.
        for carrier in carriers {
            let _ = std::fs::remove_file(carrier);
        }
        let _ = std::fs::remove_file(&temporary);
        result?;
        Ok(destination.to_owned())
    }

    fn verify_staged(&self, output: &Path, index: &Path) -> EngineResult<()> {
        let options = &self.options.execution;
        let mut disk = DiskSourceAccess::default();
        disk.insert(SourceId(0), index.to_owned());
        disk.insert(SourceId(1), output.to_owned());
        let disk = Arc::new(disk);
        let mut scanner = PacketScanner::new(
            disk.clone(),
            SourceId(0),
            options.clone(),
            crate::ScanLimits::default(),
        )?;
        let mut input = IncrementalSet::new(self.plan.input_set_id(), options.clone())?;
        loop {
            match scanner.poll()? {
                ScanEvent::Packet(packet) => {
                    input.merge(packet)?;
                }
                ScanEvent::End => break,
                ScanEvent::NeedData { .. } => {
                    return Err(EngineError::InvalidState("incomplete staged index"));
                }
            }
        }
        let set = input
            .metadata()?
            .ok_or(EngineError::InvalidState("incomplete embedded metadata"))?;
        let layout = Arc::new(crate::layout::BlockLayout::new(&set, options)?);
        let proof = crate::evidence::verify_source(layout, 0, disk.as_ref(), SourceId(1), options)?;
        if !proof.protected_complete() {
            return Err(EngineError::InvalidState(
                "embedded output failed verification",
            ));
        }
        Ok(())
    }
}

struct ArchiveViews {
    access: Arc<dyn SourceAccess>,
    source: SourceId,
    snapshot: SourceSnapshot,
    split: u64,
}

impl ArchiveViews {
    fn range(&self, source: SourceId) -> io::Result<Range<u64>> {
        match source {
            SourceId(0) => Ok(0..self.split),
            SourceId(1) => Ok(self.split..self.snapshot.len),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown archive view",
            )),
        }
    }
}

impl SourceAccess for ArchiveViews {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        let range = self.range(source)?;
        Ok(self
            .access
            .snapshot(self.source)?
            .map(|snapshot| SourceSnapshot {
                len: snapshot.len.min(range.end).saturating_sub(range.start),
                generation: snapshot.generation,
            }))
    }
    fn read_at(&self, source: SourceId, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let range = self.range(source)?;
        let length = range.end - range.start;
        if offset >= length {
            return Ok(0);
        }
        let take = (length - offset).min(output.len() as u64) as usize;
        self.access
            .read_at(self.source, range.start + offset, &mut output[..take])
    }
    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        let range = self.range(source)?;
        if offset >= range.end - range.start {
            return Ok(None);
        }
        Ok(self
            .access
            .next_available(self.source, range.start + offset)?
            .and_then(|available| {
                let start = available.start.max(range.start);
                let end = available.end.min(range.end);
                (start < end).then_some(start - range.start..end - range.start)
            }))
    }
}
