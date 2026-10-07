//! Staged PAR-inside insertion without recompressing archive members.

use crate::runtime::{EngineFile as File, MemoryCategory, OpenBudgeted};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{ContainerLayout, ContainerLimits};
use crate::creation::{
    CreationCodec, CreationDurability, CreationOptions, CreationPlan, CreationSource,
};
use crate::runtime::{EngineError, EngineResult};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};

/// Exact storage requirements, available before any output is created.
#[derive(Clone, Debug)]
pub struct InsertionRequirements {
    /// Complete archive after insertion, including any duplicated ZIP footer.
    pub output_bytes: u64,
    /// Original archive bytes, cloned or copied without recompression.
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
        let mut plan = CreationPlan::build_in_source_order(views, &sources, options.clone())?;
        let protection_bytes = plan.embedded_layout()?;
        let output_bytes = layout
            .snapshot()
            .len
            .checked_add(protection_bytes)
            .and_then(|size| size.checked_add(footer.end - footer.start))
            .ok_or(EngineError::resource_limit("embedded output length"))?;
        // The carrier is written straight into the staged output, so the only
        // auxiliary disk is the creation plan's own recovery spool.
        let scratch_bytes = plan.requirements().scratch_bytes;
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
    /// The staged output is proven before exclusive output installation.
    pub fn execute(&self, destination: &Path, scratch_directory: &Path) -> EngineResult<PathBuf> {
        self.execute_with_durability(
            destination,
            scratch_directory,
            CreationDurability::SyncFiles,
        )
    }

    /// Execute with an explicit file synchronization policy: `SyncFiles`
    /// synchronizes the staged output once before it is linked into place,
    /// `Buffered` leaves that to the host. Both build and prove the same bytes.
    ///
    /// The output is the original archive, the embedded carrier and, for ZIP,
    /// a copy of the footer. Where the filesystem shares extents (APFS, and
    /// Linux reflink filesystems), and the source is a file this process can
    /// open whose metadata still matches the plan's snapshot, the output is
    /// staged as a clone of it and only the carrier and footer are written;
    /// otherwise the archive is copied. Nothing is read back. Copied protected
    /// bytes are hashed as they are written and must reproduce the file
    /// fingerprint the plan recorded; cloned ones are the snapshot's own,
    /// checked again after the last source read. The carrier is written
    /// straight into the output and authenticated packet by packet as it is.
    pub fn execute_with_durability(
        &self,
        destination: &Path,
        scratch_directory: &Path,
        durability: CreationDurability,
    ) -> EngineResult<PathBuf> {
        let options = &self.options.execution;
        let _progress = options.stage(crate::runtime::Stage::Container)?;
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
        // Admission before the first creation operation. Creation independently
        // admits its codec and metadata workspaces.
        let size = options.stripe_bytes.min(64 << 10);
        let _memory = options
            .memory
            .reserve_as(MemoryCategory::OutputStaging, size)?;
        let mut buffer = vec![0; size];
        let mut staging = None;
        let result = (|| -> EngineResult<()> {
            let (mut output, cloned) = self.stage_output(destination, &mut staging)?;
            // Every protected byte this writes is hashed; a clone already holds
            // the archive, so only a copy feeds the whole fingerprint.
            let mut hash = (!cloned).then(crate::FingerprintHasher::new);
            let mut copy_range = |output: &mut File, range: Range<u64>| -> EngineResult<()> {
                let mut at = range.start;
                while at < range.end {
                    options.cancel.check()?;
                    let take = (range.end - at).min(size as u64) as usize;
                    read_exact_at(
                        &options.diagnostics,
                        self.access.as_ref(),
                        self.layout.source(),
                        at,
                        &mut buffer[..take],
                    )?;
                    output.write_all(&buffer[..take])?;
                    if let Some(hash) = &mut hash {
                        hash.update(&buffer[..take]);
                    }
                    at += take as u64;
                }
                Ok(())
            };
            if !cloned {
                copy_range(&mut output, 0..self.layout.snapshot().len)?;
            }
            {
                let _carrier_buffer = options
                    .memory
                    .reserve_as(MemoryCategory::OutputStaging, size)?;
                let mut carrier = std::io::BufWriter::with_capacity(
                    size,
                    crate::ingest::AuthenticatingWriter::new(
                        &mut output,
                        self.plan.input_set_id(),
                        options.clone(),
                    ),
                );
                self.plan.write_embedded(&mut carrier, scratch_directory)?;
                carrier
                    .into_inner()
                    .map_err(std::io::IntoInnerError::into_error)?
                    .finish(self.requirements.protection_bytes)?;
            }
            // The footer's protected chunks recur after the carrier, and the
            // fingerprint covers them both times.
            copy_range(&mut output, self.layout.footer())?;
            // After the clone and the last source read: the bytes cloned and
            // copied are the generation the plan was built from.
            ensure_snapshot(
                self.access.as_ref(),
                self.layout.source(),
                self.layout.snapshot(),
            )?;
            if let Some(hash) = hash
                && hash.finalize() != self.plan.embedded_fingerprint()
            {
                return Err(EngineError::InvalidState(
                    "embedded output failed verification",
                ));
            }
            if durability == CreationDurability::SyncFiles {
                output.sync_all()?;
            }
            drop(output);
            let temporary = staging
                .as_ref()
                .ok_or(EngineError::InvalidState("embedded output was not staged"))?;
            std::fs::hard_link(temporary, destination)?;
            Ok(())
        })();
        // This path was created exclusively by this invocation; it is
        // disposable staging, and no failed output has been installed.
        if let Some(temporary) = staging {
            let _ = std::fs::remove_file(temporary);
        }
        result?;
        Ok(destination.to_owned())
    }

    /// Create the staged output, recorded in `staging` as soon as it exists:
    /// a clone of the source where that works, positioned after the archive,
    /// and otherwise an empty file. Returns whether it is a clone.
    fn stage_output(
        &self,
        destination: &Path,
        staging: &mut Option<PathBuf>,
    ) -> EngineResult<(File, bool)> {
        let options = &self.options.execution;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let original = self.original();
        #[cfg(target_os = "macos")]
        if let Some(original) = &original
            && let Some(temporary) =
                crate::session_repair::clone_stage_path(destination, &*original.0)?
        {
            let temporary = staging.insert(temporary);
            match OpenOptions::new()
                .write(true)
                .open_budgeted(temporary, options)
            {
                Ok(mut output) => {
                    io::Seek::seek(&mut output, io::SeekFrom::Start(self.layout.snapshot().len))?;
                    options.diagnostics.note_clone();
                    return Ok((output, true));
                }
                // A clone that kept something denying its owner writes is
                // removed, and the output is staged by copying.
                Err(EngineError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                    tracing::debug!(%error, "PAR3 staging copies an unwritable clone");
                    std::fs::remove_file(&*temporary)?;
                    *staging = None;
                }
                Err(error) => return Err(error),
            }
        }
        let temporary = staging.insert(crate::session_repair::stage_path(destination, options)?);
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut output = OpenOptions::new()
            .write(true)
            .open_budgeted(temporary, options)?;
        #[cfg(target_os = "linux")]
        if let Some(original) = original {
            use crate::repair_tree::clone;
            #[cfg(test)]
            let refused = crate::repair_tree::REFUSE_CLONES.with(std::cell::Cell::get);
            #[cfg(not(test))]
            let refused = false;
            let cloned = if refused {
                Err(io::Error::from_raw_os_error(libc::EXDEV))
            } else {
                clone::clone_into(&*original.0, &output)
            };
            drop(original);
            match cloned {
                Ok(()) => {
                    io::Seek::seek(&mut output, io::SeekFrom::Start(self.layout.snapshot().len))?;
                    options.diagnostics.note_clone();
                    return Ok((output, true));
                }
                // A refused clone leaves the file empty, exactly as staged.
                Err(error) if clone::unsupported(&error) => {
                    tracing::debug!(%error, "PAR3 staging copies instead of cloning");
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok((output, false))
    }

    /// The source's open file when it is the file the plan inspected, so the
    /// output can be staged as a clone of it; `None` stages by copying.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn original(&self) -> Option<crate::source::SourceFile> {
        let file = self.access.open_file(self.layout.source()).ok()??;
        let metadata = file.0.metadata().ok()?;
        crate::repair_tree::clone::is_source(&metadata, self.layout.snapshot()).then_some(file)
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

#[cfg(test)]
mod tests {
    //! The staged output is the archive, the embedded carrier and the footer
    //! again, byte for byte what copying the plan's carrier file produced, and
    //! it is proven from what was written, never read back.
    use super::*;
    use crate::source::{DiskSourceAccess, MemorySourceAccess};
    use crate::test_reference::{TempTree, advanced_fixture};

    /// Archive fixture, the name it is inserted under, and its block size.
    const CASES: [(&str, &str, u64); 3] = [
        ("inside-original.zip", "archive.zip", 128),
        ("inside64-original.zip", "archive.zip", 32768),
        ("inside-original.7z", "archive.7z", 128),
    ];

    fn options(block_size: u64) -> CreationOptions {
        CreationOptions {
            block_size,
            recovery_count: 4,
            ..CreationOptions::default()
        }
    }

    fn plan(access: Arc<dyn SourceAccess>, name: &str, options: CreationOptions) -> InsertionPlan {
        InsertionPlan::build(
            access,
            SourceId(7),
            name,
            options,
            &crate::inside::ContainerLimits::default(),
        )
        .unwrap()
    }

    /// The output as insertion built it before: the archive, the embedded
    /// carrier file the plan writes, and the footer once more.
    fn assembled(original: &[u8], name: &str, block_size: u64) -> Vec<u8> {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(7), 1, original.into());
        let plan = plan(Arc::new(access), name, options(block_size));
        let tree = TempTree::new("inside-assembled");
        let carriers = plan
            .plan
            .execute(&tree.path().join("inside-parity"), tree.path())
            .unwrap();
        assert_eq!(carriers.len(), 2);
        let footer = plan.layout.footer();
        let mut bytes = original.to_vec();
        bytes.extend(std::fs::read(&carriers[1]).unwrap());
        bytes.extend_from_slice(&original[footer.start as usize..footer.end as usize]);
        bytes
    }

    /// What one disk insertion did: engine file I/O, opens, syncs, clones.
    #[derive(Debug, PartialEq)]
    struct Run {
        read_bytes: u64,
        write_bytes: u64,
        opens: u64,
        syncs: u64,
        clones: u64,
    }

    /// Insert into `original`, stored on disk, and return the installed bytes.
    /// Every file byte read must be a source read: nothing is read back.
    fn insert_from_disk(
        original: &[u8],
        name: &str,
        block_size: u64,
        refuse: bool,
        durability: CreationDurability,
    ) -> (Vec<u8>, Run, u64) {
        let tree = TempTree::new("inside-disk");
        let options = options(block_size);
        let execution = options.execution.clone();
        let mut access = DiskSourceAccess::with_options(execution.clone());
        access.insert(SourceId(7), tree.write(&format!("source/{name}"), original));
        let plan = plan(Arc::new(access), name, options);
        tree.mkdir("scratch");
        tree.mkdir("output");
        let output = tree.path().join("output").join(name);
        let diagnostics = &execution.diagnostics;
        let (files, sources) = (diagnostics.file_io(), diagnostics.source_io());
        let (opens, syncs) = (diagnostics.file_opens(), diagnostics.file_sync().calls);
        crate::repair_tree::REFUSE_CLONES.with(|refused| refused.set(refuse));
        let installed =
            plan.execute_with_durability(&output, &tree.path().join("scratch"), durability);
        crate::repair_tree::REFUSE_CLONES.with(|refused| refused.set(false));
        assert_eq!(installed.unwrap(), output);
        let (files_after, sources_after) = (diagnostics.file_io(), diagnostics.source_io());
        assert_eq!(
            files_after.read_bytes - files.read_bytes,
            sources_after.read_bytes - sources.read_bytes,
            "a staged byte was read back"
        );
        let run = Run {
            read_bytes: files_after.read_bytes - files.read_bytes,
            write_bytes: files_after.write_bytes - files.write_bytes,
            opens: diagnostics.file_opens() - opens,
            syncs: diagnostics.file_sync().calls - syncs,
            clones: diagnostics.file_clones(),
        };
        let protection = plan.requirements().protection_bytes;
        assert_eq!(
            std::fs::read_dir(tree.path().join("scratch"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(tree.path().join("output"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(&tree.read(&format!("source/{name}")), original);
        drop(plan);
        assert_eq!(execution.memory.used(), 0);
        assert_eq!(execution.handles.used(), 0);
        (std::fs::read(&output).unwrap(), run, protection)
    }

    #[test]
    fn a_clone_or_a_copy_installs_the_bytes_the_carrier_file_layout_did() {
        for (fixture, name, block_size) in CASES {
            let original = advanced_fixture(fixture);
            let expected = assembled(&original, name, block_size);
            let footer = {
                let mut access = MemorySourceAccess::default();
                access.insert(SourceId(7), 1, original.clone().into());
                plan(Arc::new(access), name, options(block_size))
                    .layout
                    .footer()
            };
            let footer = footer.end - footer.start;

            // The copy path, from a source with no file behind it.
            let mut access = MemorySourceAccess::default();
            access.insert(SourceId(7), 1, original.clone().into());
            let memory = plan(Arc::new(access), name, options(block_size));
            let tree = TempTree::new("inside-memory");
            let output = tree.path().join(name);
            memory.execute(&output, tree.path()).unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), expected, "{fixture}");

            let (cloned, clone, protection) = insert_from_disk(
                &original,
                name,
                block_size,
                false,
                CreationDurability::SyncFiles,
            );
            let (copied, copy, _) = insert_from_disk(
                &original,
                name,
                block_size,
                true,
                CreationDurability::SyncFiles,
            );
            let (buffered, unsynced, _) = insert_from_disk(
                &original,
                name,
                block_size,
                false,
                CreationDurability::Buffered,
            );
            assert_eq!(cloned, expected, "{fixture}");
            assert_eq!(copied, expected, "{fixture}");
            assert_eq!(buffered, expected, "{fixture}");
            let len = original.len() as u64;
            assert_eq!(len + protection + footer, expected.len() as u64);

            // The plan kept the archive from its hash pass, so encoding reads
            // nothing and only the footer copy reads the footer once more. A
            // refused clone also copies the archive, read and written, after
            // the open that creates the stage name and the one that writes it.
            let encoding = copy.read_bytes - len;
            assert_eq!(encoding, footer, "{fixture}");
            let copy_expected = Run {
                read_bytes: encoding + len,
                write_bytes: len + protection + footer,
                opens: 2,
                syncs: 1,
                clones: 0,
            };
            assert_eq!(copy, copy_expected, "{fixture}");
            // A clone writes only the new bytes. macOS creates the clone by
            // name and opens it once; Linux clones into the staged file, so it
            // keeps both opens, and copies where the filesystem refuses.
            let cloned_run = |opens| Run {
                read_bytes: encoding,
                write_bytes: protection + footer,
                opens,
                syncs: 1,
                clones: 1,
            };
            let clone_expected = if cfg!(target_os = "macos") {
                cloned_run(1)
            } else if cfg!(target_os = "linux") && clone.clones == 1 {
                cloned_run(2)
            } else {
                copy_expected
            };
            assert_eq!(clone, clone_expected, "{fixture}");
            assert_eq!(
                unsynced,
                Run {
                    syncs: 0,
                    ..clone_expected
                },
                "{fixture}"
            );
        }
    }

    #[test]
    fn a_source_changed_after_planning_installs_nothing() {
        let (fixture, name, block_size) = CASES[0];
        let original = advanced_fixture(fixture);
        let mut grown = original.clone();
        grown.extend_from_slice(b"appended");
        let mut rewritten = original.clone();
        rewritten[40] ^= 0x01;
        let truncated = original[..original.len() - 1].to_vec();
        for (case, changed) in [
            ("rewritten", rewritten),
            ("grown", grown),
            ("truncated", truncated),
        ] {
            let tree = TempTree::new("inside-changed");
            let options = options(block_size);
            let execution = options.execution.clone();
            let mut access = DiskSourceAccess::with_options(execution.clone());
            let source = tree.write(&format!("source/{name}"), &original);
            access.insert(SourceId(7), source.clone());
            let plan = plan(Arc::new(access), name, options);
            // A rewrite within the timestamp granularity must still be seen.
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::fs::write(&source, &changed).unwrap();
            tree.mkdir("scratch");
            tree.mkdir("output");
            let output = tree.path().join("output").join(name);
            assert!(
                matches!(
                    plan.execute(&output, &tree.path().join("scratch")),
                    Err(EngineError::SourceChanged(SourceId(7)))
                ),
                "{case}"
            );
            assert_eq!(execution.diagnostics.file_io().write_bytes, 0, "{case}");
            assert_eq!(
                std::fs::read_dir(tree.path().join("output"))
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(
                std::fs::read_dir(tree.path().join("scratch"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    /// REVIEW: a Finder-locked (`uchg`) source archive is only read by
    /// insertion. The copy path inserts into it; a clone inherits the flag,
    /// so the staged output can be neither written nor removed.
    #[cfg(target_os = "macos")]
    #[test]
    fn review_a_locked_source_archive_still_inserts_and_leaves_no_temporary() {
        let (fixture, name, block_size) = CASES[0];
        let original = advanced_fixture(fixture);
        let expected = assembled(&original, name, block_size);
        let tree = TempTree::new("inside-locked");
        let options = options(block_size);
        let chflags = |flag: &str, path: &Path| {
            assert!(
                std::process::Command::new("chflags")
                    .arg(flag)
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let mut access = DiskSourceAccess::with_options(options.execution.clone());
        let source = tree.write(&format!("source/{name}"), &original);
        // Locked before planning: the flag change is a metadata change.
        chflags("uchg", &source);
        access.insert(SourceId(7), source.clone());
        let plan = plan(Arc::new(access), name, options);
        tree.mkdir("scratch");
        tree.mkdir("output");
        let output = tree.path().join("output").join(name);
        let result = plan.execute(&output, &tree.path().join("scratch"));
        let left: Vec<_> = std::fs::read_dir(tree.path().join("output"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        // Unlock everything so the temporary tree can be removed.
        chflags("nouchg", &source);
        for path in &left {
            chflags("nouchg", path);
        }
        assert!(result.is_ok(), "{result:?}, left behind: {left:?}");
        assert_eq!(left, vec![output.clone()], "a temporary was left behind");
        assert_eq!(std::fs::read(&output).unwrap(), expected);
    }

    /// A source archive whose ACL denies its owner writes is only read by
    /// insertion. Whether or not the clone carries that ACL, the output is
    /// staged, written and installed, and no temporary is left.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_source_archive_denying_writes_by_acl_still_inserts() {
        let (fixture, name, block_size) = CASES[0];
        let original = advanced_fixture(fixture);
        let expected = assembled(&original, name, block_size);
        let tree = TempTree::new("inside-acl");
        let options = options(block_size);
        let mut access = DiskSourceAccess::with_options(options.execution.clone());
        let source = tree.write(&format!("source/{name}"), &original);
        crate::test_reference::deny_owner_writes(&source, true);
        access.insert(SourceId(7), source.clone());
        let plan = plan(Arc::new(access), name, options);
        tree.mkdir("scratch");
        tree.mkdir("output");
        let output = tree.path().join("output").join(name);
        let result = plan.execute(&output, &tree.path().join("scratch"));
        let left: Vec<_> = std::fs::read_dir(tree.path().join("output"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        crate::test_reference::deny_owner_writes(&source, false);
        for path in &left {
            crate::test_reference::deny_owner_writes(path, false);
        }
        assert!(result.is_ok(), "{result:?}, left behind: {left:?}");
        assert_eq!(left, vec![output.clone()], "a temporary was left behind");
        assert_eq!(std::fs::read(&output).unwrap(), expected);
    }

    /// A source that keeps its generation while its bytes change: the copy
    /// still hashes what it wrote, and a hash that is not the plan's
    /// fingerprint fails before anything is installed, as reading the staged
    /// output back did.
    struct Lying {
        bytes: std::sync::Mutex<Vec<u8>>,
    }

    impl SourceAccess for Lying {
        fn snapshot(&self, _: SourceId) -> io::Result<Option<SourceSnapshot>> {
            Ok(Some(SourceSnapshot {
                len: self.bytes.lock().unwrap().len() as u64,
                generation: 1,
            }))
        }
        fn read_at(&self, _: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
            let bytes = self.bytes.lock().unwrap();
            let start = (offset as usize).min(bytes.len());
            let take = (bytes.len() - start).min(out.len());
            out[..take].copy_from_slice(&bytes[start..start + take]);
            Ok(take)
        }
        fn next_available(&self, _: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
            let len = self.bytes.lock().unwrap().len() as u64;
            Ok((offset < len).then_some(offset..len))
        }
    }

    #[test]
    fn copied_bytes_that_are_not_the_planned_ones_are_refused_before_install() {
        let (fixture, name, block_size) = CASES[0];
        let original = advanced_fixture(fixture);
        let access = Arc::new(Lying {
            bytes: std::sync::Mutex::new(original.clone()),
        });
        let plan = plan(access.clone(), name, options(block_size));
        access.bytes.lock().unwrap()[40] ^= 0x01;
        let tree = TempTree::new("inside-lying");
        tree.mkdir("scratch");
        let output = tree.path().join(name);
        assert!(matches!(
            plan.execute(&output, &tree.path().join("scratch")),
            Err(EngineError::InvalidState(
                "embedded output failed verification"
            ))
        ));
        assert!(!output.exists());
        assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(tree.path().join("scratch"))
                .unwrap()
                .count(),
            0
        );
    }
}
