//! PAR3 recovery inside RAR5 archives (`rarpar par3 inside`).
//!
//! **Experimental.** The on-disk layout may change before it is stable, and
//! archives written by this version may not verify with a later one.
//!
//! This module is where the two libraries meet; neither knows the other.
//! `unrar-rs` walks a RAR5 archive's blocks and appends or removes a
//! caller-named service record ([`unrar_rs::container`]), and knows nothing
//! of PAR3. `par3-rs` plans, writes, verifies, repairs and removes embedded
//! carrier sets ([`par3_rs::embedded`]), and knows nothing of RAR. Here each
//! archive is inspected, the record position decided, and the two joined:
//! the carrier `par3-rs` writes is the payload of a service record named
//! [`RECORD_NAME`] that `unrar-rs` frames.
//!
//! # Layout
//!
//! Each archive (or each volume of a set) gets one service record named
//! `PAR3`, placed immediately before its end-of-archive header; its data
//! area is the carrier: the set's whole metadata followed by that volume's
//! share of the recovery packets. The record header is the framing in front
//! of the carrier. Under `-hp` the record header is sealed with the
//! archive's header key, like every other header of the archive, so an
//! encrypted-header archive shows no `PAR3` name in the clear. These are the
//! choices and their reasons:
//!
//! - **One layout, a service record.** It is a block of the archive, so a
//!   RAR5 reader walks over it (skip-if-unknown is set) and the archive
//!   stays one well-formed RAR5 file. Alternatives dropped: bytes after the
//!   end header (outside the archive, where nothing describes them) and a
//!   block of an unassigned type (which a reader may reject as unknown).
//! - **Before the end header.** No offset the archive records moves; see
//!   [`unrar_rs::container`].
//! - **Sealed under `-hp` with a deterministic IV.** The record header is
//!   part of the protected file's unprotected region, so repair must be able
//!   to rebuild it byte for byte from the archive's encryption header and
//!   the password; see [`unrar_rs::container::service_record_header`].
//!   Alternative: leaving the header in the clear, which would name the
//!   record in an archive whose headers are otherwise hidden.
//! - **Sealing is set-wide.** Every archive of one invocation must have
//!   sealed headers or none: the record header's length, which `par3-rs`
//!   needs to find the carrier in a damaged archive, depends on it. When no
//!   given archive's first header reads, both lengths are tried; they differ
//!   by less than one recovery packet, so at most one fits.
//!
//! RAR 2.9-4.x archives are refused: their recovery here was an earlier
//! experiment and is dropped.

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use par3_rs::creation::CreationOptions;
use par3_rs::embedded::{
    self, CarrierFraming, CarrierHint, EmbeddedHost, EmbeddedInserted, EmbeddedRepaired,
    EmbeddedSet, InsertFraming,
};
use par3_rs::runtime::{EngineError, EngineResult, ExecutionOptions};
use unrar_rs::container::{
    HeaderSealing, Rar5Container, ServiceRecordAppend, headers_sealed, service_record_header,
    service_record_header_len,
};
use unrar_rs::{KdfCache, RarError};

pub use par3_rs::embedded::{Placement, placement_counts, validate_host_name};

/// Name of the service record that carries the PAR3 carrier.
pub const RECORD_NAME: &str = "PAR3";

/// Why a PAR-inside operation stopped.
#[derive(Debug, thiserror::Error)]
pub enum InsideError {
    /// The archive could not be read or changed.
    #[error("RAR error: {0}")]
    Rar(#[from] RarError),
    /// The embedded set could not be built, read or repaired.
    #[error("PAR3 error: {0}")]
    Par3(#[from] EngineError),
    /// A file could not be read or written.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The inputs are not something this module protects.
    #[error("refused: {0}")]
    Refused(String),
}

fn refused(detail: impl Into<String>) -> InsideError {
    InsideError::Refused(detail.into())
}

/// Candidate passwords for archives with encrypted headers (`-hp`), and the
/// key derivations already done for them. `Debug` shows how many candidates
/// there are, never what they are.
#[derive(Default)]
pub struct Passwords {
    candidates: Vec<String>,
    kdf: KdfCache,
}

impl std::fmt::Debug for Passwords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passwords")
            .field("candidates", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

impl Passwords {
    /// Try `candidates`, in order, on every archive with sealed headers.
    pub fn new(candidates: Vec<String>) -> Self {
        Self {
            candidates,
            kdf: KdfCache::new(),
        }
    }

    /// The first candidate `attempt` accepts. A rejected password moves to
    /// the next candidate; any other error (a damaged header past the one
    /// that confirms the password, say) stops, so damage is reported as
    /// damage and not as a wrong password.
    fn first<T>(
        &self,
        mut attempt: impl FnMut(&str) -> Result<T, RarError>,
    ) -> Result<T, RarError> {
        let mut last = RarError::EncryptedArchive;
        for candidate in &self.candidates {
            match attempt(candidate) {
                Ok(found) => return Ok(found),
                Err(error @ RarError::InvalidPassword) => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    /// Walk the archive at `path`, unsealing its headers with the first
    /// candidate that fits when they are sealed.
    pub fn container(&self, path: &Path) -> Result<Rar5Container, RarError> {
        let mut reader = BufReader::new(File::open(path)?);
        if !headers_sealed(&mut reader)? {
            return Rar5Container::read(&mut reader, None, &self.kdf);
        }
        self.first(|password| Rar5Container::read(&mut reader, Some(password), &self.kdf))
    }

    /// The header keys of the archive at `path`: `Ok(None)` when its headers
    /// are not sealed. Reads only the archive's first headers.
    pub fn sealing(&self, path: &Path) -> Result<Option<HeaderSealing>, RarError> {
        let mut reader = BufReader::new(File::open(path)?);
        if !headers_sealed(&mut reader)? {
            return Ok(None);
        }
        self.first(|password| HeaderSealing::from_archive(&mut reader, Some(password), &self.kdf))
    }
}

/// One archive inspected for insertion.
#[derive(Clone, Debug)]
pub struct InsideHost {
    /// What `par3-rs` is told: the file, its recorded name, and the split
    /// at the record position.
    pub embedded: EmbeddedHost,
    container: Rar5Container,
}

impl InsideHost {
    /// The archive's file.
    pub fn path(&self) -> &Path {
        &self.embedded.path
    }

    /// The name recorded for the archive in the set.
    pub fn name(&self) -> &str {
        &self.embedded.name
    }

    /// The archive's length before insertion.
    pub fn len(&self) -> u64 {
        self.embedded.len()
    }

    /// Whether the archive is empty (never, for an inspected archive).
    pub fn is_empty(&self) -> bool {
        self.embedded.is_empty()
    }

    /// The archive's headers are sealed (`-hp`).
    pub fn headers_sealed(&self) -> bool {
        self.container.headers_sealed()
    }
}

/// Inspect `paths` as one RAR5 archive or the volumes of one set, in order,
/// and decide where each record goes.
///
/// # Errors
///
/// [`InsideError::Refused`] for no paths, a file name that cannot be
/// recorded, a locked archive, one that already holds a `PAR3` record, one
/// whose main header locates a block the record would move, a mix
/// of sealed and plain headers, volumes that are incomplete or out of
/// order, or two archives of one name; [`InsideError::Rar`] for anything
/// that is not a RAR5 archive walking cleanly to its end header, or sealed
/// headers no candidate password opens.
pub fn prepare_hosts(
    paths: &[PathBuf],
    passwords: &Passwords,
    options: &ExecutionOptions,
) -> Result<Vec<InsideHost>, InsideError> {
    if paths.is_empty() {
        return Err(refused("no archives to protect"));
    }
    let mut hosts: Vec<InsideHost> = Vec::with_capacity(paths.len());
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refused(format!("{} has no UTF-8 file name", path.display())))?
            .to_owned();
        // The revision is taken before the archive is walked, so a change
        // during the walk is caught below and at insertion.
        let mut embedded = EmbeddedHost::new(path, &name, options)?;
        let container = passwords.container(path)?;
        embedded.unchanged(options)?;
        // The append plan's refusals (locked, a record already there, a
        // locator the record would move) are the host's; the payload length
        // is planned again once the carrier is sized.
        embedded.split = match container.append_service_record(RECORD_NAME, 0) {
            Ok(plan) => plan.at(),
            Err(RarError::ModificationRefused { detail }) => {
                return Err(refused(format!("{name}: {detail}")));
            }
            Err(error) => return Err(error.into()),
        };
        hosts.push(InsideHost {
            embedded,
            container,
        });
    }
    if hosts
        .iter()
        .any(|host| host.headers_sealed() != hosts[0].headers_sealed())
    {
        return Err(refused(
            "the archives mix encrypted and plain headers; protect them separately",
        ));
    }
    if hosts.len() > 1 || hosts[0].container.volume.is_some() {
        for (index, host) in hosts.iter().enumerate() {
            if host.container.volume != Some(index as u64)
                || host.container.more_volumes != (index + 1 != hosts.len())
            {
                return Err(refused("RAR5 volumes are incomplete or out of order"));
            }
        }
    }
    let mut names: Vec<&str> = hosts.iter().map(InsideHost::name).collect();
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(refused("two archives share a name"));
    }
    Ok(hosts)
}

/// Insert one set over `hosts`, writing archive `k` with its `PAR3` record
/// to `outputs[k]` (absent). `counts[k]` recovery packets go into archive
/// `k`; their sum is `options.recovery_count`. Each output is staged,
/// checked and only then linked into place; a failure leaves none behind.
pub fn insert_set(
    hosts: &[InsideHost],
    outputs: &[PathBuf],
    counts: &[u64],
    options: CreationOptions,
    scratch_directory: &Path,
) -> Result<Vec<EmbeddedInserted>, InsideError> {
    let embedded: Vec<EmbeddedHost> = hosts.iter().map(|host| host.embedded.clone()).collect();
    let mut framing = InsertRecords {
        hosts,
        planned: vec![None; hosts.len()],
    };
    Ok(embedded::insert_set(
        &embedded,
        outputs,
        counts,
        options,
        scratch_directory,
        &mut framing,
    )?)
}

fn rar_io(error: RarError) -> io::Error {
    match error {
        RarError::Io(error) => error,
        other => io::Error::other(other),
    }
}

fn rar_engine(error: RarError) -> EngineError {
    EngineError::from(rar_io(error))
}

/// The `unrar-rs` side of an insertion: each archive's bytes around its
/// record, and the record header.
struct InsertRecords<'a> {
    hosts: &'a [InsideHost],
    planned: Vec<Option<ServiceRecordAppend>>,
}

impl InsertRecords<'_> {
    fn plan(&mut self, host: usize, carrier: u64) -> io::Result<&ServiceRecordAppend> {
        let stale = self.planned[host]
            .as_ref()
            .is_none_or(|plan| plan.payload_len() != carrier);
        if stale {
            self.planned[host] = Some(
                self.hosts[host]
                    .container
                    .append_service_record(RECORD_NAME, carrier)
                    .map_err(rar_io)?,
            );
        }
        Ok(self.planned[host].as_ref().expect("planned"))
    }

    fn archive(&self, host: usize) -> io::Result<BufReader<File>> {
        Ok(BufReader::new(File::open(self.hosts[host].path())?))
    }
}

impl InsertFraming for InsertRecords<'_> {
    fn prefix_len(&self, host: usize, carrier: u64) -> u64 {
        service_record_header_len(
            RECORD_NAME.len(),
            carrier,
            self.hosts[host].headers_sealed(),
        )
    }

    fn write_body(&mut self, host: usize, carrier: u64, out: &mut dyn Write) -> io::Result<()> {
        let mut archive = self.archive(host)?;
        self.plan(host, carrier)?
            .copy_before(&mut archive, out)
            .map_err(rar_io)
    }

    fn write_prefix(&mut self, host: usize, carrier: u64, out: &mut dyn Write) -> io::Result<()> {
        self.plan(host, carrier)?.write_header(out).map_err(rar_io)
    }

    fn write_tail(&mut self, host: usize, carrier: u64, out: &mut dyn Write) -> io::Result<()> {
        let mut archive = self.archive(host)?;
        self.plan(host, carrier)?
            .copy_after(&mut archive, out)
            .map_err(rar_io)
    }
}

/// The `unrar-rs` side of opening and repairing: the record header in front
/// of a carrier, and where a volume's record sits.
struct RecordFraming<'a> {
    /// Whether the set's archives have sealed headers; `None` when no given
    /// archive's first header reads (a lone archive with a damaged
    /// encryption header, say), and either record header length fits.
    sealed: Option<bool>,
    passwords: &'a Passwords,
}

impl CarrierFraming for RecordFraming<'_> {
    fn fits(&self, prefix: u64, carrier: u64) -> bool {
        // A plain and a sealed header differ by less than one recovery
        // packet (88 bytes and a block), so at most one of them leaves a
        // carrier of whole packets: accepting both when unknown is safe.
        let sealings: &[bool] = match self.sealed {
            Some(true) => &[true],
            Some(false) => &[false],
            None => &[false, true],
        };
        sealings
            .iter()
            .any(|&sealed| prefix == service_record_header_len(RECORD_NAME.len(), carrier, sealed))
    }

    fn prefix(&self, file: &Path, carrier: u64) -> EngineResult<Option<Vec<u8>>> {
        let sealing = match self.passwords.sealing(file) {
            Ok(sealing) => sealing,
            // No candidate opens the headers: the record header cannot be
            // rebuilt, so it is reported unchecked.
            Err(RarError::EncryptedArchive | RarError::InvalidPassword) => return Ok(None),
            Err(error) => return Err(rar_engine(error)),
        };
        if self
            .sealed
            .is_some_and(|sealed| sealing.is_some() != sealed)
        {
            return Ok(None);
        }
        service_record_header(RECORD_NAME, carrier, sealing.as_ref())
            .map(Some)
            .map_err(rar_engine)
    }

    fn locate(&self, file: &Path) -> CarrierHint {
        // An archive that does not walk (damaged, or sealed with no fitting
        // password) is scanned whole and bound by its packets alone.
        let Ok(container) = self.passwords.container(file) else {
            return CarrierHint::default();
        };
        CarrierHint {
            volume: container.volume,
            carrier_from: container
                .service_records(RECORD_NAME)
                .next()
                .map(|record| record.header.start),
        }
    }
}

/// One embedded set found in RAR5 archives. Dereferences to the set as
/// `par3-rs` opened it for reading; repair and removal go through this type,
/// which supplies the record framing.
pub struct InsideSet {
    set: EmbeddedSet,
    sealed: Option<bool>,
}

impl std::ops::Deref for InsideSet {
    type Target = EmbeddedSet;
    fn deref(&self) -> &EmbeddedSet {
        &self.set
    }
}

/// Whether the given archives' headers are sealed, refusing a mix. Files
/// that are missing, or whose first header does not read (not RAR5, or
/// damaged there), do not count; `None` when none counts.
fn sealed_inputs(paths: &[PathBuf]) -> Result<Option<bool>, InsideError> {
    let mut found: Option<bool> = None;
    for path in paths {
        let Ok(file) = File::open(path) else { continue };
        let Ok(sealed) = headers_sealed(&mut BufReader::new(file)) else {
            continue;
        };
        if found.is_some_and(|before| before != sealed) {
            return Err(refused(
                "the archives mix encrypted and plain headers; open them separately",
            ));
        }
        found = Some(sealed);
    }
    Ok(found)
}

/// Open every set embedded in `paths`. Archives a set records but `paths`
/// omits are looked up beside the given ones by their recorded names.
pub fn open(
    paths: &[PathBuf],
    passwords: &Passwords,
    options: &ExecutionOptions,
) -> Result<Vec<InsideSet>, InsideError> {
    let sealed = sealed_inputs(paths)?;
    let framing = RecordFraming { sealed, passwords };
    Ok(embedded::open(paths, options, &framing)?
        .into_iter()
        .map(|set| InsideSet { set, sealed })
        .collect())
}

impl InsideSet {
    /// Rebuild every archive that needs it (see
    /// [`EmbeddedSet::needs_repair`]) to `destinations[k]` (absent). Record
    /// headers are rebuilt from each rebuilt archive's encryption header and
    /// the passwords.
    pub fn repair(
        &mut self,
        destinations: &[PathBuf],
        scratch_directory: &Path,
        passwords: &Passwords,
    ) -> Result<Vec<EmbeddedRepaired>, InsideError> {
        let framing = RecordFraming {
            sealed: self.sealed,
            passwords,
        };
        Ok(self.set.repair(destinations, scratch_directory, &framing)?)
    }

    /// Write every archive without its `PAR3` record to `destinations[k]`
    /// (absent); each output is checked against the archive as it was before
    /// insertion before any is linked into place.
    pub fn remove(
        &mut self,
        destinations: &[PathBuf],
        passwords: &Passwords,
    ) -> Result<Vec<PathBuf>, InsideError> {
        let mut strip = |_: usize, path: &Path, out: &mut dyn Write| -> EngineResult<()> {
            let container = passwords.container(path).map_err(rar_engine)?;
            let removal = container
                .remove_service_record(RECORD_NAME)
                .map_err(rar_engine)?;
            removal
                .write(&mut BufReader::new(File::open(path)?), out)
                .map_err(rar_engine)?;
            Ok(())
        };
        Ok(self.set.remove(destinations, &mut strip)?)
    }
}

/// Whether the archive at `path` says another volume follows it; `None`
/// when it cannot be walked.
pub fn more_volumes(path: &Path, passwords: &Passwords) -> Option<bool> {
    passwords
        .container(path)
        .ok()
        .map(|container| container.more_volumes)
}
