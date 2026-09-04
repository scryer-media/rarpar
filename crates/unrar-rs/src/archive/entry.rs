//! The member handle: acquire one entry from an archive, then consume it.
//!
//! [`RarArchive::by_index`] and its siblings hand back an [`Entry`] without
//! decoding anything. The handle borrows the archive, so one entry is open at a
//! time, and consuming it — [`copy_to`](Entry::copy_to),
//! [`unpack_to`](Entry::unpack_to), [`copy_to_volumes`](Entry::copy_to_volumes),
//! [`skip`](Entry::skip), or reading it as a [`Read`] — takes the handle by
//! value.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::RarArchive;
use crate::error::{RarError, RarResult};
use crate::extract::{ExtractOptions, ExtractedMemberReader};
use crate::progress::ProgressHandler;
use crate::types::MemberInfo;
use crate::volume::VolumeProvider;

/// One member of an archive, ready to be consumed.
///
/// Acquired from [`RarArchive::by_index`], [`RarArchive::by_name`] or
/// [`RarArchive::by_index_via`]. Acquisition decodes nothing: it resolves the
/// member and borrows the archive.
///
/// # Consuming the entry
///
/// Every consuming call takes the handle by value, and each one streams: the
/// decoder's output goes to the destination as it is produced, with no copy of
/// the member held in between. [`copy_to`](Entry::copy_to) feeds a writer,
/// [`unpack_to`](Entry::unpack_to) and [`unpack_in`](Entry::unpack_in) land a
/// file on disk with its archived metadata, [`copy_to_volumes`](Entry::copy_to_volumes)
/// splits the output per source volume, and [`skip`](Entry::skip) walks past
/// the member.
///
/// The one exception is reading the entry as a [`Read`], which is there for
/// code that hands members to something expecting a reader. The first `read`
/// decodes the whole member into a spool — memory below a threshold, a
/// temporary file above it — and later reads serve from that spool. Where the
/// destination is already a writer, `copy_to` costs one pass; the reader costs
/// two.
///
/// # Solid archives
///
/// The same calls serve solid and non-solid archives. What solidity adds is an
/// order: members share one dictionary, so they must be consumed in ascending
/// index order. Asking for a member the archive has already moved past raises
/// [`RarError::SolidOrderViolation`]; asking for one further ahead decodes the
/// members in between for you. Dropping an entry without consuming it costs
/// nothing — the next acquisition's cursor advance covers it.
///
/// If a solid member fails partway through — a decode error, or a writer that
/// returns an error — the carried-over dictionary no longer lines up with any
/// member boundary. The archive is then poisoned: every later solid consumption
/// raises [`RarError::SolidStatePoisoned`] until
/// [`RarArchive::reset_solid_state`] clears it and extraction restarts from the
/// first member. Non-solid members are never poisoned.
pub struct Entry<'a> {
    archive: &'a mut RarArchive,
    index: usize,
    info: MemberInfo,
    provider: Option<&'a dyn VolumeProvider>,
    progress: Option<&'a dyn ProgressHandler>,
    password: Option<String>,
    spool: Option<ExtractedMemberReader>,
}

impl<'a> Entry<'a> {
    pub(crate) fn new(
        archive: &'a mut RarArchive,
        index: usize,
        provider: Option<&'a dyn VolumeProvider>,
    ) -> RarResult<Self> {
        let info = archive
            .member_info(index)
            .ok_or(RarError::MemberIndexOutOfRange {
                index,
                len: archive.len(),
            })?;
        Ok(Self {
            archive,
            index,
            info,
            provider,
            progress: None,
            password: None,
            spool: None,
        })
    }

    /// The member's index in the archive, the one `by_index` takes.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Everything the headers state about this member.
    pub fn info(&self) -> &MemberInfo {
        &self.info
    }

    /// The member's name, sanitized for use as a relative path.
    ///
    /// The name as stored, before sanitizing, is
    /// [`info().raw_name`](MemberInfo::raw_name).
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// The member's size once decoded, when the headers state it.
    pub fn size(&self) -> Option<u64> {
        self.info.unpacked_size
    }

    /// Whether the member is a directory rather than a file.
    pub fn is_dir(&self) -> bool {
        self.info.is_directory
    }

    /// Report this member's extraction to `handler`.
    ///
    /// Every consuming call reports: a start event, the running byte count as
    /// the destination receives it, and a completion event carrying the
    /// outcome.
    #[must_use]
    pub fn with_progress(mut self, handler: &'a dyn ProgressHandler) -> Self {
        self.progress = Some(handler);
        self
    }

    /// Decrypt this member with `password` instead of the archive's.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    fn options(&self) -> ExtractOptions {
        let mut options = self.archive.effective_options();
        if let Some(password) = self.password.clone() {
            options.password = Some(password);
        }
        options
    }

    /// Refuse a solid consumption while the decoder state is poisoned.
    fn check_solid_poison(&self) -> RarResult<()> {
        if !self.archive.member_is_solid_at(self.index) {
            return Ok(());
        }
        match &self.archive.solid_poison {
            Some((member, detail)) => Err(RarError::SolidStatePoisoned {
                member: member.to_string(),
                detail: detail.clone(),
            }),
            None => Ok(()),
        }
    }

    /// Decode this member straight into `writer`.
    ///
    /// Nothing is buffered on the way: each span the decoder produces is handed
    /// to `writer` as it is produced. When the entry was acquired with
    /// [`by_index_via`](RarArchive::by_index_via), volumes are pulled from that
    /// provider as they are needed; otherwise the archive's attached volumes
    /// are used.
    ///
    /// Returns the number of bytes written.
    pub fn copy_to<W: Write + ?Sized>(self, writer: &mut W) -> RarResult<u64> {
        self.check_solid_poison()?;
        let options = self.options();
        let Entry {
            archive,
            index,
            info,
            provider,
            progress,
            ..
        } = self;
        let report = Report::start(&info, progress);
        let mut writer = report.wrap(writer);
        let result = match provider {
            Some(provider) => {
                archive.extract_member_streaming_core(index, &options, provider, &mut writer)
            }
            None => archive.extract_member_attached_to_writer(index, &options, &mut writer),
        };
        report.finish(archive, index, result)
    }

    /// Decode this member into one writer per volume it spans.
    ///
    /// `writer_factory` is called with a volume index — the volume set's own
    /// numbering, the same one [`RarVolumeFacts`](crate::RarVolumeFacts) reports
    /// and `add_volume` accepts — every time the member crosses into a new
    /// volume, and the writer it returns receives that volume's contribution.
    /// The returned pairs are `(volume_index, bytes_written)` in the order the
    /// chunks were produced.
    ///
    /// The writer type is yours: it needs neither `Send` nor `'static`, so a
    /// writer holding `&RefCell<_>` or `Rc<_>` is fine.
    ///
    /// A non-solid archive needs a provider for this — acquire the entry with
    /// [`by_index_via`](RarArchive::by_index_via), or the call raises
    /// [`RarError::VolumeProviderRequired`]. Volume attribution for a
    /// non-solid member comes from the provider's segment stream, and there is
    /// no attribution to report without one. A solid archive with its volumes
    /// attached needs no provider.
    pub fn copy_to_volumes<W, F>(self, mut writer_factory: F) -> RarResult<Vec<(usize, u64)>>
    where
        W: Write,
        F: FnMut(usize) -> RarResult<W>,
    {
        self.check_solid_poison()?;
        let options = self.options();
        let Entry {
            archive,
            index,
            info,
            provider,
            progress,
            ..
        } = self;
        let report = Report::start(&info, progress);
        let factory = |volume| writer_factory(volume).map(|writer| report.wrap(writer));
        let result = match provider {
            Some(provider) => {
                archive.extract_member_streaming_chunked_core(index, &options, provider, factory)
            }
            None if archive.is_solid() => {
                archive.extract_member_solid_chunked_core(index, &options, factory)
            }
            None => Err(RarError::VolumeProviderRequired {
                member: info.name.clone(),
            }),
        };
        report.finish(archive, index, result)
    }

    /// Write this member to `path`, applying the metadata the archive carries.
    ///
    /// Times, permissions, Windows attributes and — when
    /// [`set_restore_owners`](RarArchive::set_restore_owners) is on — Unix owner
    /// and group are applied to the file once its bytes are down. Directory
    /// members create the directory; symlinks, hardlinks and file copies are
    /// created as such.
    ///
    /// Returns the number of bytes written.
    pub fn unpack_to<P: AsRef<Path>>(self, path: P) -> RarResult<u64> {
        self.check_solid_poison()?;
        let options = self.options();
        let Entry {
            archive,
            index,
            progress,
            ..
        } = self;
        // The file path reports progress itself, so no wrapper here.
        let result = archive.extract_member_to_file_core(index, &options, progress, path.as_ref());
        poison_on_error(archive, index, result)
    }

    /// Write this member under `dir`, at the path its name states.
    ///
    /// The name is sanitized first, so a member whose stored name reaches
    /// outside the directory lands inside it instead. Intermediate directories
    /// are created. Returns the path written.
    pub fn unpack_in<P: AsRef<Path>>(self, dir: P) -> RarResult<PathBuf> {
        let relative = crate::path::sanitize_path(&self.info.raw_name);
        let destination = dir.as_ref().join(&relative);
        self.unpack_to(&destination)?;
        Ok(destination)
    }

    /// Advance past this member without producing its bytes.
    ///
    /// In a solid archive this still decodes the member — the dictionary the
    /// next member needs is built from it — but discards the output. In a
    /// non-solid archive nothing is decoded and the member's declared size is
    /// returned.
    pub fn skip(self) -> RarResult<u64> {
        if !self.archive.member_is_solid_at(self.index) {
            return Ok(self.info.unpacked_size.unwrap_or(0));
        }
        self.check_solid_poison()?;
        let options = self.options();
        let Entry {
            archive,
            index,
            info,
            progress,
            ..
        } = self;
        let report = Report::start(&info, progress);
        let mut sink = report.wrap(io::sink());
        let result = archive.extract_member_solid_to_writer_local(index, &options, &mut sink);
        report.finish(archive, index, result)
    }

    /// Decode the whole member into the spool a [`Read`] serves from.
    fn fill_spool(&mut self) -> io::Result<()> {
        if self.spool.is_some() {
            return Ok(());
        }
        self.check_solid_poison().map_err(io::Error::other)?;
        let options = self.options();
        let index = self.index;
        let progress = self.progress;
        let result = self
            .archive
            .extract_member_with_link_policy(index, &options, progress, false, None)
            .and_then(|member| member.into_reader());
        let reader = poison_on_error(self.archive, index, result).map_err(io::Error::other)?;
        self.spool = Some(reader);
        Ok(())
    }
}

/// Record that a solid member left the decoder mid-stream.
///
/// Every failure poisons except the two that are refusals rather than
/// interrupted decodes: an out-of-order request never touched the decoder, and
/// an already-poisoned archive is not poisoned twice.
fn poison_on_error<T>(
    archive: &mut RarArchive,
    index: usize,
    result: RarResult<T>,
) -> RarResult<T> {
    let Err(error) = result else {
        return result;
    };
    if archive.member_is_solid_at(index)
        && !matches!(
            error,
            RarError::SolidOrderViolation { .. } | RarError::SolidStatePoisoned { .. }
        )
        && archive.solid_poison.is_none()
    {
        archive.solid_poison = Some((index, error.to_string()));
    }
    Err(error)
}

/// One member's progress reporting, from the start event to the completion
/// event, shared by every writer the consuming call hands the decoder.
struct Report<'r> {
    info: &'r MemberInfo,
    progress: Option<&'r dyn ProgressHandler>,
    written: Cell<u64>,
}

impl<'r> Report<'r> {
    fn start(info: &'r MemberInfo, progress: Option<&'r dyn ProgressHandler>) -> Self {
        if let Some(progress) = progress {
            progress.on_member_start(info);
        }
        Self {
            info,
            progress,
            written: Cell::new(0),
        }
    }

    /// Count what passes through `writer` towards this member's total.
    fn wrap<W: Write>(&self, writer: W) -> Reporting<'_, 'r, W> {
        Reporting {
            inner: writer,
            report: self,
        }
    }

    /// Poison the archive if the consumption failed mid-member, then report the
    /// outcome and hand it back.
    fn finish<T>(
        &self,
        archive: &mut RarArchive,
        index: usize,
        result: RarResult<T>,
    ) -> RarResult<T> {
        let result = poison_on_error(archive, index, result);
        let Some(progress) = self.progress else {
            return result;
        };
        match result {
            Ok(value) => {
                progress.on_member_complete(self.info, &Ok(()));
                Ok(value)
            }
            Err(error) => {
                let failure: Result<(), RarError> = Err(error);
                progress.on_member_complete(self.info, &failure);
                failure.map(|()| unreachable!("a failure holds no value"))
            }
        }
    }
}

/// A writer that adds what it receives to its member's running byte count.
struct Reporting<'a, 'r, W> {
    inner: W,
    report: &'a Report<'r>,
}

impl<W: Write> Write for Reporting<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        let total = self.report.written.get() + written as u64;
        self.report.written.set(total);
        if let Some(progress) = self.report.progress {
            progress.on_member_progress(self.report.info, total);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Names the member the handle is open on, without the archive behind it.
impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("index", &self.index)
            .field("name", &self.info.name)
            .finish_non_exhaustive()
    }
}

/// Read a member's bytes without choosing a sink for them.
///
/// The first [`read`](Read::read) decodes the whole member into a spool — held
/// in memory below a threshold, in a temporary file above it, and always in
/// memory on wasm — and every read after that serves from the spool. Prefer
/// [`copy_to`](Entry::copy_to) when the destination is already a writer: it
/// hands the decoder's output straight over with no spool in between.
impl Read for Entry<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_spool()?;
        match &mut self.spool {
            Some(reader) => reader.read(buf),
            None => Ok(0),
        }
    }
}

impl RarArchive {
    /// Take the member at `index`, reading its volumes from those attached.
    ///
    /// Decodes nothing. See [`Entry`] for what the handle can do and for how
    /// solid archives constrain the order. An index the archive does not list
    /// raises [`RarError::MemberIndexOutOfRange`].
    pub fn by_index(&mut self, index: usize) -> RarResult<Entry<'_>> {
        Entry::new(self, index, None)
    }

    /// Take the member stored under `name`.
    ///
    /// The name is matched against the raw header name, as
    /// [`index_for_name`](Self::index_for_name) does. A name the archive does
    /// not list raises [`RarError::MemberNotFound`].
    pub fn by_name(&mut self, name: &str) -> RarResult<Entry<'_>> {
        let index = self
            .find_member(name)
            .ok_or_else(|| RarError::MemberNotFound {
                name: name.to_string(),
            })?;
        Entry::new(self, index, None)
    }

    /// Take the member at `index`, reading its volumes from `provider`.
    ///
    /// This is how a member is extracted while its volumes are still arriving,
    /// or from volumes that are not files at all. The provider is borrowed for
    /// the life of the handle rather than stored on the archive.
    ///
    /// Volumes are addressed in the **set's own numbering** — a member whose
    /// first segment lives in volume 5 asks the provider for volume 5. Do not
    /// re-key a provider to the member's first volume.
    pub fn by_index_via<'a>(
        &'a mut self,
        index: usize,
        provider: &'a dyn VolumeProvider,
    ) -> RarResult<Entry<'a>> {
        Entry::new(self, index, Some(provider))
    }
}
