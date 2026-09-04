//! The pre-0.9.0 extraction entry points, kept as thin wrappers.
//!
//! Each one behaves exactly as it did: it threads an [`ExtractOptions`] through
//! to the same engine the [`Entry`](crate::Entry) handle uses. They are
//! scheduled for removal in 0.10.0, and the replacement for every one of them
//! is [`RarArchive::by_index`] plus a consuming call on the handle.

use std::io::Write;

use crate::archive::RarArchive;
use crate::error::{RarError, RarResult};
use crate::extract::{ExtractOptions, ExtractedMember};
use crate::progress::ProgressHandler;
use crate::volume::VolumeProvider;

impl RarArchive {
    /// Extract a member by index, handling any supported compression method.
    ///
    /// For multi-volume archives, this seamlessly reads data across volumes.
    #[deprecated(
        since = "0.9.0",
        note = "use by_index(index)? and read the entry, or copy_to a writer"
    )]
    pub fn extract_member(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        progress: Option<&dyn ProgressHandler>,
    ) -> RarResult<ExtractedMember> {
        self.extract_member_with_link_policy(index, options, progress, false, None)
    }

    /// Extract a member by name, handling any supported compression method.
    #[deprecated(
        since = "0.9.0",
        note = "use by_name(name)? and read the entry, or copy_to a writer"
    )]
    pub fn extract_by_name(
        &mut self,
        name: &str,
        options: &ExtractOptions,
        progress: Option<&dyn ProgressHandler>,
    ) -> RarResult<ExtractedMember> {
        let index = self
            .find_member(name)
            .ok_or_else(|| RarError::MemberNotFound {
                name: name.to_string(),
            })?;
        self.extract_member_with_link_policy(index, options, progress, false, None)
    }

    /// Extract a member directly to a file, streaming data to disk.
    #[deprecated(since = "0.9.0", note = "use by_index(index)?.unpack_to(path)")]
    pub fn extract_member_to_file(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        progress: Option<&dyn ProgressHandler>,
        out_path: &std::path::Path,
    ) -> RarResult<u64> {
        self.extract_member_to_file_core(index, options, progress, out_path)
    }

    /// Extract one member from an attached solid archive into a borrowed writer.
    #[deprecated(since = "0.9.0", note = "use by_index(index)?.copy_to(writer)")]
    pub fn extract_member_solid_to_writer<W: Write + ?Sized>(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        writer: &mut W,
    ) -> RarResult<u64> {
        self.extract_member_solid_to_writer_local(index, options, writer)
    }

    /// Advance through a solid member while discarding its produced bytes.
    #[deprecated(since = "0.9.0", note = "use by_index(index)?.skip()")]
    pub fn skip_member_solid(&mut self, index: usize, options: &ExtractOptions) -> RarResult<u64> {
        let mut sink = std::io::sink();
        self.extract_member_solid_to_writer_local(index, options, &mut sink)
    }

    /// Extract a solid member into per-volume chunk writers while preserving
    /// the archive's solid decoder state across sequential members.
    #[deprecated(
        since = "0.9.0",
        note = "use by_index(index)?.copy_to_volumes(writer_factory)"
    )]
    pub fn extract_member_solid_chunked<F>(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        self.extract_member_solid_chunked_core(index, options, writer_factory)
    }

    /// Extract a member by streaming segments through a [`VolumeProvider`].
    ///
    /// Volumes are addressed in the volume set's own numbering: a member whose
    /// first segment lives in volume 5 calls `provider.get_volume(5)`.
    #[deprecated(
        since = "0.9.0",
        note = "use by_index_via(index, provider)?.copy_to(writer)"
    )]
    pub fn extract_member_streaming<W: Write>(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        provider: &dyn VolumeProvider,
        writer: &mut W,
    ) -> RarResult<u64> {
        self.extract_member_streaming_core(index, options, provider, writer)
    }

    /// Extract a member with per-volume output splitting.
    ///
    /// Every `volume_index` here — the provider's, the factory's, and the
    /// returned chunks' — is the volume set's own.
    #[deprecated(
        since = "0.9.0",
        note = "use by_index_via(index, provider)?.copy_to_volumes(writer_factory)"
    )]
    pub fn extract_member_streaming_chunked<F>(
        &mut self,
        index: usize,
        options: &ExtractOptions,
        provider: &dyn VolumeProvider,
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        self.extract_member_streaming_chunked_core(index, options, provider, writer_factory)
    }
}
