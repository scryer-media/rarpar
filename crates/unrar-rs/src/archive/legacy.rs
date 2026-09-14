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
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
        self.extract_member_solid_to_writer_local(index, options, writer)
    }

    /// Advance through a solid member while discarding its produced bytes.
    #[deprecated(since = "0.9.0", note = "use by_index(index)?.skip()")]
    pub fn skip_member_solid(&mut self, index: usize, options: &ExtractOptions) -> RarResult<u64> {
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
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
        let _decode = self.decode_mode.enter();
        self.extract_member_streaming_chunked_core(index, options, provider, writer_factory)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct ObservedReader {
        file: File,
        armed: Arc<AtomicBool>,
        reads: Arc<AtomicUsize>,
        expected_serial: bool,
    }

    impl Read for ObservedReader {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.armed.load(Ordering::Relaxed) {
                assert_eq!(crate::decompress::policy::serial(), self.expected_serial);
                self.reads.fetch_add(1, Ordering::Relaxed);
            }
            self.file.read(bytes)
        }
    }

    impl Seek for ObservedReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.file.seek(pos)
        }
    }

    struct ObservedProvider {
        path: std::path::PathBuf,
        armed: Arc<AtomicBool>,
        reads: Arc<AtomicUsize>,
        expected_serial: bool,
    }

    impl ObservedProvider {
        fn reader(&self) -> ObservedReader {
            ObservedReader {
                file: File::open(&self.path).unwrap(),
                armed: Arc::clone(&self.armed),
                reads: Arc::clone(&self.reads),
                expected_serial: self.expected_serial,
            }
        }
    }

    impl VolumeProvider for ObservedProvider {
        fn get_volume(
            &self,
            index: usize,
        ) -> Result<Box<dyn crate::ReadSeek>, crate::VolumeProviderError> {
            assert_eq!(index, 0);
            Ok(Box::new(self.reader()))
        }
    }

    #[test]
    fn all_legacy_consumers_scope_decode_policy_and_restore_it() {
        check_legacy_consumers(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        );
    }

    #[test]
    fn legacy_consumers_allow_an_unhydrated_corpus() {
        let dir = tempfile::tempdir().unwrap();
        check_legacy_consumers(dir.path());
        std::fs::create_dir(dir.path().join("rar5")).unwrap();
        std::fs::write(
            dir.path().join("rar5/rar5_solid.rar"),
            b"version https://git-lfs.github.com/spec/v1\n",
        )
        .unwrap();
        check_legacy_consumers(dir.path());
    }

    fn check_legacy_consumers(root: &std::path::Path) {
        for fixture in ["rar5/rar5_solid.rar", "rar4/rar4_lz_solid_mv.rar"] {
            let path = root.join(fixture);
            let mut magic = [0; 4];
            if !File::open(&path)
                .is_ok_and(|mut file| file.read_exact(&mut magic).is_ok() && &magic == b"Rar!")
            {
                eprintln!("skipping unhydrated fixture: {}", path.display());
                continue;
            }
            for mode in [crate::DecodeMode::Auto, crate::DecodeMode::Serial] {
                for consumer in 0..8 {
                    let provider = ObservedProvider {
                        path: path.clone(),
                        armed: Arc::new(AtomicBool::new(false)),
                        reads: Arc::new(AtomicUsize::new(0)),
                        expected_serial: mode == crate::DecodeMode::Serial,
                    };
                    let mut archive = RarArchive::open(provider.reader()).unwrap();
                    archive.set_decode_mode(mode);
                    let name = archive.members[0].file_header.name.clone();
                    let options = ExtractOptions::default();
                    let dir = tempfile::tempdir().unwrap();
                    let mut sink = std::io::sink();
                    provider.armed.store(true, Ordering::Relaxed);
                    let outer = crate::DecodeMode::Serial.enter();
                    match consumer {
                        0 => {
                            archive.extract_member(0, &options, None).unwrap();
                        }
                        1 => {
                            archive.extract_by_name(&name, &options, None).unwrap();
                        }
                        2 => {
                            archive
                                .extract_member_to_file(0, &options, None, &dir.path().join("out"))
                                .unwrap();
                        }
                        3 => {
                            archive
                                .extract_member_solid_to_writer(0, &options, &mut sink)
                                .unwrap();
                        }
                        4 => {
                            archive.skip_member_solid(0, &options).unwrap();
                        }
                        5 => {
                            archive
                                .extract_member_solid_chunked(0, &options, |_| {
                                    Ok(Box::new(std::io::sink()))
                                })
                                .unwrap();
                        }
                        6 => {
                            archive
                                .extract_member_streaming(0, &options, &provider, &mut sink)
                                .unwrap();
                        }
                        7 => {
                            archive
                                .extract_member_streaming_chunked(0, &options, &provider, |_| {
                                    Ok(Box::new(std::io::sink()))
                                })
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                    assert!(
                        provider.reads.load(Ordering::Relaxed) > 0,
                        "{fixture} {consumer}"
                    );
                    assert!(crate::decompress::policy::serial());
                    assert!(archive.extract_member(usize::MAX, &options, None).is_err());
                    assert!(
                        crate::decompress::policy::serial(),
                        "restore policy on error"
                    );
                    drop(outer);
                    assert!(!crate::decompress::policy::serial());
                }
            }
        }
    }
}
