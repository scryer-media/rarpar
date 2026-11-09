use std::sync::Arc;

use crate::decompress::lz::window::WindowSource;
use crate::window_memory::WindowAllocator;

/// Minimum LZ window allocation used by modern RAR unpackers.
///
/// RAR5 headers can declare 128 KiB, but the extraction window uses at least
/// 256 KiB so filter accounting always has enough room.
pub const RAR_MIN_LZ_WINDOW_SIZE: u64 = 0x40000;

/// Maximum dictionary size accepted for RAR extraction.
pub const RAR_UNPACK_MAX_DICT_SIZE: u64 = 0x1000000000;

/// Largest PPMd model arena a RAR3 block header can declare.
///
/// The header stores the arena size as one byte `mem`, and the model is
/// started over `(mem + 1)` MiB, so 256 MiB is the format's ceiling.
pub const RAR_PPMD_MAX_ARENA_SIZE: u64 = 256 << 20;

/// Maximum RAR5 header body size accepted by the parser.
pub const RAR5_MAX_HEADER_BODY: u64 = 0x200000;

/// Finite anti-abuse ceiling for a single packed or unpacked member.
pub const MAX_MEMBER_DATA_SIZE: u64 = 500 * 1024 * 1024 * 1024;

/// Maximum volume number accepted from an archive header.
///
/// [`crate::volume::VolumeSet`] and `RarArchive::volumes` are dense, index-addressed
/// vectors, so a volume number lifted straight out of a header sizes an allocation.
/// RAR5 encodes that field as an unbounded vint, so a 130-byte file can declare volume
/// 5e17 and ask for hundreds of thousands of terabytes before a single member byte is
/// read. Real sets stay far below this ceiling: [`MAX_MEMBER_DATA_SIZE`] split
/// into 512 KiB volumes is still only ~1M parts.
pub const RAR_MAX_VOLUME_NUMBER: u64 = 1 << 20;

/// Maximum number of headers accepted from a single archive volume.
///
/// Every header a volume scan accepts appends to a `Vec` (`files`, `services`,
/// `comments`, …), so an unterminated scan is unbounded memory as well as
/// unbounded time. The RAR4 parser's forward-only header traversal
/// already makes a scan structurally monotonic, and each RAR4 header consumes
/// at least 7 bytes, so this is a backstop rather than the primary defence —
/// it caps the damage from any *future* way of re-reading the same offset.
/// Even minimum-size RAR4 headers require roughly 7 MiB to reach this ceiling;
/// the volume's byte length alone is not a useful bound on retained header state.
pub const MAX_HEADERS_PER_VOLUME: usize = 1 << 20;

/// Convert a header-declared volume number into a dense-vector index.
///
/// Rejects anything above [`RAR_MAX_VOLUME_NUMBER`] rather than letting an untrusted
/// vint size a `Vec`.
pub fn checked_volume_number(declared: u64) -> crate::error::RarResult<usize> {
    if declared > RAR_MAX_VOLUME_NUMBER {
        return Err(crate::error::RarError::resource_limit(
            crate::error::LimitKind::VolumeNumber,
            declared,
            RAR_MAX_VOLUME_NUMBER,
            None,
        ));
    }
    Ok(declared as usize)
}

/// Configurable limits for archive processing to prevent resource exhaustion.
///
/// Start from [`Limits::default`] and change what you need: assign a public
/// field, or use a `with_*` setter. The struct is `#[non_exhaustive]`, so a
/// field added later does not break your code.
///
/// ```
/// let mut limits = unrar_rs::Limits::default();
/// limits.max_dict_size = 64 << 20;
/// let limits = limits.with_max_allocated_dict_size(1 << 30);
/// assert_eq!(limits.max_allocated_dict_size, 1 << 30);
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum header body size in bytes (default 2 MiB).
    pub max_header_size: u64,
    /// Maximum single data segment size in bytes.
    pub max_data_segment: u64,
    /// Maximum unpacked output size in bytes.
    pub max_unpacked_size: u64,
    /// Maximum dictionary size in bytes (default 256 MB) the decoder allocates
    /// on the heap.
    ///
    /// Without a [`window_allocator`](Self::window_allocator), a larger
    /// dictionary fails with
    /// [`RarError::DictionaryTooLarge`](crate::RarError::DictionaryTooLarge).
    pub max_dict_size: u64,
    /// Supplies the LZ window for a dictionary larger than
    /// [`max_dict_size`](Self::max_dict_size), up to
    /// [`max_allocated_dict_size`](Self::max_allocated_dict_size), instead of
    /// refusing it (default `None`), and the PPMd model arena for an arena
    /// larger than [`max_heap_ppmd_arena_size`](Self::max_heap_ppmd_arena_size).
    /// Set it with [`with_window_allocator`](Self::with_window_allocator).
    /// See [`crate::window_memory`] for the memory contract.
    pub window_allocator: Option<Arc<dyn WindowAllocator>>,
    /// Largest dictionary, in bytes, the
    /// [`window_allocator`](Self::window_allocator) is asked for (default
    /// [`RAR_UNPACK_MAX_DICT_SIZE`], the format's 64 GiB maximum). A larger
    /// dictionary fails with
    /// [`RarError::DictionaryTooLarge`](crate::RarError::DictionaryTooLarge).
    /// Unused without an allocator.
    pub max_allocated_dict_size: u64,
    /// Maximum PPMd model arena, in bytes, a RAR3 PPMd block header may ask
    /// for (default [`RAR_PPMD_MAX_ARENA_SIZE`], the format's 256 MiB
    /// ceiling, so the default admits every valid archive).
    ///
    /// The header's memory-size byte `mem` declares an arena of
    /// `(mem + 1) << 20` bytes. A block that declares more than this limit
    /// fails with [`RarError::ResourceLimit`](crate::RarError::ResourceLimit)
    /// before the arena is allocated. The model's fixed tables come on top of
    /// the arena and are not counted here.
    ///
    /// The limit holds for every arena, lent or not: it is also the largest
    /// arena the [`window_allocator`](Self::window_allocator) is asked for.
    pub max_ppmd_arena_size: u64,
    /// Largest PPMd model arena, in bytes, the decoder keeps in its own
    /// memory when a [`window_allocator`](Self::window_allocator) is set
    /// (default [`RAR_PPMD_MAX_ARENA_SIZE`], so by default no arena is lent).
    ///
    /// A larger arena, up to [`max_ppmd_arena_size`](Self::max_ppmd_arena_size),
    /// is asked of the window allocator, under the same memory contract as a
    /// window (see [`crate::window_memory`]). Set it with
    /// [`with_max_heap_ppmd_arena_size`](Self::with_max_heap_ppmd_arena_size).
    /// Unused without an allocator.
    pub max_heap_ppmd_arena_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_size: RAR5_MAX_HEADER_BODY,
            max_data_segment: MAX_MEMBER_DATA_SIZE,
            max_unpacked_size: MAX_MEMBER_DATA_SIZE,
            max_dict_size: 256 * 1024 * 1024, // 256 MB
            window_allocator: None,
            max_allocated_dict_size: RAR_UNPACK_MAX_DICT_SIZE,
            max_ppmd_arena_size: RAR_PPMD_MAX_ARENA_SIZE,
            max_heap_ppmd_arena_size: RAR_PPMD_MAX_ARENA_SIZE,
        }
    }
}

impl std::fmt::Debug for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limits")
            .field("max_header_size", &self.max_header_size)
            .field("max_data_segment", &self.max_data_segment)
            .field("max_unpacked_size", &self.max_unpacked_size)
            .field("max_dict_size", &self.max_dict_size)
            .field(
                "window_allocator",
                &self.window_allocator.as_ref().map(|_| "<allocator>"),
            )
            .field("max_allocated_dict_size", &self.max_allocated_dict_size)
            .field("max_ppmd_arena_size", &self.max_ppmd_arena_size)
            .field("max_heap_ppmd_arena_size", &self.max_heap_ppmd_arena_size)
            .finish()
    }
}

impl Limits {
    /// Lend the LZ window for dictionaries above
    /// [`max_dict_size`](Self::max_dict_size), up to
    /// [`max_allocated_dict_size`](Self::max_allocated_dict_size), and the
    /// PPMd model arena for arenas above
    /// [`max_heap_ppmd_arena_size`](Self::max_heap_ppmd_arena_size), up to
    /// [`max_ppmd_arena_size`](Self::max_ppmd_arena_size), from `allocator`.
    /// See [`crate::window_memory`].
    #[must_use]
    pub fn with_window_allocator(mut self, allocator: Arc<dyn WindowAllocator>) -> Self {
        self.window_allocator = Some(allocator);
        self
    }

    /// Set the largest dictionary, in bytes, the
    /// [`window_allocator`](Self::window_allocator) is asked for.
    #[must_use]
    pub fn with_max_allocated_dict_size(mut self, bytes: u64) -> Self {
        self.max_allocated_dict_size = bytes;
        self
    }

    /// Set the largest PPMd model arena, in bytes, the decoder keeps in its
    /// own memory; a larger one, up to
    /// [`max_ppmd_arena_size`](Self::max_ppmd_arena_size), is asked of the
    /// [`window_allocator`](Self::window_allocator).
    #[must_use]
    pub fn with_max_heap_ppmd_arena_size(mut self, bytes: u64) -> Self {
        self.max_heap_ppmd_arena_size = bytes;
        self
    }

    /// Largest dictionary these limits admit: [`Self::max_dict_size`], or
    /// with an allocator also [`Self::max_allocated_dict_size`].
    pub(crate) fn dict_size_ceiling(&self) -> u64 {
        self.window_source().max_dict_size()
    }

    /// Where the decoder's LZ window and PPMd model arena come from under
    /// these limits.
    pub(crate) fn window_source(&self) -> WindowSource {
        WindowSource::new(
            self.max_dict_size,
            self.window_allocator.clone(),
            self.max_allocated_dict_size,
        )
        .with_max_owned_ppmd_arena(self.max_heap_ppmd_arena_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = Limits::default();
        assert_eq!(limits.max_header_size, RAR5_MAX_HEADER_BODY);
        assert_eq!(limits.max_data_segment, MAX_MEMBER_DATA_SIZE);
        assert_eq!(limits.max_unpacked_size, MAX_MEMBER_DATA_SIZE);
        assert_eq!(limits.max_dict_size, 256 * 1024 * 1024);
        assert_eq!(limits.max_ppmd_arena_size, RAR_PPMD_MAX_ARENA_SIZE);
        assert_eq!(RAR_PPMD_MAX_ARENA_SIZE, 256 << 20);
        assert!(limits.window_allocator.is_none());
        assert_eq!(limits.max_allocated_dict_size, RAR_UNPACK_MAX_DICT_SIZE);
        assert_eq!(limits.max_heap_ppmd_arena_size, RAR_PPMD_MAX_ARENA_SIZE);
        // Without an allocator the allocator ceiling admits nothing more.
        assert_eq!(limits.dict_size_ceiling(), limits.max_dict_size);
    }

    #[test]
    fn default_member_data_limit_covers_large_media_members() {
        let observed_bluray_member_size = 68_325_814_272;
        assert!(observed_bluray_member_size <= Limits::default().max_unpacked_size);
        assert_eq!(MAX_MEMBER_DATA_SIZE, 500 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_custom_limits() {
        let limits = Limits {
            max_header_size: 1024,
            max_data_segment: 2048,
            max_unpacked_size: 4096,
            max_dict_size: 8192,
            max_ppmd_arena_size: 1 << 20,
            ..Default::default()
        };
        assert_eq!(limits.max_header_size, 1024);
        assert_eq!(limits.max_data_segment, 2048);
        assert_eq!(limits.max_unpacked_size, 4096);
        assert_eq!(limits.max_dict_size, 8192);
        assert_eq!(limits.max_ppmd_arena_size, 1 << 20);
    }

    #[test]
    fn volume_number_at_the_cap_is_accepted() {
        assert_eq!(
            checked_volume_number(RAR_MAX_VOLUME_NUMBER).unwrap(),
            RAR_MAX_VOLUME_NUMBER as usize
        );
        assert_eq!(checked_volume_number(0).unwrap(), 0);
    }

    #[test]
    fn volume_number_above_the_cap_is_rejected() {
        for declared in [
            RAR_MAX_VOLUME_NUMBER + 1,
            // The value the ClusterFuzzLite `rar_headers` OOM declared.
            508_427_613_235_168_135,
            u64::MAX,
        ] {
            assert!(
                matches!(
                    checked_volume_number(declared),
                    Err(crate::error::RarError::ResourceLimit { .. })
                ),
                "volume number {declared} should be rejected"
            );
        }
    }
}
