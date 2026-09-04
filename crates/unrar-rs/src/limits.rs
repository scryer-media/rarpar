/// Minimum LZ window allocation used by modern RAR unpackers.
///
/// RAR5 headers can declare 128 KiB, but the extraction window uses at least
/// 256 KiB so filter accounting always has enough room.
pub const RAR_MIN_LZ_WINDOW_SIZE: u64 = 0x40000;

/// Maximum dictionary size accepted for RAR extraction.
pub const RAR_UNPACK_MAX_DICT_SIZE: u64 = 0x1000000000;

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

/// Convert a header-declared volume number into a dense-vector index.
///
/// Rejects anything above [`RAR_MAX_VOLUME_NUMBER`] rather than letting an untrusted
/// vint size a `Vec`.
pub fn checked_volume_number(declared: u64) -> crate::error::RarResult<usize> {
    if declared > RAR_MAX_VOLUME_NUMBER {
        return Err(crate::error::RarError::ResourceLimit {
            detail: format!(
                "archive declares volume number {declared}, above the {RAR_MAX_VOLUME_NUMBER} limit"
            ),
        });
    }
    Ok(declared as usize)
}

/// Configurable limits for archive processing to prevent resource exhaustion.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum header body size in bytes (default 2 MiB).
    pub max_header_size: u64,
    /// Maximum single data segment size in bytes.
    pub max_data_segment: u64,
    /// Maximum unpacked output size in bytes.
    pub max_unpacked_size: u64,
    /// Maximum dictionary size in bytes (default 256 MB).
    pub max_dict_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_size: RAR5_MAX_HEADER_BODY,
            max_data_segment: MAX_MEMBER_DATA_SIZE,
            max_unpacked_size: MAX_MEMBER_DATA_SIZE,
            max_dict_size: 256 * 1024 * 1024, // 256 MB
        }
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
        };
        assert_eq!(limits.max_header_size, 1024);
        assert_eq!(limits.max_data_segment, 2048);
        assert_eq!(limits.max_unpacked_size, 4096);
        assert_eq!(limits.max_dict_size, 8192);
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
