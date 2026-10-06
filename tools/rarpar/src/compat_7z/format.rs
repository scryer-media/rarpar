//! The strings 7-Zip prints for methods, attributes, times and sizes.

use sevenz_turbo::{Archive, Block, Coder};

const COPY: u64 = 0x00;
const DELTA: u64 = 0x03;
const BCJ: u64 = 0x0303_0103;
const BCJ2: u64 = 0x0303_011B;
const PPC: u64 = 0x0303_0205;
const IA64: u64 = 0x0303_0401;
const ARM: u64 = 0x0303_0501;
const ARMT: u64 = 0x0303_0701;
const SPARC: u64 = 0x0303_0805;
const ARM64: u64 = 0x0A;
const RISCV: u64 = 0x0B;
const SWAP2: u64 = 0x02_0302;
const SWAP4: u64 = 0x02_0304;
const LZMA: u64 = 0x03_0101;
const LZMA2: u64 = 0x21;
const PPMD: u64 = 0x03_0401;
const BZIP2: u64 = 0x04_0202;
const DEFLATE: u64 = 0x04_0108;
const DEFLATE64: u64 = 0x04_0109;
pub(super) const AES: u64 = 0x06F1_0701;

/// The coder's method id as the number 7-Zip compares and sorts.
pub(super) fn coder_id(coder: &Coder) -> u64 {
    coder
        .encoder_method_id()
        .iter()
        .fold(0u64, |id, byte| (id << 8) | u64::from(*byte))
}

/// Whether the block decrypts with 7zAES.
pub(super) fn block_is_encrypted(block: &Block) -> bool {
    block.coders.iter().any(|coder| coder_id(coder) == AES)
}

fn method_name(id: u64) -> Option<&'static str> {
    Some(match id {
        COPY => "Copy",
        DELTA => "Delta",
        BCJ => "BCJ",
        BCJ2 => "BCJ2",
        PPC => "PPC",
        IA64 => "IA64",
        ARM => "ARM",
        ARMT => "ARMT",
        SPARC => "SPARC",
        ARM64 => "ARM64",
        RISCV => "RISCV",
        SWAP2 => "Swap2",
        SWAP4 => "Swap4",
        LZMA => "LZMA",
        LZMA2 => "LZMA2",
        PPMD => "PPMD",
        BZIP2 => "BZip2",
        DEFLATE => "Deflate",
        DEFLATE64 => "Deflate64",
        AES => "7zAES",
        _ => return None,
    })
}

/// An unknown method id, as 7-Zip spells it: its bytes in hex.
fn method_id_hex(id: u64) -> String {
    let bytes = id.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first..]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn named(id: u64) -> String {
    method_name(id).map_or_else(|| method_id_hex(id), str::to_owned)
}

/// 7-Zip's `GetStringForSizeValue`: a power of two as its exponent, else a
/// count of MiB, KiB or bytes.
pub(super) fn size_value(value: u32) -> String {
    if value.is_power_of_two() {
        return value.trailing_zeros().to_string();
    }
    if value & ((1 << 20) - 1) == 0 {
        format!("{}m", value >> 20)
    } else if value & ((1 << 10) - 1) == 0 {
        format!("{}k", value >> 10)
    } else {
        format!("{value}b")
    }
}

/// 7-Zip's `GetLzma2String` for an LZMA2 dictionary property.
pub(super) fn lzma2_value(prop: u32) -> String {
    if prop > 40 {
        return String::new();
    }
    if prop & 1 == 0 {
        return ((prop >> 1) + 12).to_string();
    }
    let mut shift = (prop >> 1) + 1;
    let mut unit = 'k';
    if shift >= 10 {
        unit = 'm';
        shift -= 10;
    }
    format!("{}{unit}", 3u32 << shift)
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The archive's `Method` property: every method once, ordered by id.
pub(super) fn archive_method(archive: &Archive) -> String {
    let mut ids: Vec<u64> = Vec::new();
    let mut lzma2_prop = 0u32;
    let mut lzma_dict = 0u32;
    for block in &archive.blocks {
        for coder in &block.coders {
            let id = coder_id(coder);
            if let Err(at) = ids.binary_search(&id)
                && ids.len() < 128
            {
                ids.insert(at, id);
            }
            let props = coder.properties();
            if id == LZMA2 && props.len() == 1 {
                lzma2_prop = lzma2_prop.max(u32::from(props[0]));
            } else if id == LZMA && props.len() == 5 {
                lzma_dict = lzma_dict.max(le32(&props[1..]));
            }
        }
    }
    let mut out = String::new();
    for id in ids {
        if !out.is_empty() {
            out.push(' ');
        }
        match id {
            LZMA2 => {
                out.push_str("LZMA2:");
                out.push_str(&lzma2_value(lzma2_prop));
            }
            LZMA => {
                out.push_str("LZMA:");
                out.push_str(&size_value(lzma_dict));
            }
            _ => out.push_str(&named(id)),
        }
    }
    out
}

/// One coder's name and properties, as a file's `Method` lists it.
fn coder_string(coder: &Coder) -> String {
    let id = coder_id(coder);
    let props = coder.properties();
    let detail = match id {
        LZMA if props.len() == 5 => {
            let mut s = size_value(le32(&props[1..]));
            let mut d = u32::from(props[0]);
            if d != 0x5D {
                let lc = d % 9;
                d /= 9;
                let pb = d / 5;
                let lp = d % 5;
                if lc != 3 {
                    s.push_str(&format!(":lc{lc}"));
                }
                if lp != 0 {
                    s.push_str(&format!(":lp{lp}"));
                }
                if pb != 2 {
                    s.push_str(&format!(":pb{pb}"));
                }
            }
            s
        }
        LZMA2 if props.len() == 1 => lzma2_value(u32::from(props[0])),
        PPMD if props.len() == 5 => format!("o{}:mem{}", props[0], size_value(le32(&props[1..]))),
        DELTA if props.len() == 1 => (u32::from(props[0]) + 1).to_string(),
        ARM64 | RISCV if props.len() == 4 => le32(props).to_string(),
        AES if !props.is_empty() => (props[0] & 0x3F).to_string(),
        _ => String::new(),
    };
    let mut out = named(id);
    if !detail.is_empty() {
        out.push(':');
        out.push_str(&detail);
    }
    out
}

/// A file's `Method` property: its block's coders, last stored first.
pub(super) fn block_method(block: &Block) -> String {
    block
        .coders
        .iter()
        .rev()
        .map(coder_string)
        .collect::<Vec<_>>()
        .join(" ")
}

const WIN_ATTRIB_CHARS: &[u8; 30] = b"RHS8DAdNTsLCOIEVvX.PU.M......B";
const POSIX_TYPES: &[u8; 16] = b"0pc3d5b7-9lBsDEF";
pub(super) const ATTRIB_READONLY: u32 = 0x01;
pub(super) const ATTRIB_HIDDEN: u32 = 0x02;
pub(super) const ATTRIB_SYSTEM: u32 = 0x04;
pub(super) const ATTRIB_DIRECTORY: u32 = 0x10;
pub(super) const ATTRIB_ARCHIVE: u32 = 0x20;
pub(super) const ATTRIB_UNIX_EXTENSION: u32 = 0x8000;

fn posix_string(mode: u32) -> String {
    let mut s = vec![POSIX_TYPES[((mode >> 12) & 0xF) as usize]];
    let mut mask = 1u32 << 8;
    for _ in 0..3 {
        for c in *b"rwx" {
            s.push(if mode & mask != 0 { c } else { b'-' });
            mask >>= 1;
        }
    }
    if mode & 0x800 != 0 {
        s[3] = if mode & (1 << 6) != 0 { b's' } else { b'S' };
    }
    if mode & 0x400 != 0 {
        s[6] = if mode & (1 << 3) != 0 { b's' } else { b'S' };
    }
    if mode & 0x200 != 0 {
        s[9] = if mode & 1 != 0 { b't' } else { b'T' };
    }
    String::from_utf8(s).unwrap_or_default()
}

/// `Attributes` in `-slt` output: 7-Zip's `ConvertWinAttribToString`.
pub(super) fn attributes_long(mut wa: u32, is_dir: bool) -> String {
    if is_dir {
        wa |= ATTRIB_DIRECTORY;
    }
    let posix = (wa & ATTRIB_UNIX_EXTENSION != 0).then_some(wa >> 16);
    if posix.is_some() && wa & 0xF000_0000 != 0 {
        wa &= 0x3FFF;
    }
    let mut out = String::new();
    for (bit, c) in WIN_ATTRIB_CHARS.iter().enumerate() {
        let flag = 1u32 << bit;
        if wa & flag != 0 && *c != b'.' {
            wa &= !flag;
            out.push(char::from(*c));
        }
    }
    if wa != 0 {
        out.push_str(&format!(" {wa:08X}"));
    }
    if let Some(mode) = posix {
        out.push(' ');
        out.push_str(&posix_string(mode));
    }
    out
}

/// The five attribute characters of the `l` table.
pub(super) fn attributes_short(mut wa: u32, is_dir: bool) -> String {
    if is_dir {
        wa |= ATTRIB_DIRECTORY;
    }
    let pick = |flag: u32, c: char| if wa & flag != 0 { c } else { '.' };
    [
        pick(ATTRIB_DIRECTORY, 'D'),
        pick(ATTRIB_READONLY, 'R'),
        pick(ATTRIB_HIDDEN, 'H'),
        pick(ATTRIB_SYSTEM, 'S'),
        pick(ATTRIB_ARCHIVE, 'A'),
    ]
    .iter()
    .collect()
}

/// Ticks of 100 ns between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_TICKS: i128 = 116_444_736_000_000_000;

/// A Windows FILETIME tick count as `YYYY-MM-DD HH:MM:SS`, in local time, with
/// `fraction` digits of the second (0 or 7) appended.
pub(super) fn filetime_string(ticks: u64, fraction: bool) -> String {
    if ticks == 0 {
        return String::new();
    }
    let since_unix = i128::from(ticks) - EPOCH_DIFF_TICKS;
    let secs = since_unix.div_euclid(10_000_000) as i64;
    let rest = since_unix.rem_euclid(10_000_000);
    let mut out = local_civil_string(secs);
    if fraction {
        out.push_str(&format!(".{rest:07}"));
    }
    out
}

/// Seconds since the Unix epoch as local `YYYY-MM-DD HH:MM:SS`.
pub(super) fn unix_time_string(secs: i64) -> String {
    local_civil_string(secs)
}

/// Seconds since the Unix epoch as local `YYYY-MM-DD HH:MM:SS`.
fn local_civil_string(secs: i64) -> String {
    let [year, month, day, hour, minute, second] = local_civil(secs);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Local time as 7-Zip shows it on Unix: shifted by the offset from UTC in
/// effect now, whatever the offset was on that date (its
/// `FileTimeToLocalFileTime` takes one offset for every time). Returns year,
/// month, day, hour, minute and second.
#[cfg(unix)]
pub(crate) fn local_civil(secs: i64) -> [i64; 6] {
    static OFFSET: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    let offset = *OFFSET.get_or_init(|| {
        // SAFETY: `time` with a null pointer only returns the clock.
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        // SAFETY: `tm` is plain data and `localtime_r` only writes into it.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are valid for the call.
        let ok = unsafe { !libc::localtime_r(&now, &mut tm).is_null() };
        if ok { tm.tm_gmtoff as i64 } else { 0 }
    });
    utc_civil(secs + offset)
}

#[cfg(not(unix))]
pub(crate) fn local_civil(secs: i64) -> [i64; 6] {
    utc_civil(secs)
}

fn utc_civil(secs: i64) -> [i64; 6] {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    [year, month, day, rem / 3600, (rem / 60) % 60, rem % 60]
}

/// 7-Zip's `PrintSize_bytes_Smart`: `N bytes (K KiB)`.
pub(super) fn smart_size(value: u64) -> String {
    let mut out = format!("{value} bytes");
    if value == 0 {
        return out;
    }
    let (bits, unit) = if value >= 10 << 30 {
        (30, 'G')
    } else if value >= 10 << 20 {
        (20, 'M')
    } else {
        (10, 'K')
    };
    let rounded = (value + (1u64 << bits) - 1) >> bits;
    out.push_str(&format!(" ({rounded} {unit}iB)"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_values_match_seven_zip() {
        assert_eq!(size_value(1 << 23), "23");
        assert_eq!(size_value(384 << 10), "384k");
        assert_eq!(size_value(3 << 20), "3m");
        assert_eq!(size_value(1000), "1000b");
        assert_eq!(lzma2_value(16), "20");
        assert_eq!(lzma2_value(13), "384k");
        assert_eq!(lzma2_value(15), "768k");
        assert_eq!(lzma2_value(11), "192k");
        assert_eq!(lzma2_value(17), "1536k");
        assert_eq!(lzma2_value(27), "48m");
        assert_eq!(lzma2_value(41), "");
    }

    #[test]
    fn attributes_match_seven_zip() {
        let dir = ATTRIB_DIRECTORY | ATTRIB_UNIX_EXTENSION | (0o40755 << 16);
        assert_eq!(attributes_long(dir, true), "D drwxr-xr-x");
        let file = ATTRIB_ARCHIVE | ATTRIB_UNIX_EXTENSION | (0o100644 << 16);
        assert_eq!(attributes_long(file, false), "A -rw-r--r--");
        assert_eq!(attributes_short(file, false), "....A");
        assert_eq!(attributes_short(0, true), "D....");
        assert_eq!(attributes_long(0x4_0000, false), " 00040000");
    }

    #[test]
    fn utc_civil_dates() {
        assert_eq!(utc_civil(0), [1970, 1, 1, 0, 0, 0]);
        assert_eq!(utc_civil(951_782_400), [2000, 2, 29, 0, 0, 0]);
        assert_eq!(utc_civil(-1), [1969, 12, 31, 23, 59, 59]);
    }

    #[test]
    fn smart_sizes() {
        assert_eq!(smart_size(0), "0 bytes");
        assert_eq!(smart_size(145_635), "145635 bytes (143 KiB)");
        assert_eq!(smart_size(10 << 20), "10485760 bytes (10 MiB)");
    }
}
