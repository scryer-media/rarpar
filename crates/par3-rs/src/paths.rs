//! One name-safety rule table for every relative path the engine accepts.
//!
//! A PAR3 set names its protected files with relative paths carried in the set
//! itself. Those bytes are attacker-controlled: a hostile set can name
//! `../../etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`, a Windows
//! device (`CON`, `LPT1.txt`), a component ending in a space or a dot that
//! Windows silently trims to an existing name, a component carrying one of the
//! characters Win32 forbids outright (`? * " < > |`), or a component carrying a
//! NUL that truncates the path inside a C API. The engine is the last line of
//! defence for such a set and must not rely on the host to notice.
//!
//! The same table runs at both ends, so par3-rs never writes a set it would
//! later refuse to repair: [`crate::creation`] validates every source name
//! before a byte of the set is produced, and the repair session validates
//! every destination component before a byte of output is written. The
//! decision depends only on the bytes of the path, never on the filesystem,
//! so a set refused on one platform is refused identically on every other.

use std::fmt;

/// Longest relative path the engine accepts, in bytes, separators included.
///
/// 4096 is the traditional `PATH_MAX` on Linux and a ceiling every filesystem
/// the engine targets can express. It bounds the path as carried in the set,
/// not the absolute path the host resolves it against: a deep output directory
/// can still exceed the host's own limit, and that refusal belongs to the host.
pub const MAX_PATH_BYTES: usize = 4096;

/// Longest single path component the engine accepts, in bytes.
///
/// 255 is the per-entry ceiling of ext4, APFS, NTFS and every other filesystem
/// the engine targets. Bytes, not characters: a component of 255 multi-byte
/// characters is refused, which is the conservative direction.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Longest component and path text retained in a [`PathViolation`], in bytes.
///
/// A refusal must be reportable without handing the hostile path itself to a
/// log line unbounded, so both fields are truncated on a character boundary.
const MAX_REPORTED_BYTES: usize = 255;

/// Windows device names reserved on every path component, with or without an
/// extension. Matched case-insensitively against the component's stem.
///
/// `COM0` and `LPT0` are reserved alongside the numbered ports, and Windows
/// also resolves the superscript digits as ports one, two and three. Those six
/// spellings are compared by exact character: the superscripts are not ASCII,
/// so the case-insensitive comparison below leaves them untouched while still
/// folding the `COM` and `LPT` letters. Only the superscripts Windows accepts
/// are listed, not every digit-like character Unicode defines.
const RESERVED_DEVICES: [&str; 30] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// Characters Win32 forbids in a file name, beyond the separators and the
/// colon the table already names.
///
/// `?` and `*` are wildcards the shell and the API both expand, `<`, `>` and
/// `|` are redirection operators, and `"` quotes an argument. A name carrying
/// one of them cannot be created on Windows at all, and on a POSIX host it is
/// a name no PAR3 set should be writing into an output directory, so the
/// engine refuses it at both ends rather than producing a set only some
/// platforms can repair.
const FORBIDDEN_CHARACTERS: [char; 6] = ['?', '*', '"', '<', '>', '|'];

/// The rule a relative path broke.
///
/// The variants are ordered by the order the rules are applied, so the most
/// specific description of a name is the one reported: `..` is a
/// [`PathRule::ParentDirectory`], not a [`PathRule::TrailingSpaceOrDot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PathRule {
    /// The path, or one of its components, is empty.
    Empty,
    /// The whole path is longer than [`MAX_PATH_BYTES`].
    PathTooLong,
    /// The path is absolute: a leading separator, a `X:` drive prefix or a UNC
    /// prefix. Absolute names are refused as absolute, whatever else they say.
    Absolute,
    /// A component is `.`.
    CurrentDirectory,
    /// A component is `..`.
    ParentDirectory,
    /// A component is longer than [`MAX_COMPONENT_BYTES`].
    ComponentTooLong,
    /// A component contains a backslash, which is a separator on Windows.
    Backslash,
    /// A component contains a colon, which opens an NTFS alternate data stream.
    Colon,
    /// A component contains a character Win32 forbids in a file name:
    /// `?`, `*`, `"`, `<`, `>` or `|`.
    ForbiddenCharacter,
    /// A component contains NUL or another ASCII control byte, including DEL.
    Control,
    /// A component names a Windows character device, with or without an
    /// extension: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.
    ReservedDevice,
    /// A component ends in a space or a dot, which Windows silently trims.
    TrailingSpaceOrDot,
}

impl PathRule {
    /// A short phrase naming the rule, for a message or a log line.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Empty => "is empty",
            Self::PathTooLong => "is longer than 4096 bytes",
            Self::Absolute => "is absolute",
            Self::CurrentDirectory => "is the current directory",
            Self::ParentDirectory => "is the parent directory",
            Self::ComponentTooLong => "is longer than 255 bytes",
            Self::Backslash => "contains a backslash",
            Self::Colon => "contains a colon",
            Self::ForbiddenCharacter => "contains a character Windows forbids in a name",
            Self::Control => "contains an ASCII control byte",
            Self::ReservedDevice => "names a reserved device",
            Self::TrailingSpaceOrDot => "ends in a space or a dot",
        }
    }
}

impl fmt::Display for PathRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.describe())
    }
}

/// A relative path the engine refused, and why.
///
/// Both text fields are truncated on a character boundary so a hostile name
/// cannot make the refusal itself unbounded. `component` is empty when the rule
/// applies to the path as a whole rather than to one of its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathViolation {
    /// The relative path as the set carried it, truncated for reporting.
    pub path: String,
    /// The offending component, truncated for reporting.
    pub component: String,
    /// The rule it broke.
    pub rule: PathRule,
}

impl PathViolation {
    fn new(path: &str, component: &str, rule: PathRule) -> Self {
        Self {
            path: truncate(path).to_owned(),
            component: truncate(component).to_owned(),
            rule,
        }
    }
}

impl fmt::Display for PathViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.component.is_empty() || self.component == self.path {
            write!(formatter, "{:?} {}", self.path, self.rule)
        } else {
            write!(
                formatter,
                "{:?} {}: component {:?}",
                self.path, self.rule, self.component
            )
        }
    }
}

impl std::error::Error for PathViolation {}

/// Keep at most [`MAX_REPORTED_BYTES`] bytes, ending on a character boundary.
fn truncate(text: &str) -> &str {
    if text.len() <= MAX_REPORTED_BYTES {
        return text;
    }
    let mut end = MAX_REPORTED_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Whether `path` starts with a separator, a drive prefix or a UNC prefix.
///
/// A drive prefix is one ASCII letter followed by a colon, which is how
/// `C:file.txt` names a path relative to another volume's current directory —
/// still not a name this engine will resolve against its own output directory.
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    match bytes {
        [b'/' | b'\\', ..] => true,
        [drive, b':', ..] => drive.is_ascii_alphabetic(),
        _ => false,
    }
}

/// Whether `component` names a Windows character device, with or without an
/// extension. The stem is everything before the first dot, with trailing
/// spaces removed, because Windows trims them before resolving the name.
fn is_reserved_device(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    RESERVED_DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
}

/// Check one component of a relative path against the rule table.
///
/// The caller supplies the whole path only so a refusal can name it.
fn check_component(path: &str, component: &str) -> Result<(), PathViolation> {
    let rule = if component.is_empty() {
        PathRule::Empty
    } else if component == "." {
        PathRule::CurrentDirectory
    } else if component == ".." {
        PathRule::ParentDirectory
    } else if component.len() > MAX_COMPONENT_BYTES {
        PathRule::ComponentTooLong
    } else if component.contains('\\') {
        PathRule::Backslash
    } else if component.contains(':') {
        PathRule::Colon
    } else if component.contains(FORBIDDEN_CHARACTERS) {
        PathRule::ForbiddenCharacter
    } else if component.bytes().any(|byte| byte.is_ascii_control()) {
        // `is_ascii_control` is 0x00-0x1F and 0x7F, so NUL and DEL are both in.
        PathRule::Control
    } else if is_reserved_device(component) {
        PathRule::ReservedDevice
    } else if component.ends_with(' ') || component.ends_with('.') {
        PathRule::TrailingSpaceOrDot
    } else {
        return Ok(());
    };
    Err(PathViolation::new(path, component, rule))
}

/// Check a whole relative path, `/`-separated, against the rule table.
///
/// This is the engine's only name-safety decision: set creation and repair
/// output both call it, so a name accepted at one end is accepted at the
/// other. It reads no filesystem and consults no platform, so the verdict for
/// a given set of bytes is the same on every host.
///
/// ```
/// use par3_rs::paths::{PathRule, validate_relative_path};
///
/// assert!(validate_relative_path("chapters/01 - intro.mkv").is_ok());
/// assert_eq!(
///     validate_relative_path("chapters/../../etc/passwd")
///         .unwrap_err()
///         .rule,
///     PathRule::ParentDirectory,
/// );
/// assert_eq!(
///     validate_relative_path("con.txt").unwrap_err().rule,
///     PathRule::ReservedDevice,
/// );
/// ```
pub fn validate_relative_path(path: &str) -> Result<(), PathViolation> {
    if path.is_empty() {
        return Err(PathViolation::new(path, "", PathRule::Empty));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathViolation::new(path, "", PathRule::PathTooLong));
    }
    if is_absolute(path) {
        return Err(PathViolation::new(path, "", PathRule::Absolute));
    }
    for component in path.split('/') {
        check_component(path, component)?;
    }
    Ok(())
}

/// Check one component in isolation, for a caller that walks a path itself.
///
/// The whole-path rules — length and absoluteness — are the caller's, so this
/// is not a substitute for [`validate_relative_path`] on a full path.
pub fn validate_component(component: &str) -> Result<(), PathViolation> {
    check_component(component, component)
}

/// The key two paths share when a case-insensitive filesystem cannot tell them
/// apart.
///
/// macOS and Windows both fold case by default, so `Readme` and `README` in one
/// directory are one file there and the second thing written takes the first
/// one's place. par3-rs refuses that pair everywhere rather than producing a set
/// that installs correctly on one filesystem and silently loses a file on
/// another.
///
/// The fold is Unicode lowercase, not the full case folding of UAX #44: it
/// catches every ASCII collision and the common Unicode ones, and it never
/// merges two names that differ by more than case. Where it and a filesystem
/// disagree it is the stricter of the two.
#[must_use]
pub(crate) fn case_folded(path: &str) -> String {
    path.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &str) -> PathRule {
        validate_relative_path(path)
            .expect_err("path should be refused")
            .rule
    }

    /// PR #73 round 2, finding 3. Win32 forbids six more characters in a file
    /// name than the separators and the colon the table already knew, so a set
    /// naming one of them could be created here and never written on Windows.
    /// The rule sits after `Colon`, so a drive prefix and a stream name still
    /// report the more specific verdict.
    #[test]
    fn the_characters_win32_forbids_in_a_name_are_refused() {
        for path in [
            "what?.bin",
            "star*.bin",
            "quote\".bin",
            "less<.bin",
            "more>.bin",
            "pipe|.bin",
            "deep/dir/glob*.bin",
            "*",
        ] {
            let violation = validate_relative_path(path).expect_err("should be refused");
            assert_eq!(
                violation.rule,
                PathRule::ForbiddenCharacter,
                "{path:?} broke the wrong rule"
            );
        }
        // The more specific rules still win where they both apply.
        assert_eq!(
            validate_relative_path("a:b*").expect_err("refused").rule,
            PathRule::Absolute
        );
        assert_eq!(
            validate_relative_path("ab:c*").expect_err("refused").rule,
            PathRule::Colon
        );
        assert_eq!(
            validate_relative_path("a\\b*").expect_err("refused").rule,
            PathRule::Backslash
        );
    }

    #[test]
    fn ordinary_relative_names_are_still_accepted() {
        for path in [
            "file.txt",
            "a/b/c.bin",
            "Season 1/S01E01 - pilot.mkv",
            "spaces are fine/and.dots.inside",
            "unicode/ünïcödé — dash.txt",
            "Rock 'n' Roll/AC&DC — don't.flac",
            "100% of it (a & b).bin",
            "connect.log",
            "console/comic.cbz",
            "lpt10.txt",
            "com10.txt",
            "com\u{b4}.txt",
            &"n".repeat(MAX_COMPONENT_BYTES),
        ] {
            assert!(
                validate_relative_path(path).is_ok(),
                "{path:?} should be accepted"
            );
        }
    }

    #[test]
    fn every_rule_class_is_refused_and_names_itself() {
        assert_eq!(rule(""), PathRule::Empty);
        assert_eq!(rule("a//b"), PathRule::Empty);
        assert_eq!(rule("a/"), PathRule::Empty);
        assert_eq!(rule(&"a/".repeat(MAX_PATH_BYTES)), PathRule::PathTooLong);
        assert_eq!(rule("/etc/passwd"), PathRule::Absolute);
        assert_eq!(rule("\\\\server\\share"), PathRule::Absolute);
        assert_eq!(rule("C:/Windows"), PathRule::Absolute);
        assert_eq!(rule("c:file.txt"), PathRule::Absolute);
        assert_eq!(rule("./file"), PathRule::CurrentDirectory);
        assert_eq!(rule("a/./b"), PathRule::CurrentDirectory);
        assert_eq!(rule("../file"), PathRule::ParentDirectory);
        assert_eq!(rule("a/../../b"), PathRule::ParentDirectory);
        assert_eq!(
            rule(&"n".repeat(MAX_COMPONENT_BYTES + 1)),
            PathRule::ComponentTooLong
        );
        assert_eq!(rule("a\\b"), PathRule::Backslash);
        assert_eq!(rule("dir/a\\b"), PathRule::Backslash);
        // One letter and a colon is a drive-relative name, not a stream.
        assert_eq!(rule("a:b"), PathRule::Absolute);
        assert_eq!(rule("ab:c"), PathRule::Colon);
        assert_eq!(rule("dir/stream:$DATA"), PathRule::Colon);
        assert_eq!(rule("a\0b"), PathRule::Control);
        assert_eq!(rule("bell\x07"), PathRule::Control);
        assert_eq!(rule("line\nbreak"), PathRule::Control);
        assert_eq!(rule("del\x7f"), PathRule::Control);
        assert_eq!(rule("trailing "), PathRule::TrailingSpaceOrDot);
        assert_eq!(rule("trailing."), PathRule::TrailingSpaceOrDot);
        assert_eq!(rule("dir /file"), PathRule::TrailingSpaceOrDot);
    }

    #[test]
    fn every_reserved_device_is_refused_in_every_spelling() {
        for device in RESERVED_DEVICES {
            for name in [
                device.to_owned(),
                device.to_lowercase(),
                format!("{device}.txt"),
                format!("{}.tar.gz", device.to_lowercase()),
                format!("{device}   .txt"),
                format!("deep/path/{device}"),
            ] {
                assert_eq!(
                    rule(&name),
                    PathRule::ReservedDevice,
                    "{name:?} should be refused as a device"
                );
            }
        }
    }

    #[test]
    fn the_zero_and_superscript_device_aliases_are_reserved_too() {
        for name in [
            "COM0",
            "lpt0",
            "com0.txt",
            "LPT0.tar.gz",
            "COM\u{b9}.txt",
            "com\u{b2}",
            "media/LPT\u{b3}.bin",
        ] {
            assert_eq!(
                rule(name),
                PathRule::ReservedDevice,
                "{name:?} names a Windows device"
            );
        }
        // Only the three superscripts Windows resolves. A fourth is a name.
        assert!(validate_relative_path("com\u{b4}").is_ok());
        assert!(validate_relative_path("com\u{2074}.txt").is_ok());
    }

    #[test]
    fn a_refusal_names_the_path_and_the_component_without_growing_with_them() {
        let component = "x".repeat(4000);
        let violation = validate_relative_path(&format!("deep/{component}"))
            .expect_err("an over-long component should be refused");
        assert_eq!(violation.rule, PathRule::ComponentTooLong);
        assert_eq!(violation.path.len(), MAX_REPORTED_BYTES);
        assert_eq!(violation.component.len(), MAX_REPORTED_BYTES);

        let violation = validate_relative_path("a/../b").expect_err("`..` should be refused");
        assert_eq!(violation.component, "..");
        assert_eq!(violation.path, "a/../b");
        assert_eq!(
            violation.to_string(),
            "\"a/../b\" is the parent directory: component \"..\""
        );
    }

    #[test]
    fn a_multi_byte_name_is_truncated_on_a_character_boundary() {
        let violation = validate_relative_path(&"é".repeat(2000))
            .expect_err("an over-long component should be refused");
        assert_eq!(violation.rule, PathRule::ComponentTooLong);
        assert_eq!(violation.component.len(), MAX_REPORTED_BYTES - 1);
        assert!(violation.component.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_component_check_applies_the_component_rules_only() {
        assert!(validate_component("ordinary.txt").is_ok());
        assert!(validate_component("C:").is_err());
        assert_eq!(
            validate_component("..").expect_err("refused").rule,
            PathRule::ParentDirectory
        );
        // A separator is a component rule here, not a whole-path rule: a caller
        // splitting the path itself must never be handed one that hides a join.
        assert_eq!(
            validate_component("a\\b").expect_err("refused").rule,
            PathRule::Backslash
        );
    }
}
