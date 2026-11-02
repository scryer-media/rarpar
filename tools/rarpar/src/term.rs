//! Terminal-safe console output.
//!
//! Archive member names, PAR2 and PAR3 file names, and the library errors
//! that carry them come from files anyone can craft. Written raw, a name
//! can move the cursor, overwrite or recolour earlier lines, or reorder
//! what follows with a bidirectional override. Every human-readable line
//! the CLI prints goes through [`terminal_safe`], which spells such
//! characters as `\xNN` (the code point in lowercase hex), the way UnRAR
//! 7.30 beta 2 treats its console and log lines. JSON output is written
//! without it: serde_json escapes control characters itself, and a `\x`
//! escape would not be valid JSON. Library crates hand callers the raw
//! names; this is a CLI concern.

use std::borrow::Cow;

/// Whether `ch` is shown escaped. `next` is the character after it, so a
/// carriage return that ends a `\r\n` line break passes through.
fn is_unsafe(ch: char, next: Option<char>) -> bool {
    matches!(
        ch,
        '\u{08}' | '\u{1a}' | '\u{1b}' | '\u{7f}' | '\u{80}'..='\u{9f}' | '\u{202a}'..='\u{202e}'
    ) || (ch == '\r' && next != Some('\n'))
}

/// `text` with backspace, a lone carriage return, SUB, ESC, DEL, the C1
/// controls (U+0080 to U+009F) and the bidirectional embeddings and
/// overrides (U+202A to U+202E) replaced by `\xNN`. Borrowed when nothing
/// needs replacing.
pub(crate) fn terminal_safe(text: &str) -> Cow<'_, str> {
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if is_unsafe(ch, chars.peek().map(|&(_, next)| next)) {
            return Cow::Owned(escape_from(text, index));
        }
    }
    Cow::Borrowed(text)
}

fn escape_from(text: &str, start: usize) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(text.len() + 8);
    out.push_str(&text[..start]);
    let mut chars = text[start..].chars().peekable();
    while let Some(ch) = chars.next() {
        if is_unsafe(ch, chars.peek().copied()) {
            let _ = write!(out, "\\x{:02x}", u32::from(ch));
        } else {
            out.push(ch);
        }
    }
    out
}

/// `println!` through [`terminal_safe`].
macro_rules! safe_println {
    () => {
        println!()
    };
    ($($arg:tt)*) => {
        println!("{}", $crate::term::terminal_safe(&format!($($arg)*)))
    };
}

/// `eprintln!` through [`terminal_safe`].
macro_rules! safe_eprintln {
    () => {
        eprintln!()
    };
    ($($arg:tt)*) => {
        eprintln!("{}", $crate::term::terminal_safe(&format!($($arg)*)))
    };
}

/// `print!` through [`terminal_safe`].
macro_rules! safe_print {
    ($($arg:tt)*) => {
        print!("{}", $crate::term::terminal_safe(&format!($($arg)*)))
    };
}

/// `eprint!` through [`terminal_safe`].
macro_rules! safe_eprint {
    ($($arg:tt)*) => {
        eprint!("{}", $crate::term::terminal_safe(&format!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::terminal_safe;
    use std::borrow::Cow;

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        for text in ["", "movie.mkv", "dir/naïve 日本.txt", "tab\there", "line\n"] {
            assert!(matches!(terminal_safe(text), Cow::Borrowed(t) if t == text));
        }
    }

    #[test]
    fn each_listed_control_is_escaped() {
        assert_eq!(terminal_safe("a\u{08}b"), "a\\x08b");
        assert_eq!(terminal_safe("a\u{1a}b"), "a\\x1ab");
        assert_eq!(terminal_safe("\u{1b}[31mred"), "\\x1b[31mred");
        assert_eq!(terminal_safe("a\u{7f}b"), "a\\x7fb");
    }

    #[test]
    fn c1_controls_are_escaped_at_both_ends() {
        assert_eq!(terminal_safe("a\u{80}b"), "a\\x80b");
        assert_eq!(terminal_safe("\u{9b}2J"), "\\x9b2J");
        assert_eq!(terminal_safe("a\u{9f}b"), "a\\x9fb");
        // Just outside the range stays.
        assert_eq!(terminal_safe("\u{a0}"), "\u{a0}");
    }

    #[test]
    fn bidi_overrides_are_escaped() {
        assert_eq!(terminal_safe("x\u{202a}y"), "x\\x202ay");
        assert_eq!(terminal_safe("evil\u{202e}txt.exe"), "evil\\x202etxt.exe");
        assert_eq!(terminal_safe("\u{2029}\u{202f}"), "\u{2029}\u{202f}");
    }

    #[test]
    fn carriage_return_passes_only_before_line_feed() {
        assert_eq!(terminal_safe("one\r\ntwo"), "one\r\ntwo");
        assert_eq!(terminal_safe("fake\rreal"), "fake\\x0dreal");
        assert_eq!(terminal_safe("end\r"), "end\\x0d");
        assert_eq!(terminal_safe("\r\r\n"), "\\x0d\r\n");
    }

    #[test]
    fn other_controls_pass_through() {
        assert_eq!(terminal_safe("a\tb\nc\u{07}"), "a\tb\nc\u{07}");
    }
}
