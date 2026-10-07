//! 7-Zip's command-line switch table and parser (`CommandLineParser.cpp`,
//! `ArchiveCommandLine.cpp`), kept to its exact matching and error rules.
//!
//! Matching works on each argument's text; a switch's value and every
//! non-switch also keep the argument's own bytes, so a path that is not valid
//! UTF-8 names the same file it was given as.

use std::ffi::{OsStr, OsString};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Simple,
    Minus,
    Char(&'static str),
    Str,
}

struct Form {
    key: &'static str,
    kind: Kind,
    multi: bool,
    min: usize,
}

const fn simple(key: &'static str) -> Form {
    Form {
        key,
        kind: Kind::Simple,
        multi: false,
        min: 0,
    }
}
const fn minus(key: &'static str) -> Form {
    Form {
        key,
        kind: Kind::Minus,
        multi: false,
        min: 0,
    }
}
const fn chars(key: &'static str, set: &'static str, min: usize) -> Form {
    Form {
        key,
        kind: Kind::Char(set),
        multi: false,
        min,
    }
}
const fn string(key: &'static str, multi: bool, min: usize) -> Form {
    Form {
        key,
        kind: Kind::Str,
        multi,
        min,
    }
}

/// Every switch 7-Zip 26 knows, in its table order.
const FORMS: &[Form] = &[
    simple("?"),
    simple("h"),
    simple("-help"),
    simple("ba"),
    simple("bd"),
    simple("bt"),
    string("bb", false, 0),
    chars("bso", "012", 1),
    chars("bse", "012", 1),
    chars("bsp", "012", 1),
    simple("y"),
    simple("ad"),
    chars("ao", "asut", 1),
    string("t", false, 1),
    string("stx", true, 1),
    string("m", true, 1),
    string("o", false, 1),
    string("w", false, 0),
    string("i", true, 2),
    string("x", true, 2),
    string("ai", true, 2),
    string("ax", true, 2),
    simple("an"),
    string("u", true, 1),
    string("v", true, 1),
    chars("r", "0-", 0),
    string("stm", false, 0),
    string("sfx", false, 0),
    string("seml", false, 0),
    string("scrc", true, 0),
    string("shd", false, 1),
    string("smemx", false, 0),
    string("si", false, 0),
    simple("so"),
    string("slp", false, 0),
    string("scs", false, 0),
    string("scc", false, 0),
    simple("slt"),
    string("slf", false, 1),
    minus("slsl"),
    minus("slmu"),
    simple("ssp"),
    simple("ssw"),
    simple("sse"),
    minus("ssc"),
    chars("sa", "sea", 1),
    string("spm", false, 0),
    simple("spd"),
    minus("spe"),
    string("spf", false, 0),
    chars("spo", "dcr", 1),
    minus("snh"),
    string("snld", false, 0),
    minus("snl"),
    simple("sni"),
    minus("snoi"),
    minus("snon"),
    string("snz", false, 0),
    minus("sns"),
    simple("snr"),
    simple("snc"),
    minus("snt"),
    simple("sdel"),
    simple("stl"),
    string("p", false, 0),
];

/// What the command line said about one switch.
#[derive(Clone, Default, Debug)]
pub(super) struct Switch {
    pub present: bool,
    pub with_minus: bool,
    /// Index into the switch's character set, when one followed it.
    pub post_char: Option<usize>,
    pub strings: Vec<String>,
    /// Each of `strings` exactly as the command line gave it.
    pub raw: Vec<OsString>,
}

/// A parsed command line.
pub(super) struct Parsed {
    switches: Vec<Switch>,
    pub non_switches: Vec<String>,
    /// Each of `non_switches` exactly as the command line gave it.
    pub raw_non_switches: Vec<OsString>,
    /// Where `--` stopped switch parsing, as an index into `non_switches`.
    pub stop_index: Option<usize>,
}

/// A 7-Zip "Command Line Error": the message and the offending argument.
#[derive(Debug)]
pub(super) struct LineError {
    pub message: String,
    pub argument: String,
}

impl LineError {
    pub fn new(message: impl Into<String>, argument: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            argument: argument.into(),
        }
    }
}

/// `arg` without its first `skip` bytes, which are ASCII, keeping the rest
/// exactly as given (on Unix, bytes that are not UTF-8 included).
pub(super) fn raw_tail(arg: &OsStr, skip: usize) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(&arg.as_bytes()[skip..]).to_owned()
    }
    #[cfg(not(unix))]
    {
        OsString::from(&arg.to_string_lossy()[skip..])
    }
}

fn starts_with_no_case(text: &str, key: &str) -> bool {
    text.len() >= key.len()
        && text.is_char_boundary(key.len())
        && text[..key.len()].eq_ignore_ascii_case(key)
}

impl Parsed {
    pub fn get(&self, key: &str) -> &Switch {
        let index = FORMS
            .iter()
            .position(|form| form.key == key)
            .expect("switch key is in the table");
        &self.switches[index]
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).present
    }
}

fn parse_switch(arg: &str, raw: &OsStr, switches: &mut [Switch]) -> Result<(), &'static str> {
    let rest = &arg[1..];
    let mut best: Option<usize> = None;
    for (index, form) in FORMS.iter().enumerate() {
        let len = form.key.len();
        if best.is_some_and(|b| FORMS[b].key.len() >= len) || len > rest.len() {
            continue;
        }
        if starts_with_no_case(rest, form.key) {
            best = Some(index);
        }
    }
    let Some(index) = best else {
        return Err("Unknown switch:");
    };
    let form = &FORMS[index];
    let tail = &rest[form.key.len()..];
    let switch = &mut switches[index];
    if !form.multi && switch.present {
        return Err("Multiple instances for switch:");
    }
    switch.present = true;
    let remaining = tail.chars().count();
    if remaining < form.min {
        return Err("Too short switch:");
    }
    switch.with_minus = false;
    switch.post_char = None;
    match form.kind {
        Kind::Minus if remaining == 1 => {
            if tail == "-" {
                switch.with_minus = true;
                return Ok(());
            }
            return Err("Incorrect switch postfix:");
        }
        Kind::Char(set) if remaining == 1 => {
            let c = tail.chars().next().unwrap_or('\0');
            if let Some(position) = c.is_ascii().then(|| set.find(c)).flatten() {
                switch.post_char = Some(position);
                return Ok(());
            }
            return Err("Incorrect switch postfix:");
        }
        Kind::Str => {
            switch.strings.push(tail.to_owned());
            // The dash and the key are ASCII: the value starts at the same
            // byte in the raw argument.
            switch.raw.push(raw_tail(raw, 1 + form.key.len()));
            return Ok(());
        }
        _ => {}
    }
    if !tail.is_empty() {
        return Err("Too long switch:");
    }
    Ok(())
}

/// `CParser::ParseStrings`.
pub(super) fn parse(args: &[OsString]) -> Result<Parsed, LineError> {
    let mut switches = vec![Switch::default(); FORMS.len()];
    let mut non_switches = Vec::new();
    let mut raw_non_switches = Vec::new();
    let mut stop_index = None;
    for raw in args {
        let arg = raw.to_string_lossy();
        if stop_index.is_none() {
            if arg == "--" {
                stop_index = Some(non_switches.len());
                continue;
            }
            if arg.starts_with('-') {
                parse_switch(&arg, raw, &mut switches)
                    .map_err(|message| LineError::new(message, arg.clone()))?;
                continue;
            }
        }
        non_switches.push(arg.into_owned());
        raw_non_switches.push(raw.clone());
    }
    Ok(Parsed {
        switches,
        non_switches,
        raw_non_switches,
        stop_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn longest_prefix_wins() {
        let parsed = parse(&args(&["-slt", "-scrc", "-sccUTF-8", "-ssc-", "x"])).unwrap();
        assert!(parsed.has("slt"));
        assert_eq!(parsed.get("scrc").strings, vec![String::new()]);
        assert_eq!(parsed.get("scc").strings, vec!["UTF-8".to_owned()]);
        assert!(parsed.get("ssc").with_minus);
        assert_eq!(parsed.non_switches, vec!["x".to_owned()]);
    }

    #[test]
    fn password_forms() {
        let parsed = parse(&args(&["-p", "-y"])).unwrap();
        assert_eq!(parsed.get("p").strings, vec![String::new()]);
        let parsed = parse(&args(&["-p-"])).unwrap();
        assert_eq!(parsed.get("p").strings, vec!["-".to_owned()]);
        let parsed = parse(&args(&["-PSecret"])).unwrap();
        assert_eq!(parsed.get("p").strings, vec!["Secret".to_owned()]);
    }

    #[test]
    fn errors_match_seven_zip() {
        let error = parse(&args(&["-zz"])).err().unwrap();
        assert_eq!(error.message, "Unknown switch:");
        assert_eq!(error.argument, "-zz");
        assert_eq!(
            parse(&args(&["-y", "-y"])).err().unwrap().message,
            "Multiple instances for switch:"
        );
        assert_eq!(
            parse(&args(&["-aox"])).err().unwrap().message,
            "Incorrect switch postfix:"
        );
        assert_eq!(
            parse(&args(&["-ao"])).err().unwrap().message,
            "Too short switch:"
        );
        assert_eq!(
            parse(&args(&["-yy"])).err().unwrap().message,
            "Too long switch:"
        );
        assert_eq!(
            parse(&args(&["-o"])).err().unwrap().message,
            "Too short switch:"
        );
    }

    #[test]
    fn double_dash_stops_switches() {
        let parsed = parse(&args(&["x", "--", "-name.7z"])).unwrap();
        assert_eq!(parsed.non_switches, strings(&["x", "-name.7z"]));
        assert_eq!(parsed.stop_index, Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn values_and_names_keep_their_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let name = OsString::from_vec(b"arch\xffive.7z".to_vec());
        let mut out = b"-o".to_vec();
        out.extend_from_slice(b"out\xfe/");
        let parsed = parse(&[OsString::from("x"), OsString::from_vec(out), name.clone()]).unwrap();
        assert_eq!(parsed.raw_non_switches[1], name);
        assert_eq!(parsed.get("o").raw[0].as_bytes(), b"out\xfe/");
        assert_eq!(parsed.non_switches[1], "arch\u{FFFD}ive.7z");
    }
}
