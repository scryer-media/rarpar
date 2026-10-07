//! A par3cmdline-compatible front end over the par3-rs engine, for the
//! consumer side only: verify (`v`), repair (`r`) and list (`l`).
//!
//! Invoked as `par3` (a link or copy of the binary under that name), rarpar
//! reads par3cmdline's whole command line: every command and option is parsed
//! the way par3cmdline parses it, with the same messages for malformed or
//! conflicting options and the same exit codes. Invoked as `rarpar`, the facade
//! claims a command line whose first word is a par3cmdline command and whose
//! PAR file argument names a `.par3` file (or a `.zip`/`.7z` for the PAR-inside
//! commands); everything else falls through to the other front ends.
//!
//! Creation stays with rarpar's own `par3 create`: the create-side commands
//! and the switches that only shape creation are refused with an explicit
//! message and par3cmdline's invalid-command code, after par3cmdline's own
//! argument checks, never ignored.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use par3_rs::ingest::{IncrementalSet, IngestedPacket, PacketScanner, PayloadKind, ScanEvent};
use par3_rs::layout::ExtentKind;
use par3_rs::placement::{PlacementOptions, search_extent};
use par3_rs::runtime::{
    CancellationToken, EngineError, ExecutionOptions, HandleBudget, MemoryBudget,
};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceId};
use par3_rs::{Fingerprint, InputSetId, Par3Error, Par3Set, ScanLimits};

mod inside;

const RET_SUCCESS: u8 = 0;
const RET_INVALID_COMMAND: u8 = 3;
const RET_INSUFFICIENT_DATA: u8 = 4;
const RET_FILE_IO_ERROR: u8 = 6;
const RET_LOGIC_ERROR: u8 = 7;
const RET_MEMORY_ERROR: u8 = 8;

/// The allocation budget when `-m` is not given, matching `rarpar`'s default.
const DEFAULT_MEMORY_BYTES: u64 = 256 << 20;
/// The largest Cauchy solve the facade accepts, matching `rarpar`'s default.
const MAX_LOST_BLOCKS: u64 = 4096;

const VERSION_LINE: &str = "par3cmdline version 0.0.1 (rarpar facade)";

const HELP: &str = "Usage:
  par3 -h  : Show this help
  par3 -V  : Show version
  par3 -VV : Show version and copyright

  par3 tc       [options] <PAR3 file> [files] : Try to create PAR3 files
  par3 te       [options] <PAR3 file> [file]  : Try to extend PAR3 files
  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files
  par3 e(xtend) [options] <PAR3 file> [file]  : Extend PAR3 files
  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file
  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files
  par3 l(ist)   [options] <PAR3 file>         : List files in PAR3 file
  par3 ti       [options] <ZIP file>          : Try to insert PAR in ZIP file
  par3 i(nsert) [options] <ZIP file>          : Insert PAR in ZIP file
  par3 d(elete) [options] <ZIP file>          : Delete PAR from ZIP file
  par3 vs       [options] <ZIP file>  [files] : Verify itself
  par3 rs       [options] <ZIP file>  [files] : Repair itself

Options: (all uses)
  -B<path> : Set the base-path to use as reference for the datafiles
  -v [-v]  : Be more verbose
  -q [-q]  : Be more quiet (-q -q gives silence)
  -m<n>    : Memory to use
  --       : Treat all following arguments as filenames
  -abs     : Enable absolute path
Options: (verify or repair)
  -S<n>    : Searching time limit (milli second)
Options: (create)
  -b<n>    : Set the Block-Count
  -s<n>    : Set the Block-Size (don't use both -b and -s)
  -r<n>    : Level of redundancy (percentage)
  -rm<n>   : Maximum redundancy (percentage)
  -c<n>    : Recovery Block-Count (don't use both -r and -c)
  -cf<n>   : First Recovery-Block-Number
  -cm<n>   : Maximum Recovery Block-Count
  -u       : Uniform recovery file sizes
  -l       : Limit size of recovery files (don't use both -u and -l)
  -n<n>    : Number of recovery files (don't use both -n and -l)
  -R       : Recurse into subdirectories
  -D       : Store Data packets
  -d<n>    : Enable deduplication of input blocks
  -e<n>    : Set using Error Correction Codes
  -i<n>    : Number of interleaving
  -fu<n>   : Use UNIX Permissions Packet
  -ff      : Use FAT Permissions Packet
  -lp<n>   : Limit repetition of packets in each file
  -C<text> : Set comment
";

const COPYRIGHT: &str = "
This is rarpar's par3cmdline-compatible facade over the par3-rs engine.
It is not par3cmdline; see rarpar's changelog for where the two differ.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Create,
    Verify,
    Repair,
    List,
    Extend,
    Insert,
    Delete,
}

impl Operation {
    fn parse(command: &str) -> Option<(Self, bool, bool)> {
        // (operation, trial, self) as par3cmdline's `main` assigns them.
        Some(match command {
            "c" | "create" => (Self::Create, false, false),
            "v" | "verify" => (Self::Verify, false, false),
            "r" | "repair" => (Self::Repair, false, false),
            "l" | "list" => (Self::List, false, false),
            "e" | "extend" => (Self::Extend, false, false),
            "tc" => (Self::Create, true, false),
            "te" => (Self::Extend, true, false),
            "i" | "insert" => (Self::Insert, false, false),
            "ti" => (Self::Insert, true, false),
            "d" | "delete" => (Self::Delete, false, false),
            "vs" => (Self::Verify, false, true),
            "rs" => (Self::Repair, false, true),
            _ => return None,
        })
    }

    /// Whether the option rules call this operation "creating" (`c` or `e`).
    fn creating(self) -> bool {
        matches!(self, Self::Create | Self::Extend)
    }
}

/// par3cmdline's option state, field for field, with zero meaning "unset"
/// exactly where par3cmdline's checks treat it so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Options {
    noise: i32,
    memory_limit: u64,
    search_limit: u32,
    base_path: String,
    block_count: u64,
    block_size: u64,
    redundancy: u32,
    max_redundancy: u32,
    recovery_count: u64,
    first_recovery: u64,
    max_recovery: u64,
    /// 0 none, -1 uniform, -2 limit to the largest file, >0 limit in bytes.
    file_scheme: i64,
    file_count: u32,
    recursive: bool,
    data_packets: bool,
    /// The option's digit character, or 0 when not given.
    dedup: u8,
    ecc: u32,
    interleave: u32,
    file_system: u32,
    /// `-fu` was given, whatever its masked value.
    unix_permissions_given: bool,
    repetition_limit: u32,
    comment: Option<String>,
    absolute: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    operation: Operation,
    trial: bool,
    self_target: bool,
    options: Options,
    /// The PAR file as par3cmdline stores it: `.par3` appended where it
    /// appends it, made absolute where it makes it absolute.
    par_filename: String,
    /// The PAR argument exactly as given, which `c` protects when no input
    /// file follows it.
    par_argument: String,
    files: Vec<String>,
    /// Lines par3cmdline prints while parsing and then carries on.
    notices: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Failure {
    code: u8,
    lines: Vec<String>,
    stderr: Vec<String>,
}

impl Failure {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![message.into()],
            stderr: Vec::new(),
        }
    }

    fn with_trailer(mut self, line: impl Into<String>) -> Self {
        self.lines.push(line.into());
        self
    }

    fn emit(&self) {
        for line in &self.lines {
            println!("{line}");
        }
        for line in &self.stderr {
            eprintln!("{line}");
        }
    }
}

/// Whether the binary was started under par3cmdline's own name.
pub fn invoked_as_par3(program: &OsStr) -> bool {
    Path::new(program)
        .file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|stem| stem.eq_ignore_ascii_case("par3"))
}

/// Run a par3cmdline command line, or return `None` when it is not one this
/// facade claims. `full` (the binary is named `par3`) claims every command
/// line, including `-h` and `-V`.
pub fn dispatch(args: &[OsString], full: bool) -> Option<u8> {
    if !full && !claims(args) {
        return None;
    }
    let args: Vec<String> = args.iter().map(|arg| escape(arg)).collect();
    Some(run(&args))
}

/// First code point of the range that carries a native path's non-UTF-8
/// bytes through the parser's text: U+10FF00 + byte, in plane 16's private
/// use area.
#[cfg(unix)]
const ESCAPE_BASE: u32 = 0x10_FF00;

/// A native argument or file name as the parser's text. On Unix any byte
/// that is not UTF-8 becomes a private-use character that [`native`] turns
/// back into the same byte, so a path is never altered on its way through.
#[cfg(unix)]
fn escape(text: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut out = String::new();
    for chunk in text.as_bytes().utf8_chunks() {
        out.push_str(chunk.valid());
        for &byte in chunk.invalid() {
            out.push(char::from_u32(ESCAPE_BASE + u32::from(byte)).expect("private use"));
        }
    }
    out
}

#[cfg(not(unix))]
fn escape(text: &OsStr) -> String {
    text.to_string_lossy().into_owned()
}

/// The native path text [`escape`] made.
#[cfg(unix)]
fn native(text: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = Vec::with_capacity(text.len());
    for c in text.chars() {
        let code = u32::from(c);
        if (ESCAPE_BASE..ESCAPE_BASE + 0x100).contains(&code) {
            bytes.push((code - ESCAPE_BASE) as u8);
        } else {
            let mut buffer = [0; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
        }
    }
    OsString::from_vec(bytes)
}

#[cfg(not(unix))]
fn native(text: &str) -> OsString {
    OsString::from(text)
}

/// Where the last path separator of a native path argument is: `/`, and on
/// Windows `\` too.
fn last_separator(text: &str) -> Option<usize> {
    if cfg!(windows) {
        text.rfind(['/', '\\'])
    } else {
        text.rfind('/')
    }
}

/// Under the `rarpar` name the facade takes a command line only when its first
/// word is a par3cmdline command and the PAR argument, found the way
/// par3cmdline finds it, names a PAR3 file (or a ZIP or 7z file for the
/// PAR-inside commands).
fn claims(args: &[OsString]) -> bool {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return false;
    };
    let Some((operation, _, self_target)) = Operation::parse(command) else {
        return false;
    };
    let mut rest = args[1..].iter().map(|arg| arg.to_string_lossy());
    let par = loop {
        match rest.next() {
            Some(arg) if arg == "--" => break rest.next(),
            Some(arg) if arg.starts_with('-') => {}
            other => break other,
        }
    };
    let Some(par) = par else {
        return false;
    };
    let lower = par.to_ascii_lowercase();
    if matches!(operation, Operation::Insert | Operation::Delete) || self_target {
        lower.ends_with(".zip") || lower.ends_with(".7z")
    } else {
        lower.ends_with(".par3")
    }
}

fn run(args: &[String]) -> u8 {
    let invocation = match parse(args) {
        Ok(Parsed::Exit(code, lines)) => {
            for line in lines {
                println!("{line}");
            }
            return code;
        }
        Ok(Parsed::Run(invocation)) => invocation,
        Err(failure) => {
            failure.emit();
            return failure.code;
        }
    };
    for line in &invocation.notices {
        println!("{line}");
    }
    let result = match prepare(&invocation) {
        Ok(context) => execute(&invocation, &context),
        Err(failure) => Err(failure),
    };
    match result {
        Ok(()) => RET_SUCCESS,
        Err(failure) => {
            failure.emit();
            failure.code
        }
    }
}

#[derive(Debug)]
enum Parsed {
    /// `-h`, `-V` and `-VV`: print and leave.
    Exit(u8, Vec<String>),
    Run(Box<Invocation>),
}

/// The digits at the start of `text` as `strtoull` reads them, saturating on
/// overflow, and what follows them.
fn leading_number(text: &str) -> (u64, &str) {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let value = if digits == 0 {
        0
    } else {
        text[..digits].parse::<u64>().unwrap_or(u64::MAX)
    };
    (value, &text[digits..])
}

fn number(text: &str) -> u64 {
    leading_number(text).0
}

/// `strtoul` stored into a 32-bit field.
fn number32(text: &str) -> u32 {
    number(text) as u32
}

fn starts_with_digit(text: &str, index: usize) -> bool {
    text.as_bytes().get(index).is_some_and(u8::is_ascii_digit)
}

fn parse(args: &[String]) -> Result<Parsed, Failure> {
    if args.len() < 2 {
        if let [only] = args {
            match only.as_str() {
                "-h" => {
                    return Ok(Parsed::Exit(
                        RET_SUCCESS,
                        vec![HELP.trim_end_matches('\n').to_owned()],
                    ));
                }
                "-V" => return Ok(Parsed::Exit(RET_SUCCESS, vec![VERSION_LINE.to_owned()])),
                "-VV" => {
                    return Ok(Parsed::Exit(
                        RET_SUCCESS,
                        vec![VERSION_LINE.to_owned(), COPYRIGHT.to_owned()],
                    ));
                }
                _ => {}
            }
        }
        return Err(
            Failure::new(RET_INVALID_COMMAND, "Not enough command line arguments.")
                .with_trailer("To show help, type: par3 -h"),
        );
    }

    let Some((operation, trial, self_target)) = Operation::parse(&args[0]) else {
        return Err(Failure::new(
            RET_INVALID_COMMAND,
            HELP.trim_end_matches('\n'),
        ));
    };
    let mut recursive_flag = false;
    let mut options = Options::default();
    let mut notices = Vec::new();
    let mut comment: Vec<String> = Vec::new();
    let mut index = 1;
    let fail = |notices: &Vec<String>, message: &str| {
        let mut failure = Failure::new(RET_INVALID_COMMAND, message);
        let mut lines = notices.clone();
        lines.append(&mut failure.lines);
        failure.lines = lines;
        failure
    };
    while index < args.len() {
        let arg = &args[index];
        let Some(option) = arg.strip_prefix('-') else {
            break;
        };
        let bytes = option.as_bytes();
        let first = bytes.first().copied().unwrap_or(0);
        let second = bytes.get(1).copied().unwrap_or(0);
        let creating = operation.creating();
        let create_only = operation == Operation::Create;
        if option == "-" {
            index += 1;
            break;
        } else if option == "v" {
            options.noise += 1;
        } else if option == "vv" {
            options.noise += 2;
        } else if option == "vvv" {
            options.noise += 3;
        } else if option == "q" {
            options.noise -= 1;
        } else if option == "qq" {
            options.noise -= 2;
        } else if first == b'm' && starts_with_digit(option, 1) {
            if options.memory_limit > 0 {
                return Err(fail(&notices, "Cannot specify memory limit twice."));
            }
            let (value, unit) = leading_number(&option[1..]);
            let unit = unit.to_ascii_lowercase();
            options.memory_limit = match unit.as_str() {
                "g" | "gb" => value.wrapping_shl(30),
                "m" | "mb" => value.wrapping_shl(20),
                "k" | "kb" => value.wrapping_shl(10),
                _ => value,
            };
        } else if first == b'S' && starts_with_digit(option, 1) {
            if !matches!(operation, Operation::Verify | Operation::Repair) {
                return Err(fail(
                    &notices,
                    "Cannot specify searching time limit unless reparing or verifying.",
                ));
            } else if options.search_limit > 0 {
                return Err(fail(&notices, "Cannot specify searching time limit twice."));
            }
            options.search_limit = number32(&option[1..]);
        } else if first == b'B' && second != 0 {
            if operation == Operation::List {
                return Err(fail(&notices, "Cannot specify base-path for listing."));
            } else if matches!(operation, Operation::Insert | Operation::Delete) {
                return Err(fail(&notices, "Cannot specify base-path for PAR inside."));
            } else if !options.base_path.is_empty() {
                return Err(fail(&notices, "Cannot specify base-path twice."));
            }
            options.base_path = option[1..].to_owned();
        } else if first == b'b' && starts_with_digit(option, 1) {
            if !create_only {
                return Err(fail(
                    &notices,
                    "Cannot specify block count unless creating.",
                ));
            } else if options.block_count > 0 {
                return Err(fail(&notices, "Cannot specify block count twice."));
            } else if options.block_size > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify both block count and block size.",
                ));
            }
            options.block_count = number(&option[1..]);
        } else if first == b's' && starts_with_digit(option, 1) {
            if !create_only {
                return Err(fail(&notices, "Cannot specify block size unless creating."));
            } else if options.block_size > 0 {
                return Err(fail(&notices, "Cannot specify block size twice."));
            } else if options.block_count > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify both block count and block size.",
                ));
            }
            options.block_size = number(&option[1..]);
        } else if first == b'r' && starts_with_digit(option, 1) {
            if !(creating || operation == Operation::Insert) {
                return Err(fail(&notices, "Cannot specify redundancy unless creating."));
            } else if options.redundancy > 0 {
                return Err(fail(&notices, "Cannot specify redundancy twice."));
            } else if options.recovery_count > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify both redundancy and recovery block count.",
                ));
            }
            options.redundancy = number32(&option[1..]);
            if options.redundancy > 250 {
                notices.push(format!("Invalid redundancy option: {}", options.redundancy));
                options.redundancy = 0;
            }
        } else if first == b'r' && second == b'm' && starts_with_digit(option, 2) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify max redundancy unless creating.",
                ));
            } else if options.max_redundancy > 0 {
                return Err(fail(&notices, "Cannot specify max redundancy twice."));
            } else if options.max_recovery > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify both max redundancy and recovery block count.",
                ));
            }
            options.max_redundancy = number32(&option[2..]);
            if options.max_redundancy > 250 {
                notices.push(format!(
                    "Invalid max redundancy option: {}",
                    options.max_redundancy
                ));
                options.max_redundancy = 0;
            }
        } else if first == b'c' && starts_with_digit(option, 1) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify recovery block count unless creating.",
                ));
            } else if options.recovery_count > 0 {
                return Err(fail(&notices, "Cannot specify recovery block count twice."));
            } else if options.redundancy > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify both recovery block count and redundancy.",
                ));
            }
            options.recovery_count = number(&option[1..]);
        } else if first == b'c' && second == b'f' && starts_with_digit(option, 2) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify first block number unless creating.",
                ));
            } else if options.first_recovery > 0 {
                return Err(fail(&notices, "Cannot specify first block twice."));
            }
            options.first_recovery = number(&option[2..]);
        } else if first == b'c' && second == b'm' && starts_with_digit(option, 2) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify max recovery block count unless creating.",
                ));
            } else if options.max_recovery > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify max recovery block count twice.",
                ));
            }
            options.max_recovery = number(&option[2..]);
        } else if option == "u" {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify uniform files unless creating.",
                ));
            } else if options.file_scheme != 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify two recovery file size schemes.",
                ));
            }
            options.file_scheme = -1;
        } else if first == b'l' && (second == 0 || second.is_ascii_digit()) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify limit files unless creating.",
                ));
            } else if options.file_scheme != 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify two recovery file size schemes.",
                ));
            } else if options.file_count > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify limited size and number of files at the same time.",
                ));
            }
            options.file_scheme = if second == 0 {
                -2
            } else {
                i64::try_from(number(&option[1..])).unwrap_or(i64::MAX)
            };
        } else if first == b'n' && starts_with_digit(option, 1) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify recovery file count unless creating.",
                ));
            } else if options.file_count > 0 {
                return Err(fail(&notices, "Cannot specify recovery file count twice."));
            } else if options.file_scheme == -2 || options.file_scheme > 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify limited size and number of files at the same time.",
                ));
            }
            options.file_count = number32(&option[1..]);
        } else if option == "R" {
            if !create_only {
                return Err(fail(&notices, "Cannot specify Recursive unless creating."));
            }
            recursive_flag = true;
        } else if option == "D" {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify Data packet unless creating.",
                ));
            }
            options.data_packets = true;
        } else if first == b'd' && (b'0'..=b'2').contains(&second) {
            if !create_only {
                return Err(fail(
                    &notices,
                    "Cannot specify deduplication unless creating.",
                ));
            } else if options.dedup != 0 {
                return Err(fail(&notices, "Cannot specify deduplication twice."));
            }
            options.dedup = second;
        } else if first == b'e' && starts_with_digit(option, 1) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify Error Correction Codes unless creating.",
                ));
            } else if options.ecc != 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify Error Correction Codes twice.",
                ));
            }
            options.ecc = number32(&option[1..]);
            if options.ecc.count_ones() > 1 {
                notices.push("Cannot specify multiple Error Correction Codes.".to_owned());
                options.ecc = 0;
            }
        } else if first == b'i' && starts_with_digit(option, 1) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify interleaving unless creating.",
                ));
            } else if options.interleave != 0 {
                return Err(fail(&notices, "Cannot specify interleaving twice."));
            }
            options.interleave = number32(&option[1..]);
        } else if first == b'f' && second == b'u' && bytes.get(2).is_none_or(u8::is_ascii_digit) {
            options.unix_permissions_given = true;
            if options.file_system & 7 != 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify UNIX Permissions Packet twice.",
                ));
            }
            options.file_system |= if bytes.len() == 2 {
                7
            } else {
                number32(&option[2..]) & 7
            };
        } else if option == "ff" {
            if options.file_system & 0x10000 != 0 {
                return Err(fail(
                    &notices,
                    "Cannot specify FAT Permissions Packet twice.",
                ));
            }
            options.file_system |= 0x10000;
        } else if first == b'l' && second == b'p' && starts_with_digit(option, 2) {
            if !creating {
                return Err(fail(
                    &notices,
                    "Cannot specify max repetition unless creating.",
                ));
            } else if options.repetition_limit != 0 {
                return Err(fail(&notices, "Cannot specify max repetition twice."));
            }
            options.repetition_limit = number32(&option[2..]);
        } else if first == b'C' && second != 0 {
            if !create_only {
                return Err(fail(&notices, "Cannot specify comment unless creating."));
            }
            let mut text = &option[1..];
            if text.len() > 2 && text.starts_with('"') && text.ends_with('"') {
                text = &text[1..text.len() - 1];
            }
            if !text.is_empty() {
                comment.push(text.to_owned());
            }
        } else if option == "abs" || option == "ABS" {
            if options.absolute != 0 {
                return Err(fail(&notices, "Cannot enable absolute path twice."));
            }
            options.absolute = first;
        } else {
            return Err(fail(&notices, &format!("Invalid option specified: {arg}")));
        }
        index += 1;
    }
    options.recursive = recursive_flag;
    if !comment.is_empty() {
        let joined = comment.join("\n");
        let trimmed = joined.trim_end_matches([' ', '\n', '\r', '\t']);
        if !trimmed.is_empty() {
            options.comment = Some(trimmed.to_owned());
        }
    }

    // The PAR filename.
    let mut par_filename = String::new();
    let mut par_argument = String::new();
    if let Some(argument) = args.get(index) {
        index += 1;
        par_argument = argument.clone();
        if argument.contains(['*', '?']) {
            notices.push(format!("Found wildcard in PAR filename, {argument}"));
        } else {
            par_filename = argument.clone();
            if Path::new(&native(argument)).is_absolute() {
                if options.base_path.is_empty()
                    && let Some(slash) = last_separator(argument)
                {
                    options.base_path = argument[..slash].to_owned();
                }
            } else if !options.base_path.is_empty() {
                let current = std::env::current_dir().map_err(|_| {
                    Failure::new(
                        RET_FILE_IO_ERROR,
                        "Failed to convert PAR filename to absolute path",
                    )
                })?;
                par_filename = escape(current.join(native(argument)).as_os_str());
            }
        }
    }
    if par_filename.is_empty() {
        return Err(fail(&notices, "PAR filename is not specified"));
    }
    if matches!(operation, Operation::Insert | Operation::Delete) || self_target {
        match last_separator(&par_filename) {
            Some(slash) if slash > 0 => {
                options.base_path = par_filename[..slash].to_owned();
                par_filename = par_filename[slash + 1..].to_owned();
            }
            _ => options.base_path.clear(),
        }
        if self_target {
            let lower = par_filename.to_ascii_lowercase();
            if !lower.ends_with(".zip") && !lower.ends_with(".7z") {
                let mut failure =
                    Failure::new(RET_FILE_IO_ERROR, "File extension is different from ZIP.");
                let mut lines = notices.clone();
                lines.append(&mut failure.lines);
                failure.lines = lines;
                return Err(failure);
            }
        }
    } else if !par_filename.to_ascii_lowercase().ends_with(".par3") {
        par_filename.push_str(".par3");
    }

    Ok(Parsed::Run(Box::new(Invocation {
        operation,
        trial,
        self_target,
        options,
        par_filename,
        par_argument,
        files: args[index..].to_vec(),
        notices,
    })))
}

/// Where the command runs: par3cmdline changes into the base path; the facade
/// resolves every relative name against it instead.
#[derive(Debug)]
struct Context {
    base: PathBuf,
    /// The PAR file resolved against the directory rarpar was started in, or
    /// for a self target against the base path its directory became.
    par_path: PathBuf,
    execution: ExecutionOptions,
}

fn prepare(invocation: &Invocation) -> Result<Context, Failure> {
    // What the facade refuses is refused before any path is looked at.
    refuse_unsupported(invocation)?;
    let options = &invocation.options;
    let current = std::env::current_dir().map_err(|error| {
        Failure::new(
            RET_FILE_IO_ERROR,
            format!("Failed to get current working directory: {error}"),
        )
    })?;
    let base = if options.base_path.is_empty() {
        current.clone()
    } else {
        let base = current.join(native(&options.base_path));
        if !base.is_dir() {
            return Err(Failure {
                code: RET_FILE_IO_ERROR,
                lines: Vec::new(),
                stderr: vec![format!(
                    "Failed to change working directory: {}",
                    if base.exists() {
                        "Not a directory"
                    } else {
                        "No such file or directory"
                    }
                )],
            });
        }
        base
    };
    if options.noise >= 1 {
        print_option_summary(invocation);
    }
    // A self target's directory was moved into the base path when it was
    // parsed, so its bare name resolves there.
    let par_path = if invocation.self_target {
        base.join(native(&invocation.par_filename))
    } else {
        current.join(native(&invocation.par_filename))
    };
    Ok(Context {
        base,
        par_path,
        execution: execution_options(options.memory_limit)?,
    })
}

fn execution_options(memory_limit: u64) -> Result<ExecutionOptions, Failure> {
    let bytes = if memory_limit == 0 {
        DEFAULT_MEMORY_BYTES
    } else {
        memory_limit
    };
    let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(bytes);
    options.retained_bytes = bytes.min(64 << 20);
    options.max_cauchy_lost_blocks = MAX_LOST_BLOCKS;
    Ok(options)
}

fn print_option_summary(invocation: &Invocation) {
    let options = &invocation.options;
    if options.memory_limit != 0 {
        let limit = options.memory_limit;
        if limit & ((1 << 30) - 1) == 0 {
            println!("memory_limit = {} GB", limit >> 30);
        } else if limit & ((1 << 20) - 1) == 0 {
            println!("memory_limit = {} MB", limit >> 20);
        } else if limit & ((1 << 10) - 1) == 0 {
            println!("memory_limit = {} KB", limit >> 10);
        } else {
            println!("memory_limit = {limit} Bytes");
        }
    }
    if options.search_limit != 0 {
        println!("search_limit = {} ms", options.search_limit);
    }
    if options.block_count != 0 {
        println!("Specified block count = {}", options.block_count);
    }
    if options.block_size != 0 {
        println!("Specified block size = {}", options.block_size);
    }
    if options.redundancy != 0 {
        println!("Specified redundancy = {} %", options.redundancy);
    }
    if options.max_redundancy != 0 {
        println!("max_redundancy_size = {}", options.max_redundancy);
    }
    if options.recovery_count != 0 {
        println!("recovery_block_count = {}", options.recovery_count);
    }
    if options.first_recovery != 0 {
        println!("First recovery block number = {}", options.first_recovery);
    }
    if options.max_recovery != 0 {
        println!("max_recovery_block = {}", options.max_recovery);
    }
    if options.file_count != 0 {
        println!(
            "Specified number of recovery files = {}",
            options.file_count
        );
    }
    match options.file_scheme {
        -1 => println!("Recovery file sizing = uniform"),
        -2 => println!("Recovery file sizing = limit"),
        limit if limit > 0 => println!("Recovery file sizing = limit to {limit}"),
        _ => {}
    }
    if options.ecc != 0 {
        println!("Error Correction Codes = {}", options.ecc);
    }
    if options.interleave != 0 && options.ecc == 8 {
        println!("Specified interleaving times = {}", options.interleave);
    }
    if options.file_system != 0 {
        println!("File System Packet = 0x{:X}", options.file_system);
    }
    if options.dedup != 0 {
        println!("deduplication = level {}", options.dedup as char);
    }
    if options.recursive {
        println!("recursive search = enable");
    }
    if options.absolute != 0 {
        println!("Absolute path = enable");
    }
    if options.data_packets {
        println!("Data packet = store");
    }
    if options.repetition_limit != 0 {
        println!("Max packet repetition = {}", options.repetition_limit);
    }
    if !options.base_path.is_empty() {
        println!("Base path = \"{}\"", options.base_path);
    }
    println!("PAR file = \"{}\"", invocation.par_filename);
    println!();
}

/// Everything par3cmdline accepts that the engine cannot honour, refused
/// before any work starts. Each refusal names what was asked for.
fn refuse_unsupported(invocation: &Invocation) -> Result<(), Failure> {
    let refuse = |message: &str| Err(Failure::new(RET_INVALID_COMMAND, message));
    let options = &invocation.options;
    // The facade decodes, verifies and repairs; creation stays with rarpar's
    // own `par3 create`.
    match (invocation.operation, invocation.trial) {
        (Operation::Create, trial) => {
            return refuse(&format!(
                "rarpar does not create PAR3 files through the par3cmdline facade ({} is not supported); use `rarpar par3 create`.",
                if trial { "tc" } else { "c" }
            ));
        }
        (Operation::Extend, trial) => {
            return refuse(&format!(
                "rarpar does not extend PAR3 files through the par3cmdline facade ({} is not supported); use `rarpar par3 create`.",
                if trial { "te" } else { "e" }
            ));
        }
        (Operation::Insert | Operation::Delete, _) => {
            return refuse(
                "rarpar does not write PAR3 data into, or remove it from, a ZIP or 7z file (i, ti and d are not supported).",
            );
        }
        _ => {}
    }
    // par3cmdline accepts these with any command; they only shape creation.
    if options.unix_permissions_given || options.file_system & 0x10007 != 0 {
        return refuse(
            "rarpar does not create PAR3 files through the par3cmdline facade, so -fu and -ff are not supported.",
        );
    }
    if options.absolute != 0 {
        return refuse(
            "rarpar does not create PAR3 files through the par3cmdline facade, so -abs is not supported.",
        );
    }
    Ok(())
}

fn execute(invocation: &Invocation, context: &Context) -> Result<(), Failure> {
    match invocation.operation {
        Operation::Verify | Operation::Repair | Operation::List => verify(invocation, context),
        Operation::Create | Operation::Extend | Operation::Insert | Operation::Delete => {
            unreachable!("refused before execution")
        }
    }
}

// ----------------------------------------------------------------------------
// Input search

/// par3cmdline's wildcard match: `*` and `?`, nothing else special.
fn wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = n;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            n = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn visible_entries(directory: &Path) -> std::io::Result<Vec<(String, bool)>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        // An entry that cannot be read, or a link that leads nowhere, is
        // skipped on its own; it never hides its siblings.
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let is_dir = if kind.is_symlink() {
            match std::fs::metadata(entry.path()) {
                Ok(meta) => meta.is_dir(),
                Err(_) => continue,
            }
        } else {
            kind.is_dir()
        };
        // `read_dir` never yields `.` or `..`; dot files are ordinary names.
        entries.push((escape(&entry.file_name()), is_dir));
    }
    entries.sort();
    Ok(entries)
}

#[derive(Debug, Default)]
struct InputList {
    /// Names in discovery order.
    files: Vec<String>,
    directories: Vec<String>,
    /// Membership of `files` and `directories`, so a wildcard over many
    /// names is not a rescan per name.
    file_set: HashSet<String>,
    directory_set: HashSet<String>,
}

impl InputList {
    fn add_file(&mut self, name: String) {
        if self.file_set.insert(name.clone()) {
            self.files.push(name);
        }
    }

    fn add_directory(&mut self, name: String) -> bool {
        if !self.directory_set.insert(name.clone()) {
            return false;
        }
        self.directories.push(name);
        true
    }
}

/// Split `argument` into its directory, relative to `base`, and its name
/// pattern, refusing a directory outside `base` as par3cmdline does.
fn split_search(base: &Path, argument: &str) -> Result<(String, String), Failure> {
    let Some(slash) = last_separator(argument) else {
        return Ok((String::new(), argument.to_owned()));
    };
    let directory = &argument[..slash];
    let pattern = argument[slash + 1..].to_owned();
    let joined = if directory.is_empty() {
        PathBuf::from("/")
    } else {
        base.join(native(directory))
    };
    let outside = || {
        Failure::new(
            RET_FILE_IO_ERROR,
            format!("Ignoring out of base-path input file: {argument}"),
        )
    };
    let resolved = joined.canonicalize().map_err(|_| Failure {
        code: RET_FILE_IO_ERROR,
        lines: Vec::new(),
        stderr: vec!["Failed to change working directory: No such file or directory".into()],
    })?;
    let base = base.canonicalize().map_err(|_| outside())?;
    let relative = resolved.strip_prefix(&base).map_err(|_| outside())?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(outside());
        };
        parts.push(escape(part));
    }
    Ok((parts.join("/"), pattern))
}

fn join_name(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

/// par3cmdline's `path_search` for the extra names given to `v` and `r`:
/// files matching the pattern, and directories matching it as directory
/// entries.
fn path_search(base: &Path, argument: &str, list: &mut InputList) -> Result<(), Failure> {
    let (directory, pattern) = split_search(base, argument)?;
    if !directory.is_empty() {
        // The directory of a nested name is itself an input directory.
        let mut prefix = String::new();
        for part in directory.split('/') {
            prefix = join_name(&prefix, part);
            list.add_directory(prefix.clone());
        }
    }
    let io =
        |error: std::io::Error| Failure::new(RET_FILE_IO_ERROR, format!("{argument}: {error}"));
    let entries = visible_entries(&base.join(native(&directory))).map_err(io)?;
    for (name, is_dir) in entries {
        if !wildcard_match(pattern.as_bytes(), name.as_bytes()) {
            continue;
        }
        let path = join_name(&directory, &name);
        if !is_dir {
            list.add_file(path);
        } else {
            list.add_directory(path);
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Verify, repair and list

fn engine_failure(error: impl Into<EngineError>, trailer: &str) -> Failure {
    let error = error.into();
    let code = match &error {
        EngineError::Io(_) | EngineError::Format(Par3Error::FileIo { .. }) => RET_FILE_IO_ERROR,
        EngineError::ResourceLimit(_) => RET_MEMORY_ERROR,
        _ => RET_LOGIC_ERROR,
    };
    Failure::new(code, format!("rarpar: {error}")).with_trailer(trailer)
}

fn file_name(path: &Path) -> String {
    path.file_name().map(escape).unwrap_or_default()
}

struct Loaded {
    /// Packets of every carrier, in load order, grouped by set.
    sets: BTreeMap<InputSetId, Vec<IngestedPacket>>,
    /// The set the named PAR file belongs to, else the first set loaded.
    selected: Option<InputSetId>,
}

/// par3cmdline's `par_search`: the named file, then (for verify and repair)
/// every `<stem>.*par3` beside it, then PAR3 files among the extra names.
fn find_carriers(
    invocation: &Invocation,
    context: &Context,
    extra_carriers: &[(PathBuf, String)],
) -> Vec<(PathBuf, String)> {
    let mut carriers: Vec<(PathBuf, String)> = Vec::new();
    let named = &context.par_path;
    if named.is_file() {
        carriers.push((named.clone(), invocation.par_filename.clone()));
    }
    let others = invocation.operation != Operation::List && !invocation.self_target;
    if others {
        let directory = named.parent().unwrap_or(Path::new("."));
        let entries = visible_entries(directory).ok();
        let mut stem = file_name(named);
        // On a case-insensitive filesystem the named file may be spelled
        // differently on disk; its siblings match the on-disk spelling.
        if let Some(entries) = &entries
            && !carriers.is_empty()
            && !entries.iter().any(|(name, _)| *name == stem)
            && let Some((actual, _)) = entries
                .iter()
                .find(|(name, is_dir)| !is_dir && name.eq_ignore_ascii_case(&stem))
        {
            carriers[0].0 = directory.join(native(actual));
            stem = actual.clone();
        }
        if stem.to_ascii_lowercase().ends_with(".par3") {
            stem.truncate(stem.len() - 5);
        }
        if let Some(dot) = stem.rfind('.') {
            let tail = stem[dot..].to_ascii_lowercase();
            if tail.starts_with(".vol") || tail.starts_with(".part") {
                stem.truncate(dot);
            }
        }
        let prefix = format!("{stem}.");
        let shown_directory = last_separator(&invocation.par_filename)
            .map(|slash| invocation.par_filename[..=slash].to_owned())
            .unwrap_or_default();
        if let Some(entries) = entries {
            for (name, is_dir) in entries {
                let lower = name.to_ascii_lowercase();
                if is_dir
                    || !name.starts_with(&prefix)
                    || !lower.ends_with("par3")
                    || name.len() < prefix.len() + 4
                {
                    continue;
                }
                let path = directory.join(native(&name));
                if carriers.iter().any(|(known, _)| *known == path) {
                    continue;
                }
                carriers.push((path, format!("{shown_directory}{name}")));
            }
        }
        for (path, name) in extra_carriers {
            if carriers.iter().any(|(known, _)| known == path) {
                continue;
            }
            if path.is_file() {
                carriers.push((path.clone(), name.clone()));
            }
        }
    }
    carriers
}

fn load_carriers(
    carriers: &[(PathBuf, String)],
    execution: &ExecutionOptions,
    noise: i32,
    trailer: &str,
) -> Result<Loaded, Failure> {
    let mut options = execution.clone();
    options.open_handles = options.open_handles.saturating_add(carriers.len());
    options.handles = HandleBudget::new(options.open_handles);
    let mut disk = DiskSourceAccess::with_options(options.clone());
    for (index, (path, _)) in carriers.iter().enumerate() {
        disk.insert(SourceId(index as u64), path.clone());
    }
    let access: Arc<dyn SourceAccess> = Arc::new(disk);
    let mut seen: BTreeSet<Fingerprint> = BTreeSet::new();
    let mut sets: BTreeMap<InputSetId, Vec<IngestedPacket>> = BTreeMap::new();
    let mut selected = None;
    for (index, (_, shown)) in carriers.iter().enumerate() {
        if noise >= -1 {
            println!("Loading \"{shown}\".");
        }
        let scanner = PacketScanner::new(
            access.clone(),
            SourceId(index as u64),
            options.clone(),
            ScanLimits::default(),
        );
        let mut scanner = match scanner {
            Ok(scanner) => scanner,
            // A memory limit too small to read a packet stops the run, as
            // par3cmdline's does; any other failure skips the file.
            Err(error @ EngineError::ResourceLimit(_)) => {
                return Err(engine_failure(error, trailer));
            }
            Err(_) => {
                println!("Failed to open \"{shown}\", skip to next file.");
                continue;
            }
        };
        let (mut found, mut new) = (0u64, 0u64);
        loop {
            match scanner.poll() {
                Ok(ScanEvent::Packet(packet)) => {
                    found += 1;
                    if seen.insert(packet.hash()) {
                        new += 1;
                    }
                    let id = packet.input_set_id();
                    selected.get_or_insert(id);
                    sets.entry(id).or_default().push(packet);
                }
                Ok(ScanEvent::End) => break,
                Err(error @ EngineError::ResourceLimit(_)) => {
                    return Err(engine_failure(error, trailer));
                }
                Ok(ScanEvent::NeedData { .. }) | Err(_) => {
                    println!("Failed to read \"{shown}\", skip to next file.");
                    break;
                }
            }
        }
        if noise >= 0 {
            println!("Loaded {new} new packets (found {found} packets)");
        }
    }
    Ok(Loaded { sets, selected })
}

/// The set's files and directories in par3cmdline's order: a depth-first walk
/// of the Root packet's children, a directory before its contents.
fn tree_order(set: &Par3Set) -> (Vec<usize>, Vec<usize>) {
    let files: BTreeMap<Fingerprint, usize> = set
        .files()
        .iter()
        .enumerate()
        .map(|(index, file)| (file.packet_hash(), index))
        .collect();
    let directories: BTreeMap<Fingerprint, usize> = set
        .directories()
        .iter()
        .enumerate()
        .map(|(index, directory)| (directory.packet_hash(), index))
        .collect();
    let mut file_order = Vec::new();
    let mut directory_order = Vec::new();
    // Membership in constant time: a set may hold many thousands of entries.
    let mut file_seen = vec![false; set.files().len()];
    let mut directory_seen = vec![false; set.directories().len()];
    let mut stack: Vec<std::vec::IntoIter<Fingerprint>> =
        vec![set.root().children.clone().into_iter()];
    while let Some(level) = stack.last_mut() {
        let Some(child) = level.next() else {
            stack.pop();
            continue;
        };
        if let Some(&index) = files.get(&child) {
            if !std::mem::replace(&mut file_seen[index], true) {
                file_order.push(index);
            }
        } else if let Some(&index) = directories.get(&child)
            && !std::mem::replace(&mut directory_seen[index], true)
        {
            directory_order.push(index);
            stack.push(
                set.directories()[index]
                    .packet()
                    .children
                    .clone()
                    .into_iter(),
            );
        }
    }
    // Anything the walk missed keeps the engine's order at the end.
    file_order.extend((0..set.files().len()).filter(|&index| !file_seen[index]));
    directory_order.extend((0..set.directories().len()).filter(|&index| !directory_seen[index]));
    (file_order, directory_order)
}

/// What par3cmdline prints from the Creator, Comment and Start packets before
/// it finds that the set's tree is incomplete. Returns whether a Root packet
/// was found (so a File or Directory packet is what is missing).
fn print_partial_header(packets: &[IngestedPacket], noise: i32) -> bool {
    let root = packets
        .iter()
        .filter_map(IngestedPacket::metadata)
        .find_map(|packet| match packet.body() {
            par3_rs::PacketBody::Root(root) => Some(root.clone()),
            _ => None,
        });
    if noise < 0 {
        return root.is_some();
    }
    let bodies = || {
        packets
            .iter()
            .filter_map(IngestedPacket::metadata)
            .map(par3_rs::Packet::body)
    };
    if let Some(text) = bodies().find_map(|body| match body {
        par3_rs::PacketBody::Creator(creator) => Some(creator.text().into_owned()),
        _ => None,
    }) {
        println!();
        println!("Creator text:");
        println!("{}", text.trim_end_matches([' ', '\n', '\r', '\t']));
    }
    if let Some(text) = bodies().find_map(|body| match body {
        par3_rs::PacketBody::Comment(comment) => Some(comment.text().into_owned()),
        _ => None,
    }) {
        let text = text.trim_end_matches([' ', '\n', '\r', '\t']);
        println!();
        if text.contains('\n') {
            println!("Comment text:");
            println!("{text}");
        } else {
            println!("Comment text: {text}");
        }
    }
    let start = bodies().find_map(|body| match body {
        par3_rs::PacketBody::Start(start) => Some((start.block_size, start.galois_field)),
        _ => None,
    });
    let (block_size, size, generator) = start.map_or((0, 0, 0), |(block_size, field)| {
        let generator = if field.size == 0 {
            0
        } else {
            field.generator | (1 << (u64::from(field.size) * 8))
        };
        (block_size, field.size, generator)
    });
    println!();
    println!("Block size = {block_size}");
    if noise >= 1 {
        println!("Galois field size = {size}");
        println!("Galois field generator = 0x{generator:X}");
    }
    if let Some(root) = &root {
        println!("Block count = {}", root.lowest_unused_block_index);
        println!("Root attribute = {}", root.attributes);
    }
    root.is_some()
}

/// par3cmdline's 16-bit Cauchy decoder announces its matrix solve; the 8-bit
/// one solves silently.
fn print_matrix_solve(set: &Par3Set, started: Instant) {
    let cauchy = matches!(
        set.matrix_packets().first().map(|packet| packet.body()),
        Some(par3_rs::PacketBody::CauchyMatrix(_))
    );
    if cauchy && set.galois_field().size == 2 {
        println!();
        println!("Computing Reed Solomon matrix:");
        println!("done in {:.1} seconds.", started.elapsed().as_secs_f64());
    }
}

fn print_header(set: &Par3Set, file_order: &[usize], noise: i32, block_map: bool) {
    if noise < 0 {
        return;
    }
    for text in set.creator_texts() {
        println!();
        println!("Creator text:");
        println!("{}", text.trim_end_matches([' ', '\n', '\r', '\t']));
    }
    for text in set.comments() {
        let text = text.trim_end_matches([' ', '\n', '\r', '\t']);
        println!();
        if text.contains('\n') {
            println!("Comment text:");
            println!("{text}");
        } else {
            println!("Comment text: {text}");
        }
    }
    println!();
    println!("Block size = {}", set.block_size());
    if noise >= 1 {
        let field = set.galois_field();
        let generator = if field.size == 0 {
            0
        } else {
            field.generator | (1 << (u64::from(field.size) * 8))
        };
        println!("Galois field size = {}", field.size);
        println!("Galois field generator = 0x{generator:X}");
    }
    println!("Block count = {}", set.block_count());
    println!("Root attribute = {}", set.root().attributes);
    println!(
        "Number of input file = {}, directory = {}",
        set.files().len(),
        set.directories().len()
    );
    let chunks: usize = set.files().iter().map(|file| file.chunks().len()).sum();
    println!("Number of chunk description = {chunks}");
    if !file_order.is_empty() {
        let total: u64 = set.files().iter().map(par3_rs::Par3File::size).sum();
        let largest = set
            .files()
            .iter()
            .map(par3_rs::Par3File::size)
            .max()
            .unwrap_or(0);
        println!("Total file size = {total}");
        println!("Max file size = {largest}");
        // Only verify and repair map the blocks, and print what they found.
        if block_map {
            let (packed, deduplicated) = tail_packing(set);
            println!("Tail packing = {packed}, Deduplication = {deduplicated}");
        }
    }
}

/// par3cmdline's count of tails packed into a shared block and of slices that
/// repeat one already mapped, as its block map reports them.
fn tail_packing(set: &Par3Set) -> (u64, u64) {
    let block_size = set.block_size();
    let mut map = BlockMap::default();
    for file in set.files() {
        for chunk in file.chunks() {
            let par3_rs::ChunkDescription::Protected {
                length,
                first_block_index,
                tail,
            } = chunk
            else {
                continue;
            };
            if let Some(first) = first_block_index
                && block_size != 0
            {
                map.full_blocks(*first, length / block_size);
            }
            if let par3_rs::ChunkTail::Described {
                block_index,
                offset,
                ..
            } = tail
            {
                map.tail(*block_index, *offset, length % block_size.max(1));
            }
        }
    }
    (map.packed, map.deduplicated)
}

/// The block map par3cmdline builds for its report, kept as ranges so a set
/// that declares an enormous chunk costs work in its number of chunks, not in
/// its number of blocks.
#[derive(Default)]
struct BlockMap {
    /// Blocks some chunk fills completely, as disjoint `start -> end`
    /// (exclusive) ranges in a 65-bit index space.
    full: BTreeMap<u128, u128>,
    /// Per block: the (offset, size) of each tail mapped onto it.
    tails: BTreeMap<u64, Vec<(u64, u64)>>,
    /// Blocks holding tails that no full range covers yet.
    tail_only: BTreeSet<u64>,
    packed: u64,
    deduplicated: u64,
}

impl BlockMap {
    /// Map `count` whole blocks from `first`, wrapping past `u64::MAX` the
    /// way par3cmdline's index arithmetic does. Every block that already
    /// held a slice counts as deduplicated.
    fn full_blocks(&mut self, first: u64, count: u64) {
        let start = u128::from(first);
        let end = start + u128::from(count);
        let limit = 1u128 << 64;
        if end > limit {
            self.full_range(start, limit);
            self.full_range(0, end - limit);
        } else {
            self.full_range(start, end);
        }
    }

    fn full_range(&mut self, mut start: u128, mut end: u128) {
        if start >= end {
            return;
        }
        // Blocks already filled: overlap with every range touching this one.
        let mut overlap = 0u128;
        let touching: Vec<(u128, u128)> = self
            .full
            .range(..=end)
            .rev()
            .take_while(|&(_, &range_end)| range_end >= start)
            .map(|(&range_start, &range_end)| (range_start, range_end))
            .collect();
        for (range_start, range_end) in touching {
            overlap += range_end.min(end).saturating_sub(range_start.max(start));
            self.full.remove(&range_start);
            start = start.min(range_start);
            end = end.max(range_end);
        }
        // Blocks that held only tails until now.
        let first = u64::try_from(start).unwrap_or(u64::MAX);
        let tails: Vec<u64> = self
            .tail_only
            .range(first..)
            .take_while(|&&block| u128::from(block) < end)
            .copied()
            .collect();
        for block in &tails {
            self.tail_only.remove(block);
        }
        self.full.insert(start, end);
        let repeated = overlap + tails.len() as u128;
        self.deduplicated = self
            .deduplicated
            .saturating_add(u64::try_from(repeated).unwrap_or(u64::MAX));
    }

    fn covered(&self, block: u64) -> bool {
        let block = u128::from(block);
        self.full
            .range(..=block)
            .next_back()
            .is_some_and(|(_, &end)| end > block)
    }

    /// Map a tail of `size` bytes at `offset` within `block`.
    fn tail(&mut self, block: u64, offset: u64, size: u64) {
        let covered = self.covered(block);
        let slices = self.tails.entry(block).or_default();
        if slices.contains(&(offset, size)) {
            self.deduplicated = self.deduplicated.saturating_add(1);
        } else if covered || !slices.is_empty() {
            self.packed = self.packed.saturating_add(1);
        }
        slices.push((offset, size));
        if !covered {
            self.tail_only.insert(block);
        }
    }
}

fn print_listing(set: &Par3Set, file_order: &[usize], directory_order: &[usize], detail: u8) {
    if !file_order.is_empty() {
        let longest = file_order
            .iter()
            .map(|&index| set.files()[index].path().len())
            .max()
            .unwrap_or(0)
            .max(8);
        println!();
        let dashes = match detail {
            0 => {
                println!(" File ({})", file_order.len());
                print!(" ");
                longest.min(119)
            }
            1 => {
                println!(" Size (Bytes)  File ({})", file_order.len());
                print!(" ------------  ");
                longest.min(104)
            }
            _ => {
                println!(
                    " Size (Bytes)            BLAKE3 Hash            File ({})",
                    file_order.len()
                );
                print!(" ------------ --------------------------------  ");
                longest.min(71)
            }
        };
        println!("{}", "-".repeat(dashes));
        for &index in file_order {
            let file = &set.files()[index];
            match detail {
                0 => println!("\"{}\"", file.path()),
                1 => println!("{:13} \"{}\"", file.size(), file.path()),
                _ => {
                    let hash: String = file
                        .fingerprint()
                        .as_ref()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    println!("{:13} {hash} \"{}\"", file.size(), file.path());
                }
            }
        }
    }
    if !directory_order.is_empty() {
        let longest = directory_order
            .iter()
            .map(|&index| set.directories()[index].path().len())
            .max()
            .unwrap_or(0)
            .clamp(13, 119);
        println!();
        println!(" Directory ({})", directory_order.len());
        println!(" {}", "-".repeat(longest));
        for &index in directory_order {
            println!("\"{}\"", set.directories()[index].path());
        }
    }
    println!();
}

/// Join a name the PAR3 set supplies onto `root`, refusing anything but plain
/// components and any symlink on the way. With `link_at_name`, a read-only run
/// may find a link at the name itself and read through it, as par3cmdline
/// does; a run that may write there never accepts one.
fn member_path(root: &Path, name: &str, link_at_name: bool) -> Result<PathBuf, Failure> {
    let unsafe_name = || {
        Failure::new(
            RET_LOGIC_ERROR,
            format!("rarpar: unsafe PAR3 member path: {name}"),
        )
    };
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_name());
    }
    let mut joined = root.to_path_buf();
    let last = path.components().count();
    for (index, component) in path.components().enumerate() {
        joined.push(component);
        if link_at_name && index + 1 == last {
            break;
        }
        if std::fs::symlink_metadata(&joined).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(unsafe_name());
        }
    }
    Ok(joined)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    Missing,
    NotFile,
    Found,
    Complete,
    Damaged { available: u64, size: u64 },
}

fn verify(invocation: &Invocation, context: &Context) -> Result<(), Failure> {
    let options = &invocation.options;
    let noise = options.noise;
    let operation = invocation.operation;
    let trailer = match operation {
        Operation::List => "Failed to list files in PAR file",
        Operation::Verify => "Failed to verify with PAR file",
        _ => "Failed to repair with PAR file",
    };

    // Extra names: PAR3 files join the carriers, others are searched for
    // misnamed or moved input data.
    let mut extra = InputList::default();
    if operation != Operation::List {
        for argument in &invocation.files {
            if argument.is_empty() {
                continue;
            }
            path_search(&context.base, argument, &mut extra)
                .map_err(|failure| failure.with_trailer(format!("Failed to search: {argument}")))?;
        }
    }
    let (extra_carriers, extra_files): (Vec<_>, Vec<_>) = extra
        .files
        .iter()
        .map(|name| (context.base.join(native(name)), name.clone()))
        .partition(|(_, name)| name.to_ascii_lowercase().ends_with(".par3"));
    let extra_files: Vec<PathBuf> = extra_files.into_iter().map(|(path, _)| path).collect();

    let carriers = find_carriers(invocation, context, &extra_carriers);
    if carriers.is_empty() {
        return Err(Failure::new(RET_FILE_IO_ERROR, "PAR file is not found")
            .with_trailer("Failed to search PAR files"));
    }
    let loaded = load_carriers(&carriers, &context.execution, noise, trailer)?;
    let Some(id) = loaded.selected else {
        return Err(
            Failure::new(RET_INSUFFICIENT_DATA, "Failed to find PAR3 Start Packet")
                .with_trailer(trailer),
        );
    };
    let packets = loaded.sets.get(&id).cloned().unwrap_or_default();
    let mut incremental = IncrementalSet::new(id, context.execution.clone())
        .map_err(|error| engine_failure(error, trailer))?;
    for packet in &packets {
        incremental
            .merge(packet.clone())
            .map_err(|error| engine_failure(error, trailer))?;
    }
    let set = match incremental.metadata() {
        Ok(Some(set)) => set,
        Ok(None) => {
            let message = if print_partial_header(&packets, noise) {
                "File Packet or Directory Packet is missing."
            } else {
                "There is no Root Packet."
            };
            return Err(Failure::new(RET_INSUFFICIENT_DATA, message).with_trailer(trailer));
        }
        Err(error) => return Err(engine_failure(error, trailer)),
    };
    let (file_order, directory_order) = tree_order(&set);
    print_header(&set, &file_order, noise, operation != Operation::List);

    if operation == Operation::List {
        match noise {
            -1 => print_listing(&set, &file_order, &directory_order, 0),
            0 => print_listing(&set, &file_order, &directory_order, 1),
            noise if noise >= 1 => print_listing(&set, &file_order, &directory_order, 2),
            _ => {}
        }
        if noise >= -1 {
            println!("Listed");
        }
        return Ok(());
    }
    if noise == 1 {
        print_listing(&set, &file_order, &directory_order, 1);
    } else if noise >= 2 {
        print_listing(&set, &file_order, &directory_order, 2);
    }

    let base = &context.base;
    // Only a repair writes at the protected names, so only a repair refuses a
    // link at one.
    let link_at_name = operation != Operation::Repair;
    // Directories.
    let mut missing_directories = Vec::new();
    if !directory_order.is_empty() {
        if noise >= -1 {
            println!();
            println!("Verifying input directories:");
            println!();
        }
        for &index in &directory_order {
            let name = set.directories()[index].path();
            let path = member_path(base, name, link_at_name)
                .map_err(|failure| failure.with_trailer(trailer))?;
            let state = match std::fs::metadata(&path) {
                Ok(meta) if meta.is_dir() => " - found.",
                Ok(_) => " - not directory.",
                Err(_) => " - missing.",
            };
            if state != " - found." {
                missing_directories.push((name.to_owned(), path));
            }
            if noise >= -1 {
                println!("Target: \"{name}\"{state}");
            }
        }
    }

    // Files: bind each to the session, then assess.
    let mut execution = context.execution.clone();
    let candidates_count = extra_files.len();
    execution.open_handles = execution.open_handles.saturating_add(candidates_count);
    execution.handles = HandleBudget::new(execution.open_handles);
    let mut disk = DiskSourceAccess::with_options(execution.clone());
    let mut bindings = Vec::new();
    let mut destinations = BTreeMap::new();
    for file in set.files() {
        let path = member_path(base, file.path(), link_at_name)
            .map_err(|failure| failure.with_trailer(trailer))?;
        // Only a regular file (or a link to one) is a source; anything else
        // at the name is left unbound, so its contents count as missing and
        // it is reported as "not file" below.
        let regular = std::fs::metadata(&path).is_ok_and(|meta| meta.is_file());
        if regular {
            let source = SourceId(bindings.len() as u64);
            disk.insert(source, path.clone());
            bindings.push((file.path().to_owned(), source));
        }
        destinations.insert(file.path().to_owned(), path);
    }
    let mut candidates = Vec::new();
    for path in &extra_files {
        if destinations.values().any(|known| known == path) {
            continue;
        }
        let source = SourceId((bindings.len() + candidates.len()) as u64);
        disk.insert(source, path.clone());
        candidates.push(source);
    }
    let access: Arc<dyn SourceAccess> = Arc::new(disk);
    // Recovery blocks loaded for this set, counted once per matrix and index.
    let recovery_blocks = packets
        .iter()
        .filter_map(IngestedPacket::payload)
        .filter_map(|payload| match payload.kind() {
            PayloadKind::Recovery { matrix, index, .. } => Some((matrix, index)),
            PayloadKind::Data { .. } => None,
        })
        .collect::<BTreeSet<_>>()
        .len() as u64;
    let session_failure = |error: EngineError| engine_failure(error, trailer);
    let mut session =
        Par3RepairSession::new(id, access.clone(), execution.clone()).map_err(session_failure)?;
    for packet in packets {
        session.merge(packet).map_err(session_failure)?;
    }
    for (name, source) in &bindings {
        session.bind_file(name, *source).map_err(session_failure)?;
    }
    let first = session.assess().map_err(session_failure)?;
    let first_status = first.status;
    let unresolved: Vec<_> = first
        .files
        .iter()
        .map(|file| file.unresolved.clone())
        .collect();
    if matches!(
        first_status,
        RepairStatus::NeedRecovery | RepairStatus::Unsupported
    ) && !candidates.is_empty()
    {
        search_candidates(
            &mut session,
            access.as_ref(),
            &candidates,
            &unresolved,
            &execution,
            options.search_limit,
        )
        .map_err(session_failure)?;
    }
    let assessment = session.assess().map_err(session_failure)?;
    let status = assessment.status;
    if status == RepairStatus::IncompleteMetadata {
        return Err(
            Failure::new(RET_INSUFFICIENT_DATA, "There is no Root Packet.").with_trailer(trailer),
        );
    }
    let assessed: BTreeMap<String, (bool, Vec<std::ops::Range<u64>>)> = assessment
        .files
        .iter()
        .map(|file| (file.path.clone(), (file.complete, file.unresolved.clone())))
        .collect();
    let lost_blocks = assessment.lost_blocks.len() as u64;
    let requirements: Vec<(u64, u64)> = assessment
        .requirements
        .iter()
        .map(|need| (need.additional, need.cohorts))
        .collect();

    // Files with unprotected chunks ("PAR inside") are judged by their
    // protected chunks alone, as par3cmdline judges them.
    let layout = session.layout().map_err(session_failure)?;
    let embedded_layout = |name: &str| {
        layout
            .as_ref()
            .and_then(|layout| layout.files().iter().find(|file| file.path == name))
            .filter(|file| inside::has_unprotected(file))
            .cloned()
    };
    let mut embedded: BTreeMap<String, Vec<std::ops::Range<u64>>> = BTreeMap::new();

    if noise >= 0 {
        println!();
        println!("Verifying input files:");
        println!();
    }
    let mut states = Vec::new();
    for &index in &file_order {
        let file = &set.files()[index];
        let path = &destinations[file.path()];
        let state = match std::fs::metadata(path) {
            Err(_) => FileState::Missing,
            Ok(meta) if !meta.is_file() => FileState::NotFile,
            Ok(meta) if meta.len() == 0 && file.size() == 0 => FileState::Found,
            Ok(meta) if embedded_layout(file.path()).is_some() => {
                let size = meta.len();
                let unresolved = assessed
                    .get(file.path())
                    .map(|(_, unresolved)| unresolved.as_slice())
                    .unwrap_or_default();
                let layout = embedded_layout(file.path()).expect("checked above");
                let standing = inside::assess(&layout, unresolved, size);
                embedded.insert(file.path().to_owned(), standing.found);
                if standing.complete {
                    FileState::Complete
                } else {
                    FileState::Damaged {
                        available: standing.available,
                        size,
                    }
                }
            }
            Ok(meta) => {
                let size = meta.len();
                match assessed.get(file.path()) {
                    Some((true, _)) if size == file.size() => FileState::Complete,
                    Some((_, unresolved)) => {
                        // Bytes of the file as it stands that verified.
                        let damage: u64 = unresolved
                            .iter()
                            .map(|range| range.end.min(size).saturating_sub(range.start.min(size)))
                            .sum();
                        FileState::Damaged {
                            available: size - damage.min(size),
                            size,
                        }
                    }
                    None => FileState::Damaged { available: 0, size },
                }
            }
        };
        if noise >= 0 && matches!(state, FileState::Complete | FileState::Damaged { .. }) {
            println!("Opening: \"{}\"", file.path());
        }
        if noise >= -1 {
            match state {
                FileState::Missing => println!("Target: \"{}\" - missing.", file.path()),
                FileState::NotFile => println!("Target: \"{}\" - not file.", file.path()),
                FileState::Found => println!("Target: \"{}\" - found.", file.path()),
                FileState::Complete if embedded.contains_key(file.path()) => {
                    println!("Target: \"{}\" - protected data is complete.", file.path())
                }
                FileState::Complete => println!("Target: \"{}\" - complete.", file.path()),
                FileState::Damaged { available, size } => println!(
                    "Target: \"{}\" - damaged. {available} of {size} bytes available.",
                    file.path()
                ),
            }
        }
        states.push((file.path().to_owned(), state));
    }

    let missing_files = states
        .iter()
        .filter(|(_, state)| matches!(state, FileState::Missing | FileState::NotFile))
        .count();
    let damaged_files = states
        .iter()
        .filter(|(_, state)| matches!(state, FileState::Damaged { .. }))
        .count();
    // Bytes outside the protected chunks never make a repair necessary.
    if missing_directories.is_empty()
        && missing_files + damaged_files == 0
        && (status == RepairStatus::Complete || !embedded.is_empty())
    {
        if noise >= -1 {
            println!();
            println!("All files are correct, repair is not required.");
        }
        return Ok(());
    }
    if noise >= -1 {
        println!();
        println!("Repair is required.");
    }
    let block_count = set.block_count();
    let available = block_count.saturating_sub(lost_blocks);
    if noise >= 0 {
        let directories = directory_order.len();
        if !missing_directories.is_empty() {
            println!("{} directories are missing.", missing_directories.len());
        }
        if directories > missing_directories.len() {
            println!(
                "{} directories are ok.",
                directories - missing_directories.len()
            );
        }
        if missing_files > 0 {
            println!("{missing_files} files are missing.");
        }
        if damaged_files > 0 {
            println!("{damaged_files} files exist but are damaged.");
        }
        let ok = states.len() - missing_files - damaged_files;
        if ok > 0 {
            println!("{ok} files are ok.");
        }
        if missing_files + damaged_files > 0 {
            println!("You have {available} out of {block_count} input blocks available.");
        }
        // par3cmdline reports the count for each Matrix packet it holds,
        // once it holds any Recovery Data packet.
        if !set.matrix_packets().is_empty() && recovery_blocks > 0 {
            let codes = match set.matrix_packets().first().map(|packet| packet.body()) {
                Some(par3_rs::PacketBody::FftMatrix(_)) => "FFT based Reed-Solomon Codes",
                _ => "Cauchy Reed-Solomon Codes",
            };
            println!("You have {recovery_blocks} recovery blocks available for {codes}.");
        }
    }
    let possible = matches!(status, RepairStatus::Ready | RepairStatus::Complete);
    if !possible {
        let lack: u64 = requirements.iter().map(|(additional, _)| additional).sum();
        let cohorts = requirements.first().map_or(1, |(_, cohorts)| *cohorts);
        if noise >= -1 {
            println!("Repair is not possible.");
            if cohorts <= 1 {
                println!("You need {lack} more recovery blocks to be able to repair.");
            } else {
                let volumes = requirements
                    .iter()
                    .map(|(additional, _)| *additional)
                    .max()
                    .unwrap_or(0);
                println!(
                    "You need {lack} more recovery blocks ({volumes} volumes) to be able to repair."
                );
            }
        }
        return Ok(());
    }
    if noise >= -1 {
        println!("Repair is possible.");
    }
    if noise >= 0 {
        if lost_blocks == 0 {
            println!("None of the recovery blocks will be used for the repair.");
        } else {
            if recovery_blocks > lost_blocks {
                println!(
                    "You have an excess of {} recovery blocks.",
                    recovery_blocks - lost_blocks
                );
            }
            println!("{lost_blocks} recovery blocks will be used to repair.");
        }
    }
    if operation != Operation::Repair {
        return Ok(());
    }

    for (name, directory) in &missing_directories {
        // Made the way repair installs files: relative to a handle on the
        // base, never through a link swapped in since the check above.
        par3_rs::session_repair::create_directory(base, name).map_err(|error| {
            Failure::new(
                RET_FILE_IO_ERROR,
                format!("rarpar: {}: {error}", directory.display()),
            )
            .with_trailer(trailer)
        })?;
    }
    let mut repaired = Vec::new();
    if status == RepairStatus::Ready {
        let started = Instant::now();
        let self_repair = match set.files() {
            [file] if invocation.self_target && embedded.contains_key(file.path()) => {
                Some(file.path().to_owned())
            }
            _ => None,
        };
        if let Some(name) = self_repair {
            let layout = embedded_layout(&name).expect("embedded file layout");
            let matrix = set
                .matrix_packets()
                .first()
                .map(par3_rs::Packet::hash)
                .ok_or_else(|| Failure::new(RET_LOGIC_ERROR, "There is no Matrix Packet."))?;
            let installed = inside::self_repair(
                &mut session,
                base,
                &destinations[&name],
                id,
                matrix,
                &layout,
                &embedded[&name],
            )
            .map_err(session_failure)?;
            if noise >= 0 && lost_blocks > 0 {
                print_matrix_solve(&set, started);
                println!();
                println!("Recovering lost input blocks:");
                println!("done in {:.1} seconds.", started.elapsed().as_secs_f64());
            }
            if installed {
                repaired.push(name);
            }
        } else {
            let report = session.repair(base, true).map_err(session_failure)?;
            if noise >= 0 && lost_blocks > 0 {
                print_matrix_solve(&set, started);
                println!();
                println!("Recovering lost input blocks:");
                println!("done in {:.1} seconds.", started.elapsed().as_secs_f64());
            }
            for installed in report.installed {
                let name = destinations
                    .iter()
                    .find(|(_, path)| **path == installed.path)
                    .map(|(name, _)| name.clone())
                    .unwrap_or_else(|| installed.path.to_string_lossy().into_owned());
                repaired.push(name);
            }
        }
    }
    if noise >= 0 {
        println!();
        println!("Verifying repaired files:");
        println!();
        for (name, state) in &states {
            if !matches!(state, FileState::Complete | FileState::Found) {
                let fixed = repaired.contains(name);
                println!(
                    "Target: \"{name}\" - {}.",
                    match (fixed, embedded.contains_key(name)) {
                        (false, _) => "failed",
                        (true, true) => "protected data was repaired",
                        (true, false) => "repaired",
                    }
                );
            }
        }
    }
    let all_fixed = states
        .iter()
        .filter(|(_, state)| !matches!(state, FileState::Complete | FileState::Found))
        .all(|(name, _)| repaired.contains(name));
    println!();
    if all_fixed {
        println!("Repair complete.");
    } else {
        println!("Repair failed.");
    }
    Ok(())
}

/// Look through the extra files for blocks the damaged inputs lost, within
/// `-S` milliseconds when it is given.
fn search_candidates(
    session: &mut Par3RepairSession,
    access: &dyn SourceAccess,
    candidates: &[SourceId],
    unresolved: &[Vec<std::ops::Range<u64>>],
    execution: &ExecutionOptions,
    search_limit: u32,
) -> Result<(), EngineError> {
    let started = Instant::now();
    // `-S` also bounds a scan already under way: a timer cancels a token of
    // the search's own, and a cancelled scan ends the search with what it has
    // found so far.
    let mut search = execution.clone();
    let timer = (search_limit > 0).then(|| {
        let token = CancellationToken::default();
        search.cancel = token.clone();
        DeadlineTimer::start(
            token,
            started + Duration::from_millis(u64::from(search_limit)),
        )
    });
    let result = search_extents(
        session,
        access,
        candidates,
        unresolved,
        &search,
        started,
        search_limit,
    );
    drop(timer);
    match result {
        Err(EngineError::Cancelled) if search_limit > 0 => Ok(()),
        other => other,
    }
}

/// Cancels a token at a deadline unless dropped first; dropping it stops
/// and joins the timer thread.
struct DeadlineTimer {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DeadlineTimer {
    fn start(token: CancellationToken, deadline: Instant) -> Self {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let wait = deadline.saturating_duration_since(Instant::now());
            if let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(wait) {
                token.cancel();
            }
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for DeadlineTimer {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The search proper: every wanted extent, until the time is up or the
/// search's token is cancelled.
fn search_extents(
    session: &mut Par3RepairSession,
    access: &dyn SourceAccess,
    candidates: &[SourceId],
    unresolved: &[Vec<std::ops::Range<u64>>],
    execution: &ExecutionOptions,
    started: Instant,
    search_limit: u32,
) -> Result<(), EngineError> {
    let Some(layout) = session.layout()? else {
        return Ok(());
    };
    let mut limits = search_limits();
    for (file_index, file) in layout.files().iter().enumerate() {
        for (extent_index, extent) in file.extents.iter().enumerate() {
            if search_limit > 0 && started.elapsed().as_millis() >= u128::from(search_limit) {
                return Ok(());
            }
            let wanted = matches!(
                extent.kind,
                ExtentKind::Block {
                    fingerprint: Some(_),
                    rolling_hash: Some(_),
                    ..
                }
            ) && unresolved.get(file_index).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|range| range.start < extent.range.end && extent.range.start < range.end)
            });
            if !wanted {
                continue;
            }
            let found = search_extent(
                &layout,
                file_index,
                extent_index,
                access,
                candidates,
                &limits,
                execution,
            )?;
            limits.max_read_bytes = limits.max_read_bytes.saturating_sub(found.read_bytes);
            if let Some(placement) = found.matches.into_iter().next() {
                session.add_placement(placement)?;
            }
        }
    }
    Ok(())
}

/// par3cmdline searches every byte of every name it is given; only `-S`
/// bounds the search, by time. The API's safety defaults do not apply.
fn search_limits() -> PlacementOptions {
    PlacementOptions {
        max_read_bytes: u64::MAX,
        max_candidates: usize::MAX,
        ..PlacementOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn parsed(list: &[&str]) -> Invocation {
        match parse(&args(list)) {
            Ok(Parsed::Run(invocation)) => *invocation,
            other => panic!("expected an invocation, got {other:?}"),
        }
    }

    fn failure(list: &[&str]) -> Failure {
        match parse(&args(list)) {
            Err(failure) => failure,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn short_command_lines_print_help_version_or_the_argument_error() {
        assert!(matches!(parse(&args(&["-h"])), Ok(Parsed::Exit(0, _))));
        assert!(matches!(parse(&args(&["-V"])), Ok(Parsed::Exit(0, _))));
        assert!(matches!(parse(&args(&["-VV"])), Ok(Parsed::Exit(0, _))));
        for list in [&[][..], &["c"], &["-VV", "x"], &["-h", "x"]] {
            let failure = failure(list);
            if list.len() < 2 {
                assert_eq!(failure.code, RET_INVALID_COMMAND);
                assert_eq!(failure.lines[0], "Not enough command line arguments.");
            } else {
                // Two arguments, the first no command: help and code 3.
                assert_eq!(failure.code, RET_INVALID_COMMAND);
                assert!(failure.lines[0].starts_with("Usage:"));
            }
        }
    }

    #[test]
    fn commands_map_as_par3cmdline_maps_them() {
        for (word, operation, trial, self_target) in [
            ("c", Operation::Create, false, false),
            ("create", Operation::Create, false, false),
            ("tc", Operation::Create, true, false),
            ("v", Operation::Verify, false, false),
            ("verify", Operation::Verify, false, false),
            ("r", Operation::Repair, false, false),
            ("repair", Operation::Repair, false, false),
            ("l", Operation::List, false, false),
            ("list", Operation::List, false, false),
            ("e", Operation::Extend, false, false),
            ("extend", Operation::Extend, false, false),
            ("te", Operation::Extend, true, false),
            ("i", Operation::Insert, false, false),
            ("insert", Operation::Insert, false, false),
            ("ti", Operation::Insert, true, false),
            ("d", Operation::Delete, false, false),
            ("delete", Operation::Delete, false, false),
            ("vs", Operation::Verify, false, true),
            ("rs", Operation::Repair, false, true),
        ] {
            let target =
                if self_target || matches!(operation, Operation::Insert | Operation::Delete) {
                    "set.zip"
                } else {
                    "set"
                };
            let invocation = parsed(&[word, target]);
            assert_eq!(invocation.operation, operation, "{word}");
            assert_eq!(invocation.trial, trial, "{word}");
            assert_eq!(invocation.self_target, self_target, "{word}");
        }
        assert!(failure(&["C", "set"]).lines[0].starts_with("Usage:"));
        assert!(failure(&["x", "set"]).lines[0].starts_with("Usage:"));
    }

    #[test]
    fn every_option_is_read_as_par3cmdline_reads_it() {
        let invocation = parsed(&[
            "c",
            "-v",
            "-vv",
            "-q",
            "-m3k",
            "-B.",
            "-s1000",
            "-r10",
            "-rm20",
            "-cf2",
            "-cm9",
            "-u",
            "-n2",
            "-R",
            "-D",
            "-d1",
            "-e8",
            "-i3",
            "-lp4",
            "-C\"one\"",
            "-Ctwo ",
            "set",
            "a",
            "b",
        ]);
        let options = &invocation.options;
        assert_eq!(options.noise, 2);
        assert_eq!(options.memory_limit, 3 << 10);
        assert_eq!(options.base_path, ".");
        assert_eq!(options.block_size, 1000);
        assert_eq!(options.redundancy, 10);
        assert_eq!(options.max_redundancy, 20);
        assert_eq!(options.first_recovery, 2);
        assert_eq!(options.max_recovery, 9);
        assert_eq!(options.file_scheme, -1);
        assert_eq!(options.file_count, 2);
        assert!(options.recursive && options.data_packets);
        assert_eq!(options.dedup, b'1');
        assert_eq!(options.ecc, 8);
        assert_eq!(options.interleave, 3);
        assert_eq!(options.repetition_limit, 4);
        assert_eq!(options.comment.as_deref(), Some("one\ntwo"));
        assert_eq!(invocation.files, ["a", "b"]);
        assert!(invocation.par_filename.ends_with("set.par3"));

        let options =
            parsed(&["v", "-S250", "-qq", "-m2GB", "-abs", "-fu", "-ff", "x.par3"]).options;
        assert_eq!(options.search_limit, 250);
        assert_eq!(options.noise, -2);
        assert_eq!(options.memory_limit, 2 << 30);
        assert_eq!(options.absolute, b'a');
        assert_eq!(options.file_system, 0x10007);
        assert_eq!(parsed(&["c", "-l", "x"]).options.file_scheme, -2);
        assert_eq!(parsed(&["c", "-l4096", "x"]).options.file_scheme, 4096);
        assert_eq!(parsed(&["c", "-fu5", "x"]).options.file_system, 5);
        assert_eq!(parsed(&["c", "-ABS", "x"]).options.absolute, b'A');
        assert_eq!(parsed(&["c", "-b7", "x"]).options.block_count, 7);
        assert_eq!(parsed(&["c", "-c7", "x"]).options.recovery_count, 7);
    }

    #[test]
    fn option_conflicts_fail_with_par3cmdline_messages() {
        for (list, message) in [
            (
                &["c", "-b5", "-s5", "a"][..],
                "Cannot specify both block count and block size.",
            ),
            (
                &["c", "-s5", "-b5", "a"],
                "Cannot specify both block count and block size.",
            ),
            (
                &["c", "-s5", "-s5", "a"],
                "Cannot specify block size twice.",
            ),
            (
                &["c", "-b5", "-b5", "a"],
                "Cannot specify block count twice.",
            ),
            (
                &["v", "-b4", "set"],
                "Cannot specify block count unless creating.",
            ),
            (
                &["v", "-s4", "set"],
                "Cannot specify block size unless creating.",
            ),
            (
                &["c", "-r5", "-c5", "a"],
                "Cannot specify both recovery block count and redundancy.",
            ),
            (
                &["c", "-c5", "-r5", "a"],
                "Cannot specify both redundancy and recovery block count.",
            ),
            (
                &["c", "-r5", "-r6", "a"],
                "Cannot specify redundancy twice.",
            ),
            (
                &["v", "-r5", "a"],
                "Cannot specify redundancy unless creating.",
            ),
            (
                &["c", "-cm5", "-rm5", "a"],
                "Cannot specify both max redundancy and recovery block count.",
            ),
            (
                &["c", "-u", "-l", "a"],
                "Cannot specify two recovery file size schemes.",
            ),
            (
                &["c", "-n2", "-l", "a"],
                "Cannot specify limited size and number of files at the same time.",
            ),
            (
                &["c", "-l", "-n2", "a"],
                "Cannot specify limited size and number of files at the same time.",
            ),
            (
                &["c", "-d0", "-d1", "a"],
                "Cannot specify deduplication twice.",
            ),
            (
                &["e", "-d1", "a"],
                "Cannot specify deduplication unless creating.",
            ),
            (
                &["e", "-R", "a"],
                "Cannot specify Recursive unless creating.",
            ),
            (&["e", "-C", "a"], "Invalid option specified: -C"),
            (
                &["e", "-Cx", "a"],
                "Cannot specify comment unless creating.",
            ),
            (
                &["c", "-e1", "-e8", "a"],
                "Cannot specify Error Correction Codes twice.",
            ),
            (
                &["c", "-i1", "-i2", "a"],
                "Cannot specify interleaving twice.",
            ),
            (
                &["c", "-fu", "-fu1", "a"],
                "Cannot specify UNIX Permissions Packet twice.",
            ),
            (
                &["c", "-ff", "-ff", "a"],
                "Cannot specify FAT Permissions Packet twice.",
            ),
            (
                &["c", "-lp1", "-lp2", "a"],
                "Cannot specify max repetition twice.",
            ),
            (
                &["c", "-abs", "-ABS", "a"],
                "Cannot enable absolute path twice.",
            ),
            (
                &["c", "-m1", "-m2", "a"],
                "Cannot specify memory limit twice.",
            ),
            (
                &["c", "-S1", "a"],
                "Cannot specify searching time limit unless reparing or verifying.",
            ),
            (
                &["v", "-S1", "-S2", "a"],
                "Cannot specify searching time limit twice.",
            ),
            (&["l", "-Bx", "a"], "Cannot specify base-path for listing."),
            (
                &["i", "-Bx", "a.zip"],
                "Cannot specify base-path for PAR inside.",
            ),
            (&["v", "-Bx", "-By", "a"], "Cannot specify base-path twice."),
            (&["v", "-Z", "s"], "Invalid option specified: -Z"),
            (&["v", "-", "s"], "Invalid option specified: -"),
            (&["v", "-d3", "s"], "Invalid option specified: -d3"),
            (&["v", "-q"], "PAR filename is not specified"),
            (&["v", "--"], "PAR filename is not specified"),
        ] {
            let failure = failure(list);
            assert_eq!(failure.code, RET_INVALID_COMMAND, "{list:?}");
            assert_eq!(failure.lines.last().unwrap(), message, "{list:?}");
        }
    }

    #[test]
    fn soft_option_errors_print_and_carry_on() {
        let invocation = parsed(&["c", "-r300", "-e9", "set", "a"]);
        assert_eq!(invocation.options.redundancy, 0);
        assert_eq!(invocation.options.ecc, 0);
        assert_eq!(
            invocation.notices,
            [
                "Invalid redundancy option: 300",
                "Cannot specify multiple Error Correction Codes."
            ]
        );
        // The reset lets the option be given again.
        assert_eq!(parsed(&["c", "-e3", "-e8", "set"]).options.ecc, 8);
        let failure = failure(&["l", "a*"]);
        assert_eq!(
            failure.lines,
            [
                "Found wildcard in PAR filename, a*",
                "PAR filename is not specified"
            ]
        );
    }

    #[test]
    fn par_filename_takes_the_par3_extension_and_double_dash_ends_options() {
        assert_eq!(parsed(&["v", "set"]).par_filename, "set.par3");
        assert_eq!(parsed(&["v", "set.PAR3"]).par_filename, "set.PAR3");
        assert_eq!(parsed(&["v", "--", "-set"]).par_filename, "-set.par3");
        let invocation = parsed(&["c", "-s100", "a.bin"]);
        assert_eq!(invocation.par_filename, "a.bin.par3");
        assert_eq!(invocation.par_argument, "a.bin");
        assert!(invocation.files.is_empty());
        // An absolute PAR filename gives the base path; what counts as
        // absolute, and which separators split it, is the platform's.
        if cfg!(windows) {
            let invocation = parsed(&["v", r"C:\data\sets\set.par3"]);
            assert_eq!(invocation.options.base_path, r"C:\data\sets");
            let invocation = parsed(&["v", "C:/data/sets/set.par3"]);
            assert_eq!(invocation.options.base_path, "C:/data/sets");
            // Rooted without a drive is not absolute there.
            let invocation = parsed(&["v", "/data/sets/set.par3"]);
            assert_eq!(invocation.options.base_path, "");
        } else {
            let invocation = parsed(&["v", "/data/sets/set.par3"]);
            assert_eq!(invocation.options.base_path, "/data/sets");
        }
        let invocation = parsed(&["rs", "dir/set.zip"]);
        assert_eq!(invocation.options.base_path, "dir");
        assert_eq!(invocation.par_filename, "set.zip");
        let failure = failure(&["vs", "set.par3"]);
        assert_eq!(failure.code, RET_FILE_IO_ERROR);
        assert_eq!(failure.lines, ["File extension is different from ZIP."]);
    }

    #[test]
    fn the_rarpar_name_claims_only_par3_command_lines() {
        let os = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(claims(&os(&["c", "-r10", "set.par3", "a.bin"])));
        assert!(claims(&os(&["v", "set.PAR3"])));
        assert!(claims(&os(&["l", "--", "set.par3"])));
        assert!(claims(&os(&["vs", "set.zip"])));
        assert!(!claims(&os(&["v", "set"])));
        assert!(!claims(&os(&["x", "archive.rar"])));
        assert!(!claims(&os(&["l", "archive.rar", "set.par3"])));
        assert!(!claims(&os(&["r", "set.par2"])));
        assert!(!claims(&os(&["auto", "set.par3"])));
        assert!(invoked_as_par3(OsStr::new("/opt/bin/par3")));
        assert!(invoked_as_par3(OsStr::new("PAR3.exe")));
        assert!(!invoked_as_par3(OsStr::new("rarpar")));
        assert!(!invoked_as_par3(OsStr::new("par2")));
    }

    #[test]
    fn wildcards_match_as_findfirst_does() {
        assert!(wildcard_match(b"*", b"alpha.bin"));
        assert!(wildcard_match(b"*.bin", b"alpha.bin"));
        assert!(wildcard_match(b"a?pha.*", b"alpha.bin"));
        assert!(!wildcard_match(b"*.txt", b"alpha.bin"));
        assert!(wildcard_match(b"alpha.bin", b"alpha.bin"));
        assert!(!wildcard_match(b"alpha", b"alpha.bin"));
    }

    #[test]
    fn moved_file_searches_carry_no_byte_or_candidate_ceiling() {
        let limits = search_limits();
        assert_eq!(limits.max_read_bytes, u64::MAX);
        assert_eq!(limits.max_candidates, usize::MAX);
    }

    #[cfg(unix)]
    #[test]
    fn native_arguments_survive_the_parser_byte_for_byte() {
        use std::os::unix::ffi::OsStrExt;
        for bytes in [
            &b"plain.par3"[..],
            b"caf\xe9.par3",
            b"\xff\xfe/\x80set",
            b"ok\xc3",
        ] {
            let original = OsStr::from_bytes(bytes);
            assert_eq!(native(&escape(original)), original, "{bytes:?}");
        }
        assert_eq!(escape(OsStr::new("set.par3")), "set.par3");
        let invocation = parsed(&["v", &escape(OsStr::from_bytes(b"sub\xff/set.par3"))]);
        assert_eq!(
            native(&invocation.par_filename).as_bytes(),
            b"sub\xff/set.par3"
        );
    }

    /// The `-S` timer cancels the search's token once its deadline passes,
    /// so a scan under way stops; dropped before its deadline it cancels
    /// nothing and its thread is joined.
    #[test]
    fn the_search_deadline_cancels_its_token_only_once_due() {
        let due = CancellationToken::default();
        let timer = DeadlineTimer::start(due.clone(), Instant::now());
        while due.check().is_ok() {
            std::thread::yield_now();
        }
        drop(timer);
        assert!(matches!(due.check(), Err(EngineError::Cancelled)));

        let early = CancellationToken::default();
        let far = Instant::now() + Duration::from_secs(24 * 60 * 60);
        drop(DeadlineTimer::start(early.clone(), far));
        assert!(early.check().is_ok());
    }

    #[test]
    fn self_targets_split_on_native_separators() {
        let invocation = parsed(&["vs", "sub/set.zip"]);
        assert_eq!(invocation.options.base_path, "sub");
        assert_eq!(invocation.par_filename, "set.zip");
        #[cfg(windows)]
        {
            let invocation = parsed(&["vs", "sub\\set.zip"]);
            assert_eq!(invocation.options.base_path, "sub");
            assert_eq!(invocation.par_filename, "set.zip");
        }
        #[cfg(not(windows))]
        assert_eq!(last_separator("sub\\set.zip"), None);
    }

    #[test]
    fn every_unix_permissions_spelling_is_remembered() {
        for option in ["-fu", "-fu0", "-fu8", "-fu7"] {
            assert!(
                parsed(&["v", option, "set"]).options.unix_permissions_given,
                "{option}"
            );
        }
    }

    #[test]
    fn block_map_counts_as_the_per_block_walk_does() {
        let mut map = BlockMap::default();
        map.full_blocks(0, 4); // blocks 0..4
        map.full_blocks(2, 4); // 2 and 3 repeat
        assert_eq!((map.packed, map.deduplicated), (0, 2));
        map.tail(9, 0, 10);
        map.tail(9, 10, 5); // shares block 9
        map.tail(9, 0, 10); // repeats the first tail
        map.tail(5, 0, 7); // lands on a full block
        assert_eq!((map.packed, map.deduplicated), (2, 3));
        // A full range over a tail-only block counts it once.
        map.full_blocks(8, 3); // 8, 9, 10: only 9 held slices
        assert_eq!((map.packed, map.deduplicated), (2, 4));
        map.full_blocks(9, 1);
        assert_eq!((map.packed, map.deduplicated), (2, 5));
    }

    #[test]
    fn block_map_takes_a_full_index_space_chunk_without_expanding_it() {
        // A chunk of u64::MAX one-byte blocks, then another over the same
        // space: counted from ranges, never materialised.
        let mut map = BlockMap::default();
        map.full_blocks(0, u64::MAX);
        assert_eq!(map.deduplicated, 0);
        map.full_blocks(1, u64::MAX); // 1..=u64::MAX: all but the last repeat
        assert_eq!(map.deduplicated, u64::MAX - 1);
        map.tail(u64::MAX, 0, 1);
        assert_eq!(map.packed, 1);
        // Index arithmetic wraps past u64::MAX onto block 0.
        let mut map = BlockMap::default();
        map.full_blocks(u64::MAX, 2);
        map.full_blocks(0, 1);
        assert_eq!(map.deduplicated, 1);
    }
}
