//! The 7-Zip-compatible facade: `rarpar 7z ...`, or rarpar started as `7z`,
//! `7za`, `7zz` or `7zr`.
//!
//! The default suite runs on archives sevenz-turbo writes. The ignored
//! matrix at the end runs the same command lines under a reference 7-Zip
//! (`SEVENZ_REFERENCE_BIN`) and under the facade, and compares exit codes,
//! every output line and the extracted trees byte for byte.

#![cfg(feature = "sevenz")]

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sevenz_turbo::encoder_options::AesEncoderOptions;
use sevenz_turbo::{
    ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password, SourceReader,
};

fn bytes(size: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761) | 1;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// Invented members, in the order 7-Zip stores them: folders, empty files,
/// then files with data. `None` is a folder.
fn members() -> Vec<(&'static str, Option<Vec<u8>>)> {
    vec![
        ("attic", None),
        ("cellar", None),
        ("cellar/vault", None),
        ("blank.dat", Some(Vec::new())),
        ("static.bin", Some(bytes(150_000, 3))),
        ("ledger.txt", Some(b"quartz ferry ".repeat(4000))),
        ("cellar/vault/tally.raw", Some(bytes(4321, 9))),
        ("cellar/f\u{f6}rd \u{2603}.txt", Some("h\u{e9}llo\n".into())),
    ]
}

/// How a test archive is written.
#[derive(Clone, Copy)]
struct Shape {
    methods: fn() -> Vec<EncoderConfiguration>,
    solid: bool,
    encrypt_header: bool,
}

fn lzma2() -> Vec<EncoderConfiguration> {
    vec![EncoderMethod::LZMA2.into()]
}

/// AES-256 over LZMA2 with a fixed salt and IV. With the random ones
/// `AesEncoderOptions::new` draws, a wrong password decrypts to different
/// bytes on every run, and LZMA2 then either faults ("Data Error") or decodes
/// garbage that fails the member CRC ("CRC Failed"): the message a test sees
/// would change from run to run. Fixed values make the archive, and so the
/// route a wrong password takes, the same every time.
fn sealed() -> Vec<EncoderConfiguration> {
    let mut aes = AesEncoderOptions::new(Password::from("lantern"));
    aes.salt = *b"invented-salt-01";
    aes.iv = *b"invented-iv-0001";
    vec![aes.into(), EncoderMethod::LZMA2.into()]
}

const SOLID: Shape = Shape {
    methods: lzma2,
    solid: true,
    encrypt_header: false,
};

fn write_archive(path: &Path, shape: Shape) {
    let mut out = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut out)).unwrap();
        writer.set_content_methods((shape.methods)());
        writer.set_encrypt_header(shape.encrypt_header);
        let mut solid_entries = Vec::new();
        let mut solid_readers = Vec::new();
        for (name, data) in members() {
            match data {
                None => {
                    writer
                        .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(name), None)
                        .unwrap();
                }
                Some(data) if data.is_empty() => {
                    writer
                        .push_archive_entry::<&[u8]>(ArchiveEntry::new_file(name), None)
                        .unwrap();
                }
                Some(data) if shape.solid => {
                    solid_entries.push(ArchiveEntry::new_file(name));
                    solid_readers.push(SourceReader::new(Cursor::new(data)));
                }
                Some(data) => {
                    writer
                        .push_archive_entry(ArchiveEntry::new_file(name), Some(data.as_slice()))
                        .unwrap();
                }
            }
        }
        if !solid_entries.is_empty() {
            writer
                .push_archive_entries(solid_entries, solid_readers)
                .unwrap();
        }
        writer.finish().unwrap();
    }
    std::fs::write(path, out).unwrap();
}

fn facade(cwd: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(cwd)
        .arg("7z")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[track_caller]
fn expect(output: &Output, code: i32) -> (String, String) {
    let (out, err) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={out}\nstderr={err}"
    );
    (out, err)
}

/// Every member extracted under `dir` matches its source.
#[track_caller]
fn assert_tree(dir: &Path) {
    for (name, data) in members() {
        let path = dir.join(name);
        match data {
            None => assert!(path.is_dir(), "{name} is not a folder"),
            Some(data) => assert_eq!(std::fs::read(&path).unwrap(), data, "{name}"),
        }
    }
}

fn shapes() -> Vec<(&'static str, Shape)> {
    fn copy() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::COPY.into()]
    }
    fn lzma() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::LZMA.into()]
    }
    fn ppmd() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::PPMD.into()]
    }
    fn bzip2() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::BZIP2.into()]
    }
    fn deflate() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::DEFLATE.into()]
    }
    fn bcj() -> Vec<EncoderConfiguration> {
        vec![
            EncoderMethod::LZMA2.into(),
            EncoderMethod::BCJ_X86_FILTER.into(),
        ]
    }
    fn arm64() -> Vec<EncoderConfiguration> {
        vec![
            EncoderMethod::LZMA2.into(),
            EncoderMethod::BCJ_ARM64_FILTER.into(),
        ]
    }
    let shape = |methods, solid| Shape {
        methods,
        solid,
        encrypt_header: false,
    };
    vec![
        ("lzma2.7z", SOLID),
        ("lzma.7z", shape(lzma, true)),
        ("ppmd.7z", shape(ppmd, true)),
        ("bzip2.7z", shape(bzip2, true)),
        ("deflate.7z", shape(deflate, true)),
        ("copy.7z", shape(copy, false)),
        ("bcj.7z", shape(bcj, true)),
        ("arm64.7z", shape(arm64, true)),
        ("loose.7z", shape(lzma2, false)),
    ]
}

#[test]
fn extracts_every_method_and_layout() {
    let dir = tempfile::tempdir().unwrap();
    for (name, shape) in shapes() {
        write_archive(&dir.path().join(name), shape);
        let out_dir = format!("-o{name}.out");
        let (out, err) = expect(&facade(dir.path(), &["x", "-y", &out_dir, name], b""), 0);
        assert!(out.contains("Everything is Ok\n"), "{name}: {out}");
        assert!(out.contains("\nType = 7z\n"), "{name}: {out}");
        assert!(err.is_empty(), "{name}: {err}");
        assert_tree(&dir.path().join(format!("{name}.out")));
        let (out, _) = expect(&facade(dir.path(), &["t", name], b""), 0);
        assert!(out.contains("Everything is Ok\n"), "{name}: {out}");
    }
}

#[test]
fn summary_counts_folders_files_and_sizes() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("set.7z"), SOLID);
    let (out, _) = expect(&facade(dir.path(), &["x", "-y", "-oout", "set.7z"], b""), 0);
    let size: usize = members()
        .iter()
        .filter_map(|(_, data)| data.as_ref().map(Vec::len))
        .sum();
    let physical = std::fs::metadata(dir.path().join("set.7z")).unwrap().len();
    assert!(
        out.ends_with(&format!(
            "Everything is Ok\n\nFolders: 3\nFiles: 5\nSize:       {size}\nCompressed: {physical}\n"
        )),
        "{out}"
    );
    assert!(out.contains("\nSolid = +\nBlocks = 1\n"), "{out}");
}

/// The banner carries a version and the word SABnzbd's version check looks
/// for, and a bare `7z` prints help and succeeds.
#[test]
fn bare_invocation_prints_banner_and_help() {
    let dir = tempfile::tempdir().unwrap();
    let (out, _) = expect(&facade(dir.path(), &[], b""), 0);
    let first = out.lines().nth(1).unwrap();
    let version = first
        .split_whitespace()
        .find(|word| word.contains('.') && word.chars().all(|c| c.is_ascii_digit() || c == '.'));
    assert!(version.is_some() && first.contains("Copyright"), "{out}");
    assert!(out.contains("Usage: 7z <command>"), "{out}");
}

#[cfg(unix)]
#[test]
fn program_names_select_the_facade() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("set.7z"), SOLID);
    for program in ["7z", "7za", "7ZZ", "7zr"] {
        let link = dir.path().join(program);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_rarpar"), &link).unwrap();
        let output = Command::new(&link)
            .current_dir(dir.path())
            .args(["t", "set.7z"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let (out, _) = expect(&output, 0);
        assert!(
            out.contains("Testing archive: set.7z\n"),
            "{program}: {out}"
        );
    }
}

#[test]
fn creation_and_other_commands_are_command_line_errors() {
    let dir = tempfile::tempdir().unwrap();
    for command in ["a", "u", "d", "rn", "h", "b", "i"] {
        let (out, err) = expect(&facade(dir.path(), &[command, "set.7z", "x"], b""), 7);
        assert_eq!(
            err,
            format!("\n\nCommand Line Error:\nUnsupported command:\n{command}\n")
        );
        assert!(!out.contains("Scanning"), "{out}");
    }
    assert!(!dir.path().join("set.7z").exists());
    let (out, err) = expect(&facade(dir.path(), &["x", "-zz", "set.7z"], b""), 7);
    assert_eq!(err, "\n\nCommand Line Error:\nUnknown switch:\n-zz\n");
    assert!(out.is_empty());
    let (_, err) = expect(&facade(dir.path(), &["x"], b""), 7);
    assert_eq!(err, "\n\nCommand Line Error:\nCannot find archive name\n");
}

#[test]
fn missing_archive_is_a_system_error() {
    let dir = tempfile::tempdir().unwrap();
    let (out, err) = expect(&facade(dir.path(), &["x", "-y", "absent.7z"], b""), 2);
    assert!(out.ends_with("Scanning the drive for archives:\n"), "{out}");
    assert!(
        err.starts_with("\nERROR: errno=2 : ")
            && err.contains("\nabsent.7z\n\n\n\nSystem ERROR:\n"),
        "{err}"
    );
    let (_, err) = expect(&facade(dir.path(), &["x", "-y", "*.7z"], b""), 7);
    assert_eq!(err, "\n\nCommand Line Error:\nCannot find archive\n");
}

/// SABnzbd's command lines, as it builds them.
#[test]
fn sabnzbd_command_lines() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("set.7z"), SOLID);
    let sealed_shape = Shape {
        methods: sealed,
        solid: true,
        encrypt_header: false,
    };
    write_archive(&dir.path().join("sealed.7z"), sealed_shape);
    let out_dir = dir.path().join("dest");
    let out_arg = format!("-o{}", out_dir.display());

    // Listing: SABnzbd reads the `Path = ` lines.
    let (out, _) = expect(
        &facade(
            dir.path(),
            &["l", "-p", "-y", "-slt", "-sccUTF-8", "set.7z"],
            b"",
        ),
        0,
    );
    let paths: Vec<&str> = out
        .lines()
        .filter_map(|line| line.strip_prefix("Path = "))
        .collect();
    let mut expected = vec!["set.7z"];
    expected.extend(members().iter().map(|(name, _)| *name));
    assert_eq!(paths, expected);

    // Extraction, overwriting and with case-sensitive names.
    for (overwrite, case) in [("-aoa", "-ssc"), ("-aou", "-ssc-")] {
        let (out, _) = expect(
            &facade(
                dir.path(),
                &["x", "-y", overwrite, case, "-p", &out_arg, "set.7z"],
                b"",
            ),
            0,
        );
        assert!(out.contains("Everything is Ok"), "{out}");
    }
    assert_tree(&out_dir);
    assert_eq!(
        std::fs::read(out_dir.join("static_1.bin")).unwrap(),
        bytes(150_000, 3),
        "-aou renames the new copy"
    );

    // A single member to standard output.
    let output = facade(
        dir.path(),
        &["e", "-p", "-y", "-so", "set.7z", "ledger.txt"],
        b"",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"quartz ferry ".repeat(4000));

    // The right password, and the wrong one SABnzbd greps stderr for.
    let (out, _) = expect(
        &facade(
            dir.path(),
            &[
                "x",
                "-y",
                "-aoa",
                "-ssc",
                "-plantern",
                &out_arg,
                "sealed.7z",
            ],
            b"",
        ),
        0,
    );
    assert!(out.contains("Everything is Ok"), "{out}");
    let (_, err) = expect(
        &facade(
            dir.path(),
            &["x", "-y", "-aoa", "-ssc", "-pwrong", &out_arg, "sealed.7z"],
            b"",
        ),
        2,
    );
    assert!(
        err.contains("ERROR: Data Error in encrypted file. Wrong password? : static.bin"),
        "{err}"
    );
}

/// NZBGet runs `7z x -y -p- -o<dest> *.7z` (or `*.7z.001`) in the download
/// folder, and wants exit code 0 and "Everything is Ok".
#[test]
fn nzbget_command_lines() {
    let dir = tempfile::tempdir().unwrap();
    let download = dir.path().join("download");
    std::fs::create_dir(&download).unwrap();
    write_archive(&download.join("show.7z"), SOLID);
    let whole = std::fs::read(download.join("show.7z")).unwrap();
    let split = dir.path().join("split");
    std::fs::create_dir(&split).unwrap();
    for (index, piece) in whole.chunks(40_000).enumerate() {
        std::fs::write(split.join(format!("show.7z.{:03}", index + 1)), piece).unwrap();
    }
    for (cwd, pattern) in [(&download, "*.7z"), (&split, "*.7z.001")] {
        let out_arg = format!("-o{}", cwd.join("out").display());
        let (out, _) = expect(&facade(cwd, &["x", "-y", "-p-", &out_arg, pattern], b""), 0);
        assert!(out.contains("Everything is Ok"), "{out}");
        assert_tree(&cwd.join("out"));
    }
    // Every volume of the split set matches the pattern; one archive opens.
    let out_arg = format!("-o{}", split.join("all").display());
    let (out, _) = expect(&facade(&split, &["x", "-y", "-p-", &out_arg, "*"], b""), 0);
    assert!(out.contains("Type = Split\n"), "{out}");
    assert_eq!(out.matches("Extracting archive:").count(), 1, "{out}");
}

#[test]
fn header_encrypted_archives_ask_once_and_report_wrong_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let shape = Shape {
        methods: sealed,
        solid: true,
        encrypt_header: true,
    };
    write_archive(&dir.path().join("hidden.7z"), shape);
    let (out, _) = expect(
        &facade(dir.path(), &["x", "-y", "-oa", "hidden.7z"], b"lantern\n"),
        0,
    );
    assert_eq!(out.matches("Enter password:").count(), 1, "{out}");
    assert_tree(&dir.path().join("a"));

    let (_, err) = expect(
        &facade(dir.path(), &["x", "-y", "-pwrong", "-ob", "hidden.7z"], b""),
        2,
    );
    assert_eq!(
        err,
        "ERROR: hidden.7z\nCannot open encrypted archive. Wrong password?\n\n"
    );
    let (out, err) = expect(&facade(dir.path(), &["l", "hidden.7z"], b""), 255);
    assert!(out.ends_with("Enter password:\n"), "{out}");
    assert_eq!(err, "\n\nBreak signaled\n");
}

#[test]
fn damage_reports_the_member_and_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    fn copy() -> Vec<EncoderConfiguration> {
        vec![EncoderMethod::COPY.into()]
    }
    let shape = Shape {
        methods: copy,
        solid: false,
        encrypt_header: false,
    };
    let path = dir.path().join("worn.7z");
    write_archive(&path, shape);
    let mut data = std::fs::read(&path).unwrap();
    // The first stored member's bytes start right after the 32-byte header.
    data[32 + 100] ^= 0xFF;
    std::fs::write(&path, data).unwrap();
    let (out, err) = expect(
        &facade(dir.path(), &["x", "-y", "-oout", "worn.7z"], b""),
        2,
    );
    assert_eq!(err, "ERROR: CRC Failed : static.bin\n");
    assert!(
        out.ends_with("\nSub items Errors: 1\n\nArchives with Errors: 1\n\nSub items Errors: 1\n"),
        "{out}"
    );
    let kept = std::fs::read(dir.path().join("out/static.bin")).unwrap();
    // A stored member keeps every byte, damaged ones included.
    assert_eq!(kept.len(), 150_000);
    assert_ne!(kept, bytes(150_000, 3));
    assert_eq!(
        std::fs::read(dir.path().join("out/ledger.txt")).unwrap(),
        b"quartz ferry ".repeat(4000)
    );

    // Cut short: 7-Zip cannot open it.
    let whole = std::fs::read(dir.path().join("worn.7z")).unwrap();
    std::fs::write(dir.path().join("short.7z"), &whole[..whole.len() - 10]).unwrap();
    let (_, err) = expect(&facade(dir.path(), &["t", "short.7z"], b""), 2);
    assert_eq!(
        err,
        "ERROR: short.7z\nshort.7z\nOpen ERROR: Cannot open the file as [7z] archive\n\n\nERRORS:\nUnexpected end of archive\n"
    );
}

/// Bytes after the archive, such as a PAR3 set inside it, are a warning,
/// not an error.
#[test]
fn trailing_data_and_par3_inside_extract_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("tail.7z"), SOLID);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join("tail.7z"))
        .unwrap();
    file.write_all(b"some trailing bytes").unwrap();
    drop(file);
    let (out, _) = expect(&facade(dir.path(), &["x", "-y", "-oa", "tail.7z"], b""), 0);
    assert!(
        out.contains("\nWARNINGS:\nThere are data after the end of archive\n\n--\n"),
        "{out}"
    );
    assert!(out.contains("Tail Size = 19\n"), "{out}");
    assert!(
        out.contains("Archives with Warnings: 1\n\nWarnings: 1\n"),
        "{out}"
    );
    assert_tree(&dir.path().join("a"));

    // An archive rarpar protects with its PAR3 set inside it.
    let input = dir.path().join("in");
    std::fs::create_dir_all(&input).unwrap();
    for (name, data) in members() {
        match data {
            None => std::fs::create_dir_all(input.join(name)).unwrap(),
            Some(data) => {
                std::fs::create_dir_all(input.join(name).parent().unwrap()).unwrap();
                std::fs::write(input.join(name), data).unwrap();
            }
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(dir.path())
        .args([
            "par3",
            "archive",
            "--inside",
            "--base-path",
            "in",
            "guarded.7z",
        ])
        .args(["attic", "cellar", "blank.dat", "static.bin", "ledger.txt"])
        .output()
        .unwrap();
    expect(&output, 0);
    let (out, _) = expect(
        &facade(dir.path(), &["x", "-y", "-ob", "guarded.7z"], b""),
        0,
    );
    assert!(out.contains("Everything is Ok\n"), "{out}");
    assert!(out.contains("Tail Size = "), "{out}");
    assert_tree(&dir.path().join("b"));
}

/// One non-solid LZMA2 archive of `(name, data, is_link)` entries, in order.
fn write_entries(path: &Path, entries: &[(&str, &[u8], bool)]) {
    let mut out = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut out)).unwrap();
        writer.set_content_methods(lzma2());
        for &(name, data, link) in entries {
            let mut entry = ArchiveEntry::new_file(name);
            if link {
                // A Unix symlink, as p7zip records one.
                entry.has_windows_attributes = true;
                entry.windows_attributes = 0x8000 | (0o120_777 << 16);
            }
            writer.push_archive_entry(entry, Some(data)).unwrap();
        }
        writer.finish().unwrap();
    }
    std::fs::write(path, out).unwrap();
}

/// A link named `../../pivot` is created at `out/pivot`, so its target is
/// judged from there: `../../outside` escapes and is refused, and the member
/// meant to go through it cannot leave the output folder.
#[cfg(unix)]
#[test]
fn links_are_judged_from_where_they_are_created() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    write_entries(
        &work.join("pivot.7z"),
        &[
            ("../../pivot", b"../../outside", true),
            ("pivot/planted.txt", b"stray bytes", false),
        ],
    );
    let (_, err) = expect(&facade(&work, &["x", "-y", "-oout", "pivot.7z"], b""), 2);
    assert!(
        err.contains("Dangerous link path was ignored : ../../pivot : ../../outside"),
        "{err}"
    );
    assert!(std::fs::symlink_metadata(dir.path().join("outside")).is_err());
    let pivot = work.join("out/pivot");
    assert!(!std::fs::symlink_metadata(&pivot).unwrap().is_symlink());
}

/// A link target that is not UTF-8 keeps its own bytes: it is never rewritten
/// with U+FFFD into a link to some other name.
#[cfg(unix)]
#[test]
fn link_targets_keep_their_bytes() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    write_entries(
        &dir.path().join("raw.7z"),
        &[("raw.lnk", b"caf\xe9.txt", true)],
    );
    expect(&facade(dir.path(), &["x", "-y", "-oout", "raw.7z"], b""), 0);
    let target = std::fs::read_link(dir.path().join("out/raw.lnk")).unwrap();
    assert_eq!(target.as_os_str().as_bytes(), b"caf\xe9.txt");
}

/// A refused link leaves nothing at its name, as 7-Zip's does: not an empty
/// placeholder in place of the file `-y` overwrote.
#[cfg(unix)]
#[test]
fn refused_links_leave_no_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("pivot"), b"older copy").unwrap();
    write_entries(
        &dir.path().join("pivot.7z"),
        &[("pivot", b"../outside", true)],
    );
    let (_, err) = expect(
        &facade(dir.path(), &["x", "-y", "-oout", "pivot.7z"], b""),
        2,
    );
    assert!(
        err.contains("Dangerous link path was ignored : pivot : ../outside"),
        "{err}"
    );
    assert!(
        std::fs::symlink_metadata(out.join("pivot"))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    );
}

/// A folder in the output tree that is already a symbolic link is never
/// written through.
#[cfg(unix)]
#[test]
fn members_are_never_written_through_a_linked_folder() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    let victim = dir.path().join("victim");
    std::fs::create_dir_all(work.join("out")).unwrap();
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("ledger.txt"), b"keep me").unwrap();
    std::os::unix::fs::symlink(&victim, work.join("out/shelf")).unwrap();
    write_entries(
        &work.join("shelf.7z"),
        &[("shelf/ledger.txt", b"overwritten", false)],
    );
    let (_, err) = expect(&facade(&work, &["x", "-y", "-oout", "shelf.7z"], b""), 2);
    assert!(
        err.contains("Dangerous link via another link was ignored : shelf/ledger.txt"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(victim.join("ledger.txt")).unwrap(),
        b"keep me"
    );
}

/// A link member's recorded mode is never applied through the link: a target
/// that reaches outside the output folder through a link already there keeps
/// its own mode.
#[cfg(unix)]
#[test]
fn link_members_never_change_their_targets_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(work.join("out")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let victim = outside.join("ledger.txt");
    std::fs::write(&victim, b"keep me").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&outside, work.join("out/pivot")).unwrap();
    write_entries(
        &work.join("mode.7z"),
        &[("link", b"pivot/ledger.txt", true)],
    );
    let output = facade(&work, &["x", "-y", "-oout", "mode.7z"], b"");
    expect(&output, 0);
    assert!(
        std::fs::symlink_metadata(work.join("out/link"))
            .unwrap()
            .is_symlink()
    );
    let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
}

/// A symlink member whose target is longer than any path is refused as it
/// streams, not buffered whole.
#[cfg(unix)]
#[test]
fn oversized_link_targets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = vec![b'a'; 1 << 20];
    write_entries(&dir.path().join("long.7z"), &[("long.lnk", &target, true)]);
    let (_, err) = expect(
        &facade(dir.path(), &["x", "-y", "-oout", "long.7z"], b""),
        2,
    );
    assert!(
        err.contains("Cannot create symbolic link : File name too long"),
        "{err}"
    );
    assert!(
        std::fs::symlink_metadata(dir.path().join("out/long.lnk"))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    );
}

/// After `--`, a word starting with `@` is a member name, not a list file.
#[test]
fn double_dash_makes_at_words_member_names() {
    let dir = tempfile::tempdir().unwrap();
    write_entries(
        &dir.path().join("notes.7z"),
        &[
            ("@note.txt", b"literal", false),
            ("other.txt", b"skipped", false),
        ],
    );
    expect(
        &facade(
            dir.path(),
            &["x", "-y", "-oout", "notes.7z", "--", "@note.txt"],
            b"",
        ),
        0,
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/@note.txt")).unwrap(),
        b"literal"
    );
    assert!(!dir.path().join("out/other.txt").exists());
}

#[test]
fn overwrite_modes_and_prompt() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("set.7z"), SOLID);
    expect(&facade(dir.path(), &["x", "-y", "-oout", "set.7z"], b""), 0);
    std::fs::write(dir.path().join("out/ledger.txt"), b"mine").unwrap();

    expect(
        &facade(dir.path(), &["x", "-aos", "-oout", "set.7z"], b""),
        0,
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/ledger.txt")).unwrap(),
        b"mine"
    );

    // Asked: no for the empty file, then skip all.
    let (out, _) = expect(&facade(dir.path(), &["x", "-oout", "set.7z"], b"n\ns\n"), 0);
    assert_eq!(
        out.matches("Would you like to replace the existing file:")
            .count(),
        2
    );
    assert!(
        out.contains("  Path:     out/static.bin\n")
            || out.contains("  Path:     out\\static.bin\n"),
        "{out}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/ledger.txt")).unwrap(),
        b"mine"
    );

    // Quit: a break, exit 255.
    let (_, err) = expect(&facade(dir.path(), &["x", "-oout", "set.7z"], b"q\n"), 255);
    assert_eq!(err, "\n\nBreak signaled\n");

    expect(
        &facade(dir.path(), &["x", "-aot", "-oout", "set.7z"], b""),
        0,
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/ledger_1.txt")).unwrap(),
        b"mine"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/ledger.txt")).unwrap(),
        b"quartz ferry ".repeat(4000)
    );
}

#[test]
fn filters_flat_extraction_listing_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("set.7z"), SOLID);
    let (out, _) = expect(
        &facade(
            dir.path(),
            &["x", "-y", "-bb1", "-oa", "-r", "set.7z", "*.raw"],
            b"",
        ),
        0,
    );
    assert!(out.contains("- cellar/vault/tally.raw\n"), "{out}");
    assert!(dir.path().join("a/cellar/vault/tally.raw").is_file());
    assert!(!dir.path().join("a/ledger.txt").exists());

    expect(
        &facade(dir.path(), &["e", "-y", "-ob", "-x!*.bin", "set.7z"], b""),
        0,
    );
    assert!(dir.path().join("b/tally.raw").is_file());
    assert!(!dir.path().join("b/static.bin").exists());

    let (out, _) = expect(
        &facade(dir.path(), &["x", "-y", "-oc", "set.7z", "nothing"], b""),
        0,
    );
    assert!(
        out.contains("\nNo files to process\nEverything is Ok\n"),
        "{out}"
    );

    let (out, _) = expect(&facade(dir.path(), &["t", "-scrc", "set.7z"], b""), 0);
    assert!(out.contains("CRC32  for data:              "), "{out}");
    assert!(out.contains("CRC32  for data and names:    "), "{out}");

    let (out, _) = expect(&facade(dir.path(), &["l", "set.7z"], b""), 0);
    assert!(
        out.contains("   Date      Time    Attr         Size   Compressed  Name\n"),
        "{out}"
    );
    assert!(out.contains("  5 files, 3 folders\n"), "{out}");
}

/// The ignored matrix: the facade and a reference 7-Zip, side by side.
mod reference {
    use super::*;

    fn reference_bin() -> PathBuf {
        PathBuf::from(
            std::env::var_os("SEVENZ_REFERENCE_BIN")
                .expect("set SEVENZ_REFERENCE_BIN to a 7-Zip (7zz) binary"),
        )
    }

    fn run(program: &Path, facade: bool, cwd: &Path, args: &[String], stdin: &[u8]) -> Output {
        let mut command = Command::new(program);
        if facade {
            command.arg("7z");
        }
        let mut child = command
            .current_dir(cwd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// The banner is the one line the two are allowed to differ on.
    fn without_banner(out: &str) -> String {
        let mut lines: Vec<&str> = out.split_inclusive('\n').collect();
        if lines.first() == Some(&"\n") {
            if lines.get(1).is_some_and(|l| l.starts_with("7-Zip")) {
                lines.drain(1..3);
            } else if lines.get(1).is_some_and(|l| l.starts_with("rarpar ")) {
                lines.drain(1..2);
            }
        }
        lines.concat()
    }

    #[derive(PartialEq, Eq, Debug)]
    enum Node {
        Folder(u32),
        File(Vec<u8>, u32, i64),
        Link(String),
    }

    /// Every source item's modification time, in seconds since 1970.
    const SOURCE_TIME: i64 = 981_173_106;

    /// The extracted tree. A modification time other than the sources' was
    /// set by the extraction itself rather than taken from the archive
    /// (7-Zip leaves some files, such as a refused link, without metadata),
    /// so it is recorded as 0: when the clock ticks is not compared.
    fn tree(root: &Path) -> BTreeMap<String, Node> {
        let mut found = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let mode = mode_of(&meta);
                let node = if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    Node::Link(
                        target
                            .to_string_lossy()
                            .replace(&*root.to_string_lossy(), "{O}"),
                    )
                } else if meta.is_dir() {
                    stack.push(path.clone());
                    Node::Folder(mode)
                } else {
                    let mtime = filetime::FileTime::from_last_modification_time(&meta);
                    let seconds = mtime.unix_seconds();
                    let seconds = if seconds == SOURCE_TIME { seconds } else { 0 };
                    Node::File(std::fs::read(&path).unwrap(), mode, seconds)
                };
                found.insert(name, node);
            }
        }
        found
    }

    #[cfg(unix)]
    fn mode_of(meta: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }

    #[cfg(not(unix))]
    fn mode_of(meta: &std::fs::Metadata) -> u32 {
        u32::from(meta.permissions().readonly())
    }

    struct Case {
        name: String,
        args: Vec<String>,
        cwd: PathBuf,
        stdin: Vec<u8>,
        /// Compare extracted content (off where a damaged member's partial
        /// bytes depend on decoder chunking).
        content: bool,
        /// Run this first under each tool's output folder, with the reference.
        prepare: Option<Vec<String>>,
    }

    fn case(name: &str, args: &[&str]) -> Case {
        Case {
            name: name.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            cwd: PathBuf::new(),
            stdin: Vec::new(),
            content: true,
            prepare: None,
        }
    }

    /// Run one case under both tools; returns a description of each
    /// difference.
    fn compare(work: &Path, reference: &Path, case: &Case) -> Vec<String> {
        let cwd = if case.cwd.as_os_str().is_empty() {
            work.to_path_buf()
        } else {
            work.join(&case.cwd)
        };
        let mut results = Vec::new();
        for (who, program, facade) in [
            ("ref", reference.to_path_buf(), false),
            ("us", PathBuf::from(env!("CARGO_BIN_EXE_rarpar")), true),
        ] {
            let out_dir = work.join("cmp").join(&case.name).join(who);
            std::fs::create_dir_all(&out_dir).unwrap();
            let fill = |args: &[String]| -> Vec<String> {
                args.iter()
                    .map(|arg| arg.replace("{O}", &out_dir.to_string_lossy()))
                    .collect()
            };
            if let Some(prepare) = &case.prepare {
                run(reference, false, &cwd, &fill(prepare), b"");
            }
            let output = run(&program, facade, &cwd, &fill(&case.args), &case.stdin);
            let scrub = |bytes: &[u8]| text(bytes).replace(&*out_dir.to_string_lossy(), "{O}");
            results.push((
                without_banner(&scrub(&output.stdout)),
                scrub(&output.stderr),
                output.status.code(),
                tree(&out_dir),
            ));
        }
        let (reference, ours) = (&results[0], &results[1]);
        let mut differences = Vec::new();
        if reference.0 != ours.0 {
            differences.push(format!("stdout\n--ref\n{}\n--us\n{}", reference.0, ours.0));
        }
        if reference.1 != ours.1 {
            differences.push(format!("stderr\n--ref\n{}\n--us\n{}", reference.1, ours.1));
        }
        if reference.2 != ours.2 {
            differences.push(format!("exit code ref={:?} us={:?}", reference.2, ours.2));
        }
        let names = |tree: &BTreeMap<String, Node>| tree.keys().cloned().collect::<Vec<_>>();
        if names(&reference.3) != names(&ours.3) {
            differences.push(format!(
                "tree names ref={:?} us={:?}",
                names(&reference.3),
                names(&ours.3)
            ));
        } else if case.content {
            for (name, node) in &reference.3 {
                if ours.3.get(name) != Some(node) {
                    differences.push(format!("tree entry {name} differs"));
                }
            }
        }
        differences
    }

    /// The invented source tree the reference archives are made from.
    fn source(root: &Path) {
        let src = root.join("src");
        for dir in ["folder/inner", "hollow", "\u{fc}n\u{ef}/\u{f0}\u{ed}r"] {
            std::fs::create_dir_all(src.join(dir)).unwrap();
        }
        std::fs::write(src.join("nothing.dat"), b"").unwrap();
        std::fs::write(src.join("exe.bin"), bytes(154_208, 5)).unwrap();
        std::fs::write(src.join("meadow.bin"), bytes(120_000, 7)).unwrap();
        std::fs::write(src.join("script.txt"), b"lamplight harbor ".repeat(5294)).unwrap();
        std::fs::write(src.join("folder/inner/pip.txt"), b"pip\n").unwrap();
        std::fs::write(
            src.join("\u{fc}n\u{ef}/\u{f0}\u{ed}r/fj\u{f6}rd \u{2603}.txt"),
            "snow globe!\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(src.join("exe.bin"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            let links = root.join("links/inner");
            std::fs::create_dir_all(&links).unwrap();
            std::fs::write(links.join("target.txt"), b"lantern\n").unwrap();
            std::fs::set_permissions(
                links.join("target.txt"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            std::os::unix::fs::symlink("target.txt", links.join("rel.lnk")).unwrap();
            std::os::unix::fs::symlink("../../outside.txt", links.join("esc.lnk")).unwrap();
            std::os::unix::fs::symlink("/absent/hostsx", links.join("abs.lnk")).unwrap();
            std::fs::write(root.join("links/\u{1d11e} clef.txt"), b"clef\n").unwrap();
        }
        // Pin every time, links' own included, deepest first.
        let stamp = filetime::FileTime::from_unix_time(SOURCE_TIME, 0);
        let mut paths = Vec::new();
        let mut stack = vec![root.join("src"), root.join("links")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                }
                paths.push(entry.path());
            }
        }
        paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in paths {
            filetime::set_symlink_file_times(&path, stamp, stamp).unwrap();
        }
    }

    fn make(
        reference: &Path,
        root: &Path,
        cwd: &str,
        archive: &str,
        switches: &[&str],
        names: &[&str],
    ) {
        let mut args: Vec<String> = vec!["a".into(), "-bso0".into(), "-bsp0".into()];
        args.extend(switches.iter().map(|s| (*s).to_owned()));
        args.push(root.join(archive).to_string_lossy().into_owned());
        args.extend(names.iter().map(|s| (*s).to_owned()));
        let output = run(reference, false, &root.join(cwd), &args, b"");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{archive}: {}",
            text(&output.stderr)
        );
    }

    fn damage(path: &Path, from: usize, len: usize) {
        let mut data = std::fs::read(path).unwrap();
        for byte in &mut data[from..from + len] {
            *byte ^= 0x5A;
        }
        std::fs::write(path, data).unwrap();
    }

    #[test]
    #[ignore = "needs a reference 7-Zip in SEVENZ_REFERENCE_BIN"]
    fn matches_reference_seven_zip() {
        let reference = reference_bin();
        let work = tempfile::tempdir().unwrap();
        let root = work.path();
        source(root);
        let all = [
            "folder",
            "hollow",
            "\u{fc}n\u{ef}",
            "nothing.dat",
            "exe.bin",
            "meadow.bin",
            "script.txt",
        ];
        let archives: &[(&str, &[&str])] = &[
            ("lzma2.7z", &["-m0=LZMA2"]),
            ("lzma.7z", &["-m0=LZMA"]),
            ("ppmd.7z", &["-m0=PPMd"]),
            ("bzip2.7z", &["-m0=BZip2"]),
            ("deflate.7z", &["-m0=Deflate"]),
            ("copy.7z", &["-m0=Copy"]),
            ("bcj.7z", &["-mf=BCJ"]),
            ("bcj2.7z", &["-mf=BCJ2"]),
            ("arm64.7z", &["-mf=ARM64"]),
            ("nonsolid.7z", &["-ms=off"]),
            ("mt.7z", &["-mmt=4", "-m0=LZMA2:d=64k:c=32k"]),
            ("enc.7z", &["-pHUNTER"]),
            ("hdrenc.7z", &["-pHUNTER", "-mhe=on"]),
            ("mv.7z", &["-v40k"]),
            ("mvenc.7z", &["-v40k", "-pHUNTER", "-mhe=on"]),
            ("crc.7z", &["-m0=Copy", "-ms=off"]),
            ("data.7z", &["-m0=LZMA"]),
            ("trail.7z", &[]),
        ];
        for (archive, switches) in archives {
            make(&reference, root, "src", archive, switches, &all);
        }
        #[cfg(unix)]
        make(
            &reference,
            root,
            "links",
            "links.7z",
            &["-snl"],
            &["inner", "\u{1d11e} clef.txt"],
        );
        // Damage: a stored member's bytes, and LZMA data mid-stream.
        damage(&root.join("crc.7z"), 32 + 154_208 + 100, 4);
        // Deep enough that both keep part of the damaged member: how many
        // bytes before a fault survive depends on each decoder's buffering.
        damage(&root.join("data.7z"), 40_000, 400);
        let mut trail = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join("trail.7z"))
            .unwrap();
        trail.write_all(b"PAR3\0PKT and more trailing").unwrap();
        drop(trail);
        std::fs::write(root.join("junk.7z"), bytes(5000, 11)).unwrap();
        let whole = std::fs::read(root.join("lzma2.7z")).unwrap();
        std::fs::write(root.join("short.7z"), &whole[..whole.len() / 2]).unwrap();
        std::fs::create_dir_all(root.join("nz")).unwrap();
        for volume in ["mv.7z.001", "mv.7z.002", "mv.7z.003", "mv.7z.004"] {
            if root.join(volume).exists() {
                std::fs::copy(root.join(volume), root.join("nz").join(volume)).unwrap();
            }
        }
        std::fs::copy(root.join("lzma2.7z"), root.join("nz/lzma2.7z")).unwrap();
        std::fs::write(root.join("names.lst"), "script.txt\nfolder/inner\n").unwrap();

        let mut cases = Vec::new();
        for (archive, _) in archives {
            cases.push(case(
                &format!("x {archive}"),
                &["x", "-y", "-o{O}", archive],
            ));
            cases.push(case(&format!("l {archive}"), &["l", archive]));
            cases.push(case(
                &format!("slt {archive}"),
                &["l", "-slt", "-pHUNTER", archive],
            ));
        }
        for archive in ["mv.7z.001", "mvenc.7z.001"] {
            cases.push(case(
                &format!("x {archive}"),
                &["x", "-y", "-pHUNTER", "-o{O}", archive],
            ));
            cases.push(case(&format!("l {archive}"), &["l", "-pHUNTER", archive]));
        }
        for case_ in &mut cases {
            if case_.name.starts_with("x data") || case_.name.starts_with("x crc") {
                case_.content = false;
            }
        }
        let mut more = vec![
            case("x enc right", &["x", "-y", "-pHUNTER", "-o{O}", "enc.7z"]),
            case(
                "x hdrenc right",
                &["x", "-y", "-pHUNTER", "-o{O}", "hdrenc.7z"],
            ),
            case("x enc wrong", &["x", "-y", "-pWRONG", "-o{O}", "enc.7z"]),
            case("x enc empty", &["x", "-y", "-p", "-o{O}", "enc.7z"]),
            case("x enc dash", &["x", "-y", "-p-", "-o{O}", "enc.7z"]),
            case(
                "x hdrenc wrong",
                &["x", "-y", "-pWRONG", "-o{O}", "hdrenc.7z"],
            ),
            case("t enc wrong", &["t", "-pWRONG", "enc.7z"]),
            case("l hdrenc wrong", &["l", "-pWRONG", "hdrenc.7z"]),
            case("l hdrenc none", &["l", "hdrenc.7z"]),
            case("x enc none", &["x", "-y", "-o{O}", "enc.7z"]),
            case("e flat", &["e", "-y", "-o{O}", "lzma2.7z"]),
            case("x bb1", &["x", "-y", "-bb1", "-o{O}", "lzma2.7z"]),
            case("t bb1", &["t", "-bb1", "nonsolid.7z"]),
            case("x scrc", &["x", "-y", "-scrc", "-o{O}", "copy.7z"]),
            case("t scrc", &["t", "-scrc", "nonsolid.7z"]),
            case("x filter", &["x", "-y", "-o{O}", "lzma2.7z", "folder"]),
            case(
                "x filter r",
                &["x", "-y", "-r", "-o{O}", "lzma2.7z", "*.txt"],
            ),
            case("x exclude", &["x", "-y", "-o{O}", "-x!*.bin", "lzma2.7z"]),
            case("x xr", &["x", "-y", "-o{O}", "-xr!*.txt", "lzma2.7z"]),
            case("x ir", &["x", "-y", "-o{O}", "-ir!pip*", "lzma2.7z"]),
            case("x no match", &["x", "-y", "-o{O}", "lzma2.7z", "zzz"]),
            case(
                "x list file",
                &["x", "-y", "-o{O}", "lzma2.7z", "@names.lst"],
            ),
            case(
                "x case",
                &["x", "-y", "-ssc-", "-o{O}", "lzma2.7z", "SCRIPT.TXT"],
            ),
            case("x junk", &["x", "-y", "-o{O}", "junk.7z"]),
            case("x short", &["x", "-y", "-o{O}", "short.7z"]),
            case("x absent", &["x", "-y", "-o{O}", "absent.7z"]),
            case(
                "x two",
                &["x", "-y", "-o{O}", "-an", "-ai!copy.7z", "-ai!ppmd.7z"],
            ),
            case("x star out", &["x", "-y", "-o{O}/*", "lzma2.7z"]),
            case("x so", &["e", "-p", "-y", "-so", "lzma2.7z", "script.txt"]),
            case("x bso0", &["x", "-y", "-bso0", "-o{O}", "lzma2.7z"]),
            case("x ba", &["x", "-y", "-ba", "-o{O}", "lzma2.7z"]),
            case("l ba", &["l", "-ba", "lzma2.7z"]),
            case("x tzip", &["x", "-y", "-tzip", "-o{O}", "lzma2.7z"]),
            case(
                "sab list",
                &["l", "-p", "-y", "-slt", "-sccUTF-8", "lzma2.7z"],
            ),
            case(
                "sab x",
                &["x", "-y", "-aoa", "-ssc", "-p", "-o{O}", "lzma2.7z"],
            ),
            case(
                "sab x aou",
                &["x", "-y", "-aou", "-ssc-", "-pHUNTER", "-o{O}", "enc.7z"],
            ),
            case(
                "sab x wrong",
                &["x", "-y", "-aoa", "-ssc", "-pWRONG", "-o{O}", "enc.7z"],
            ),
            case("badsw", &["x", "-zz", "lzma2.7z"]),
            case("bb bad", &["x", "-bbx", "lzma2.7z"]),
            case("noname", &["x"]),
        ];
        #[cfg(unix)]
        more.extend([
            case("x links", &["x", "-y", "-o{O}", "links.7z"]),
            case("e links", &["e", "-y", "-o{O}", "links.7z"]),
            case("slt links", &["l", "-slt", "links.7z"]),
        ]);
        for pattern in ["*.7z", "*.7z.001", "*"] {
            let mut nzb = case(
                &format!("nzbget {pattern}"),
                &["x", "-y", "-p-", "-o{O}", pattern],
            );
            nzb.cwd = PathBuf::from("nz");
            more.push(nzb);
        }
        for (answers, label) in [
            ("y\n", "y"),
            ("n\n", "n"),
            ("a\n", "a"),
            ("s\n", "s"),
            ("u\n", "u"),
            ("q\n", "q"),
            ("", "eof"),
            ("zz\nY\n", "invalid"),
        ] {
            let mut ask = case(&format!("ask {label}"), &["x", "-o{O}", "lzma2.7z"]);
            ask.stdin = answers.as_bytes().to_vec();
            ask.prepare = Some(vec![
                "x".into(),
                "-y".into(),
                "-o{O}".into(),
                "lzma2.7z".into(),
            ]);
            more.push(ask);
        }
        for mode in ["-aoa", "-aos", "-aou", "-aot"] {
            let mut again = case(&format!("again {mode}"), &["x", mode, "-o{O}", "lzma2.7z"]);
            again.prepare = Some(vec![
                "x".into(),
                "-y".into(),
                "-o{O}".into(),
                "lzma2.7z".into(),
            ]);
            more.push(again);
        }
        let mut stdin_password = case("x hdrenc stdin", &["x", "-y", "-o{O}", "hdrenc.7z"]);
        stdin_password.stdin = b"HUNTER\n".to_vec();
        more.push(stdin_password);
        let mut stdin_block = case("x enc stdin", &["x", "-y", "-o{O}", "enc.7z"]);
        stdin_block.stdin = b"HUNTER\n".to_vec();
        more.push(stdin_block);
        cases.extend(more);

        let mut failures = Vec::new();
        for case_ in &cases {
            let differences = compare(root, &reference, case_);
            if !differences.is_empty() {
                failures.push(format!("{}:\n{}", case_.name, differences.join("\n")));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} cases differ:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }
}

/// A folder named as the archive is walked without following links: a
/// linked folder that points back at itself ends the walk instead of
/// recursing, and a link out of the folder finds nothing outside it.
#[cfg(unix)]
#[test]
fn folder_walk_does_not_follow_links() {
    let dir = tempfile::tempdir().unwrap();
    let shelf = dir.path().join("shelf");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&shelf).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    write_archive(&shelf.join("inner.7z"), SOLID);
    write_archive(&outside.join("stray.7z"), SOLID);
    std::os::unix::fs::symlink(".", shelf.join("loop")).unwrap();
    std::os::unix::fs::symlink(&outside, shelf.join("away")).unwrap();
    std::os::unix::fs::symlink(outside.join("stray.7z"), shelf.join("stray.7z")).unwrap();
    let (out, _) = expect(&facade(dir.path(), &["l", "shelf"], b""), 0);
    assert!(out.contains("1 folder, 1 file, "), "{out}");
    assert!(out.contains("Listing archive: shelf/inner.7z\n"), "{out}");
    assert!(!out.contains("stray.7z"), "{out}");
    assert!(!out.contains("loop"), "{out}");
}

/// `-ax` keeps an archive out of the command entirely: under `-sdel` the
/// excluded archive is neither extracted nor deleted.
#[test]
fn excluded_archives_are_never_processed_or_deleted() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("drop.7z"), SOLID);
    write_archive(&dir.path().join("keep.7z"), SOLID);
    let (out, _) = expect(
        &facade(
            dir.path(),
            &["x", "*.7z", "-ax!keep.7z", "-sdel", "-y", "-oout"],
            b"",
        ),
        0,
    );
    assert!(out.contains("1 file, "), "{out}");
    assert!(out.contains("Extracting archive: drop.7z\n"), "{out}");
    assert!(!out.contains("keep.7z"), "{out}");
    assert!(!dir.path().join("drop.7z").exists());
    assert!(dir.path().join("keep.7z").is_file());
    assert_tree(&dir.path().join("out"));
}

/// An archive named both positionally and by an `-ai` rule is one archive:
/// counted once, extracted once, and under `-sdel` deleted once, exit 0.
#[test]
fn overlapping_archive_selectors_process_an_archive_once() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("crate.7z"), SOLID);
    let (out, _) = expect(
        &facade(dir.path(), &["l", "crate.7z", "-ai!crate.7z"], b""),
        0,
    );
    assert!(out.contains("1 file, "), "{out}");
    assert_eq!(
        out.matches("Listing archive: crate.7z\n").count(),
        1,
        "{out}"
    );
    let (out, _) = expect(
        &facade(
            dir.path(),
            &[
                "x",
                "-sdel",
                "crate.7z",
                "-ai!crate.7z",
                "-ai!*.7z",
                "-y",
                "-oout",
            ],
            b"",
        ),
        0,
    );
    assert!(out.contains("1 file, "), "{out}");
    assert_eq!(
        out.matches("Extracting archive: crate.7z\n").count(),
        1,
        "{out}"
    );
    assert!(out.contains("Everything is Ok"), "{out}");
    assert!(!dir.path().join("crate.7z").exists());
    assert_tree(&dir.path().join("out"));
}

/// `-air` matches its name in every folder below, as `-ai` does in one.
#[test]
fn recursive_archive_includes_descend() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("shelf/deep")).unwrap();
    write_archive(&dir.path().join("top.7z"), SOLID);
    write_archive(&dir.path().join("shelf/deep/low.7z"), SOLID);
    let (out, _) = expect(&facade(dir.path(), &["l", "-an", "-ai!*.7z"], b""), 0);
    assert!(out.contains("Listing archive: top.7z\n"), "{out}");
    assert!(!out.contains("low.7z"), "{out}");
    let (out, _) = expect(&facade(dir.path(), &["l", "-an", "-air!*.7z"], b""), 0);
    assert!(out.contains("2 folders, 2 files, "), "{out}");
    assert!(out.contains("Listing archive: top.7z\n"), "{out}");
    assert!(
        out.contains(&format!(
            "Listing archive: shelf{0}deep{0}low.7z\n",
            std::path::MAIN_SEPARATOR
        )),
        "{out}"
    );
    // A recursive exclusion reaches as deep.
    let (out, _) = expect(
        &facade(dir.path(), &["l", "-an", "-air!*.7z", "-axr!low.7z"], b""),
        0,
    );
    assert!(out.contains("Listing archive: top.7z\n"), "{out}");
    assert!(!out.contains("low.7z"), "{out}");
}

/// An argument that is not valid Unicode is a command-line error: it is never
/// read with U+FFFD in place of its bytes, which would name the archive
/// beside it, and `-sdel` deletes nothing.
#[cfg(unix)]
#[test]
fn non_unicode_arguments_are_refused() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let lookalike = dir.path().join("crate\u{fffd}.7z");
    write_archive(&lookalike, SOLID);
    let output = Command::new(env!("CARGO_BIN_EXE_rarpar"))
        .current_dir(dir.path())
        .args(["7z", "x", "-sdel", "-y", "-oout"])
        .arg(OsStr::from_bytes(b"crate\xff.7z"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let (_, err) = expect(&output, 7);
    assert!(
        err.contains("Command Line Error:\nUnsupported argument that is not valid Unicode:\n"),
        "{err}"
    );
    assert!(lookalike.is_file());
    assert!(!dir.path().join("out").exists());
}

/// A folder under the named one that cannot be read fails the scan with
/// 7-Zip's scan error and exit 2, rather than counting as empty: the archive
/// beside it is not processed, so `-sdel` deletes nothing.
#[cfg(unix)]
#[test]
fn an_unreadable_folder_fails_the_archive_scan() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("inbox/locked");
    std::fs::create_dir_all(&locked).unwrap();
    write_archive(&dir.path().join("inbox/open.7z"), SOLID);
    write_archive(&locked.join("hidden.7z"), SOLID);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // A privileged user reads the folder anyway: nothing to test there.
    let readable = std::fs::read_dir(&locked).is_ok();
    let output = facade(dir.path(), &["x", "-sdel", "-y", "-oout", "inbox"], b"");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        return;
    }
    let (out, err) = expect(&output, 2);
    assert!(
        err.contains("\nERROR: errno=13 : Permission denied\ninbox/locked/\n\n"),
        "{err}"
    );
    assert!(
        err.contains("System ERROR:\nerrno=13 : Permission denied\n"),
        "{err}"
    );
    assert!(!out.contains("Extracting archive"), "{out}");
    assert!(dir.path().join("inbox/open.7z").is_file());
}

/// With wildcard matching off (`-aiw-`, or `-spd` for the archive name), `*`
/// is a character of the name: only the archive literally called `set*.7z`
/// is opened, and `-sdel` never reaches the archives the wildcard would match.
#[cfg(unix)]
#[test]
fn literal_archive_names_are_not_expanded() {
    let dir = tempfile::tempdir().unwrap();
    let literal = dir.path().join("set*.7z");
    let other = dir.path().join("setalpha.7z");
    for (args, out) in [
        (&["x", "-an", "-aiw-!set*.7z"][..], "one"),
        (&["x", "-spd", "set*.7z"][..], "two"),
    ] {
        write_archive(&literal, SOLID);
        write_archive(&other, SOLID);
        let out_switch = format!("-o{out}");
        let mut args = args.to_vec();
        args.extend(["-sdel", "-y", out_switch.as_str()]);
        let (stdout, _) = expect(&facade(dir.path(), &args, b""), 0);
        assert!(stdout.contains("1 file, "), "{stdout}");
        assert!(stdout.contains("Extracting archive: set*.7z\n"), "{stdout}");
        assert!(!stdout.contains("setalpha.7z"), "{stdout}");
        assert!(!literal.exists(), "{stdout}");
        assert!(other.is_file());
        assert_tree(&dir.path().join(out));
    }
}

/// `-sdel` deletes an archive only when something was extracted from it: a
/// filter that matches nothing leaves the archive in place.
#[test]
fn sdel_keeps_an_archive_nothing_was_extracted_from() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("crate.7z");
    write_archive(&archive, SOLID);
    let output = facade(
        dir.path(),
        &["x", "-sdel", "-y", "-oout", "crate.7z", "no-such-member"],
        b"",
    );
    let (stdout, _) = expect(&output, 0);
    assert!(stdout.contains("No files to process"), "{stdout}");
    assert!(archive.is_file());
    let output = facade(dir.path(), &["x", "-sdel", "-y", "-oout", "crate.7z"], b"");
    expect(&output, 0);
    assert!(!archive.exists());
    assert_tree(&dir.path().join("out"));
}

/// `-aos -sdel` with every destination already present writes nothing, so
/// the archive stays; once one member is written, it goes.
#[test]
fn sdel_keeps_an_archive_whose_every_member_was_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("hamper.7z");
    write_entries(
        &archive,
        &[
            ("rind.txt", b"from the archive", false),
            ("pith.txt", b"also archived", false),
        ],
    );
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("rind.txt"), b"already here").unwrap();
    std::fs::write(out.join("pith.txt"), b"already here too").unwrap();
    let output = facade(
        dir.path(),
        &["x", "-aos", "-sdel", "-oout", "hamper.7z"],
        b"",
    );
    expect(&output, 0);
    assert!(archive.is_file());
    assert_eq!(
        std::fs::read(out.join("rind.txt")).unwrap(),
        b"already here"
    );
    assert_eq!(
        std::fs::read(out.join("pith.txt")).unwrap(),
        b"already here too"
    );

    std::fs::remove_file(out.join("pith.txt")).unwrap();
    let output = facade(
        dir.path(),
        &["x", "-aos", "-sdel", "-oout", "hamper.7z"],
        b"",
    );
    expect(&output, 0);
    assert!(!archive.exists());
    assert_eq!(
        std::fs::read(out.join("rind.txt")).unwrap(),
        b"already here"
    );
    assert_eq!(
        std::fs::read(out.join("pith.txt")).unwrap(),
        b"also archived"
    );
}

/// Splits `whole` into `<name>.001`, `<name>.002`, ... under `dir`.
fn write_volumes(dir: &Path, name: &str, whole: &[u8]) -> Vec<PathBuf> {
    whole
        .chunks(40_000)
        .enumerate()
        .map(|(index, piece)| {
            let path = dir.join(format!("{name}.{:03}", index + 1));
            std::fs::write(&path, piece).unwrap();
            path
        })
        .collect()
}

/// `-sdel` deletes every volume of a split set it extracted.
#[test]
fn sdel_deletes_every_volume_of_a_split_set() {
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("whole.7z"), SOLID);
    let whole = std::fs::read(dir.path().join("whole.7z")).unwrap();
    let inbox = dir.path().join("inbox");
    std::fs::create_dir(&inbox).unwrap();
    let volumes = write_volumes(&inbox, "crate.7z", &whole);
    assert!(volumes.len() > 1);
    let out_arg = format!("-o{}", dir.path().join("out").display());
    let (out, _) = expect(
        &facade(&inbox, &["x", "-sdel", "-y", &out_arg, "crate.7z.001"], b""),
        0,
    );
    assert!(out.contains("Everything is Ok"), "{out}");
    for volume in &volumes {
        assert!(!volume.exists(), "{} survived", volume.display());
    }
    assert_tree(&dir.path().join("out"));
}

/// A volume `-sdel` cannot delete is an error of its archive: it is named
/// with the system's reason, the archive is not counted OK, and the command
/// exits 2 rather than 0.
#[cfg(unix)]
#[test]
fn sdel_reports_volumes_it_cannot_delete() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    write_archive(&dir.path().join("whole.7z"), SOLID);
    let whole = std::fs::read(dir.path().join("whole.7z")).unwrap();
    let inbox = dir.path().join("inbox");
    std::fs::create_dir(&inbox).unwrap();
    let volumes = write_volumes(&inbox, "crate.7z", &whole);
    // A folder nobody may write: its entries cannot be removed.
    std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o555)).unwrap();
    let probe = inbox.join("probe");
    if std::fs::write(&probe, b"").is_ok() {
        // Permissions do not bind this process (root): nothing to test.
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let out_arg = format!("-o{}", dir.path().join("out").display());
    let output = facade(&inbox, &["x", "-sdel", "-y", &out_arg, "crate.7z.001"], b"");
    std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (out, err) = expect(&output, 2);
    for volume in &volumes {
        assert!(volume.is_file(), "{} went", volume.display());
        assert!(
            err.contains(&format!(
                "ERROR: Cannot delete file : errno={} : ",
                libc::EACCES
            )) && err.contains(&format!(
                " : {}\n",
                volume.file_name().unwrap().to_string_lossy()
            )),
            "{err}"
        );
    }
    assert!(out.contains("Archives with Errors: 1\n"), "{out}");
    assert!(
        out.contains(&format!("Sub items Errors: {}\n", volumes.len())),
        "{out}"
    );
    assert_tree(&dir.path().join("out"));
}
