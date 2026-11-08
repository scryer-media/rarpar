//! Inputs from published PAR2 advisories, built by hand so one field lies at
//! a time. Each set is written to disk and run through the real scanner and
//! repairer, and every case first proves the honest path works: the files
//! repair, land where the translated name says, and hold the right bytes.
//!
//! - CVE-2021-29488 (SABnzbd): a PAR2 filename steered a rename outside the
//!   download folder.
//! - GHSA-j5pc-g362-c5xp (par2cmdline-turbo): repair created its output
//!   through a dangling symbolic link and wrote outside the repair tree.

use std::fs;
use std::path::{Component, Path, PathBuf};

use par2_rs::checksum::{SliceChecksumState, md5};
use par2_rs::packet::header;
use par2_rs::{
    Par2FileSet, Par2RepairStatus, Par2Repairer, Par2RepairerOptions, gf_pow,
    input_slice_constants, mul_acc_region, scan_for_renames, translate_par2_name_to_relative,
};
use tempfile::tempdir;

const SLICE: usize = 64;

fn packet(kind: &[u8; 16], body: &[u8], set_id: [u8; 16]) -> Vec<u8> {
    assert!(
        body.len().is_multiple_of(4),
        "packet bodies are four-byte aligned"
    );
    let hashed = [&set_id[..], kind, body].concat();
    let mut out = Vec::with_capacity(header::HEADER_SIZE + body.len());
    out.extend_from_slice(header::MAGIC);
    out.extend_from_slice(&((header::HEADER_SIZE + body.len()) as u64).to_le_bytes());
    out.extend_from_slice(&md5(&hashed));
    out.extend_from_slice(&set_id);
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    out
}

fn pad4(mut body: Vec<u8>) -> Vec<u8> {
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    body
}

fn file_id(name: &[u8], data: &[u8]) -> [u8; 16] {
    let hash_16k = md5(&data[..data.len().min(16_384)]);
    md5(&[&hash_16k[..], &(data.len() as u64).to_le_bytes(), name].concat())
}

fn noise(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// One described file: the name bytes its File Description carries, an
/// optional Unicode Filename spelling, and its contents.
struct Source {
    name: String,
    unicode_name: Option<String>,
    data: Vec<u8>,
}

impl Source {
    fn new(name: impl Into<String>, seed: u32) -> Self {
        Self {
            name: name.into(),
            unicode_name: None,
            data: noise(150, seed),
        }
    }

    fn id(&self) -> [u8; 16] {
        file_id(self.name.as_bytes(), &self.data)
    }

    /// The name the set gives the file once translated to a local path.
    fn local_name(&self) -> String {
        translate_par2_name_to_relative(self.unicode_name.as_deref().unwrap_or(&self.name)).unwrap()
    }
}

/// A complete set: Main, File Description, IFSC and Unicode Filename packets,
/// and as many recovery slices as there are input slices, so any loss repairs.
fn par2_stream(sources: &[Source]) -> Vec<u8> {
    let mut sorted: Vec<&Source> = sources.iter().collect();
    sorted.sort_by_key(|source| source.id());

    let mut main = Vec::new();
    main.extend_from_slice(&(SLICE as u64).to_le_bytes());
    main.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for source in &sorted {
        main.extend_from_slice(&source.id());
    }
    let set_id = md5(&main);
    let mut stream = packet(header::TYPE_MAIN, &main, set_id);

    let mut slices = Vec::new();
    for source in &sorted {
        let mut description = Vec::new();
        description.extend_from_slice(&source.id());
        description.extend_from_slice(&md5(&source.data));
        description.extend_from_slice(&md5(&source.data[..source.data.len().min(16_384)]));
        description.extend_from_slice(&(source.data.len() as u64).to_le_bytes());
        description.extend_from_slice(source.name.as_bytes());
        stream.extend(packet(header::TYPE_FILE_DESC, &pad4(description), set_id));

        let mut ifsc = source.id().to_vec();
        for chunk in source.data.chunks(SLICE) {
            let mut state = SliceChecksumState::new();
            state.update(chunk);
            let (crc, hash) = state.finalize(Some(SLICE as u64));
            ifsc.extend_from_slice(&hash);
            ifsc.extend_from_slice(&crc.to_le_bytes());
            let mut slice = chunk.to_vec();
            slice.resize(SLICE, 0);
            slices.push(slice);
        }
        stream.extend(packet(header::TYPE_IFSC, &ifsc, set_id));

        if let Some(name) = &source.unicode_name {
            let mut body = source.id().to_vec();
            for unit in name.encode_utf16() {
                body.extend_from_slice(&unit.to_le_bytes());
            }
            stream.extend(packet(header::TYPE_UNICODE_FILENAME, &pad4(body), set_id));
        }
    }

    let constants = input_slice_constants(slices.len());
    for exponent in 0..slices.len() as u32 {
        let mut recovery = vec![0u8; SLICE];
        for (slice, &constant) in slices.iter().zip(&constants) {
            mul_acc_region(gf_pow(constant, exponent), slice, &mut recovery);
        }
        let body = [&exponent.to_le_bytes()[..], &recovery].concat();
        stream.extend(packet(header::TYPE_RECOVERY, &body, set_id));
    }
    stream
}

fn repair(base: &Path, par2: &Path) -> par2_rs::Result<par2_rs::Par2RepairOutcome> {
    let options = Par2RepairerOptions::new(base.to_path_buf(), vec![par2.to_path_buf()]);
    Par2Repairer::new(options).verify_or_repair()
}

/// Every file under `dir`, skipping `skip` and anything below it.
fn files_under(dir: &Path, skip: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path == skip {
                continue;
            }
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// A job directory inside a scratch root, with a sibling `outside` directory
/// that names an absolute escape target.
struct Layout {
    _root: tempfile::TempDir,
    root: PathBuf,
    base: PathBuf,
    outside: PathBuf,
}

impl Layout {
    fn new() -> Self {
        let root = tempdir().unwrap();
        let path = root.path().to_path_buf();
        let base = path.join("job");
        let outside = path.join("outside");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&outside).unwrap();
        Self {
            _root: root,
            root: path,
            base,
            outside,
        }
    }

    fn write_set(&self, sources: &[Source]) -> PathBuf {
        let par2 = self.base.join("set.par2");
        fs::write(&par2, par2_stream(sources)).unwrap();
        par2
    }

    fn assert_nothing_escaped(&self) {
        let escaped = files_under(&self.root, &self.base);
        assert!(
            escaped.is_empty(),
            "files written outside the job: {escaped:?}"
        );
    }
}

fn hostile_names(outside: &Path) -> Vec<Source> {
    let mut unicode = Source::new("unicode-carrier.bin", 7);
    unicode.unicode_name = Some("../../escaped-unicode.bin".into());
    vec![
        Source::new("../escaped-parent.bin", 1),
        Source::new("nested/../../escaped-nested.bin", 2),
        Source::new("..\\escaped-backslash.bin", 3),
        Source::new("./a/./../../../escaped-deep.bin", 4),
        Source::new(format!("{}/escaped-absolute.bin", outside.display()), 5),
        Source::new("plain.bin", 6),
        unicode,
    ]
}

fn assert_local(source: &Source, base: &Path) -> PathBuf {
    let local = source.local_name();
    assert!(
        Path::new(&local)
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir)),
        "{} translated to a non-local path {local}",
        source.name
    );
    base.join(local)
}

#[test]
fn hostile_names_reconstruct_inside_the_job() {
    // CVE-2021-29488 class: parent, absolute, backslash and Unicode Filename
    // spellings that climb out. Every file is missing, so each is rebuilt
    // from recovery slices and installed under its translated name.
    let layout = Layout::new();
    let sources = hostile_names(&layout.outside);
    let par2 = layout.write_set(&sources);

    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    for source in &sources {
        let target = assert_local(source, &layout.base);
        assert_eq!(fs::read(&target).unwrap(), source.data, "{}", source.name);
    }
    layout.assert_nothing_escaped();
}

#[test]
fn hostile_names_rename_inside_the_job() {
    // CVE-2021-29488 itself: the files are present under obfuscated names
    // and the set renames them. The renames must land inside the job.
    let layout = Layout::new();
    let sources = hostile_names(&layout.outside);
    let par2 = layout.write_set(&sources);
    for (index, source) in sources.iter().enumerate() {
        fs::write(
            layout.base.join(format!("obfuscated-{index:02}")),
            &source.data,
        )
        .unwrap();
    }

    let set = Par2FileSet::from_files(&[&fs::read(&par2).unwrap()]).unwrap();
    let suggestions = scan_for_renames(&layout.base, &set).unwrap();
    assert_eq!(suggestions.len(), sources.len());
    for suggestion in &suggestions {
        let source = sources
            .iter()
            .find(|source| source.id() == *suggestion.file_id.as_bytes())
            .unwrap();
        assert_eq!(suggestion.correct_name, source.local_name());
        assert_local(source, &layout.base);
    }

    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    for source in &sources {
        let target = assert_local(source, &layout.base);
        assert_eq!(fs::read(&target).unwrap(), source.data, "{}", source.name);
    }
    layout.assert_nothing_escaped();
}

#[cfg(unix)]
#[test]
fn repair_refuses_a_dangling_symlink_target() {
    // GHSA-j5pc-g362-c5xp: the target name is a dangling link that points
    // outside the job. Repair must not create the link's target.
    let layout = Layout::new();
    let source = Source::new(".config/autostart/poc.desktop", 11);
    let par2 = layout.write_set(std::slice::from_ref(&source));
    let target = layout.base.join(".config/autostart/poc.desktop");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let escape = layout.outside.join("escaped-by-repair");
    std::os::unix::fs::symlink(&escape, &target).unwrap();

    let refused = repair(&layout.base, &par2).map(|outcome| outcome.status);
    assert!(
        !matches!(refused, Ok(Par2RepairStatus::Repaired)),
        "repair through a dangling link reported {refused:?}"
    );
    assert!(!escape.exists(), "repair wrote through the dangling link");
    assert!(
        fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    layout.assert_nothing_escaped();

    // The same set repairs once the link is gone, so the refusal above was
    // the link and not the set.
    fs::remove_file(&target).unwrap();
    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    assert_eq!(fs::read(&target).unwrap(), source.data);
}

#[cfg(unix)]
#[test]
fn repair_replaces_a_symlink_target_without_writing_through_it() {
    // The live-link twin of the advisory: the target links to a file outside
    // the job. The repaired file replaces the link; the outside file keeps
    // its bytes.
    let layout = Layout::new();
    let source = Source::new("linked.bin", 12);
    let par2 = layout.write_set(std::slice::from_ref(&source));
    let outside_file = layout.outside.join("victim.bin");
    fs::write(&outside_file, b"outside bytes").unwrap();
    let target = layout.base.join("linked.bin");
    std::os::unix::fs::symlink(&outside_file, &target).unwrap();

    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside bytes");
    assert!(fs::symlink_metadata(&target).unwrap().file_type().is_file());
    assert_eq!(fs::read(&target).unwrap(), source.data);
}

#[cfg(unix)]
#[test]
fn repair_refuses_a_symlinked_parent_directory() {
    // A directory component of the target name links outside the job.
    let layout = Layout::new();
    let source = Source::new("nested/file.bin", 13);
    let par2 = layout.write_set(std::slice::from_ref(&source));
    std::os::unix::fs::symlink(&layout.outside, layout.base.join("nested")).unwrap();

    let refused = repair(&layout.base, &par2).map(|outcome| outcome.status);
    assert!(
        !matches!(refused, Ok(Par2RepairStatus::Repaired)),
        "repair through a linked parent reported {refused:?}"
    );
    assert_eq!(fs::read_dir(&layout.outside).unwrap().count(), 0);

    fs::remove_file(layout.base.join("nested")).unwrap();
    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    assert_eq!(
        fs::read(layout.base.join("nested/file.bin")).unwrap(),
        source.data
    );
}

/// A header whose length field lies, followed by `tail` bytes of body.
fn lying_header(length: u64, tail: usize) -> Vec<u8> {
    let mut out = header::MAGIC.to_vec();
    out.extend_from_slice(&length.to_le_bytes());
    out.resize(header::HEADER_SIZE + tail, 0x5a);
    out
}

#[test]
fn hostile_packets_before_a_valid_set_are_skipped() {
    // par2cmdline's packet checks: lengths below the header, unaligned,
    // past the end and at u64::MAX; a Main with a zero or unaligned slice;
    // file-ID, IFSC and name fields past their caps; a NUL-only name; and
    // a Unicode Filename of half a code unit. Each carries a valid packet
    // MD5 where it has a body, so only the field lies.
    let layout = Layout::new();
    let sources = [Source::new("kept.bin", 21), Source::new("lost.bin", 22)];
    let valid = par2_stream(&sources);
    let set_id: [u8; 16] = valid[32..48].try_into().unwrap();
    let main_body = |slice: u64, count: u32, ids: usize| {
        let mut body = slice.to_le_bytes().to_vec();
        body.extend_from_slice(&count.to_le_bytes());
        body.resize(12 + ids * 16, 0x11);
        body
    };
    let description = |name: &[u8]| {
        let mut body = vec![0x22; 56];
        body[48..56].copy_from_slice(&20_000u64.to_le_bytes());
        body.extend_from_slice(name);
        pad4(body)
    };

    let mut stream = Vec::new();
    for length in [0, 63, 66, 1 << 40, u64::MAX - 3] {
        stream.extend(lying_header(length, 8));
    }
    for body in [
        main_body(0, 1, 1),
        main_body(SLICE as u64 + 2, 1, 1),
        main_body(SLICE as u64, 2, 1),
        main_body(SLICE as u64, 1, 32_769),
    ] {
        stream.extend(packet(header::TYPE_MAIN, &body, set_id));
    }
    let mut ifsc = vec![0x33; 16];
    ifsc.resize(16 + 20 * 32_769, 0);
    stream.extend(packet(header::TYPE_IFSC, &ifsc, set_id));
    stream.extend(packet(
        header::TYPE_FILE_DESC,
        &description(&[0; 4]),
        set_id,
    ));
    stream.extend(packet(
        header::TYPE_FILE_DESC,
        &description(&vec![b'a'; 100_004]),
        set_id,
    ));
    let mut odd_unicode = sources[0].id().to_vec();
    odd_unicode.extend_from_slice(b"..\0");
    stream.extend(packet(
        header::TYPE_UNICODE_FILENAME,
        &pad4(odd_unicode),
        set_id,
    ));
    stream.extend(valid);

    let par2 = layout.base.join("set.par2");
    fs::write(&par2, &stream).unwrap();
    let set = Par2FileSet::from_files(&[&stream]).unwrap();
    assert_eq!(set.slice_size, SLICE as u64);
    assert_eq!(set.files.len(), 2);
    assert_eq!(set.recovery_slices.len(), 6);

    fs::write(layout.base.join("kept.bin"), &sources[0].data).unwrap();
    let outcome = repair(&layout.base, &par2).unwrap();
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);
    for source in &sources {
        assert_eq!(
            fs::read(layout.base.join(&source.name)).unwrap(),
            source.data
        );
    }
}
