//! Archives shaped after published RAR advisories, in UnRAR, WinRAR, 7-Zip,
//! libarchive, junrar and the other RAR readers. Each one is built by hand
//! here, so a single field can lie at a time. Every one must give an error or
//! a result that stays inside the extraction root, never a panic, a hang, a
//! write outside the root or output the archive does not hold.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use unrar_rs::{RarArchive, RarError};

const RAR5_SIGNATURE: [u8; 8] = *b"Rar!\x1a\x07\x01\x00";
const RAR4_SIGNATURE: [u8; 7] = *b"Rar!\x1a\x07\x00";
const HOST_WINDOWS: u64 = 0;
const HOST_UNIX: u64 = 1;

fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn crc32(parts: &[&[u8]]) -> u32 {
    let mut digest = crc_turbo::Digest::new(crc_turbo::CrcAlgorithm::Crc32IsoHdlc);
    for part in parts {
        digest.update(part);
    }
    digest.finalize() as u32
}

/// One RAR5 block: CRC32, size, then `body` (type, flags and the rest).
fn rar5_block(body: &[u8]) -> Vec<u8> {
    let size = vint(body.len() as u64);
    let mut out = crc32(&[&size, body]).to_le_bytes().to_vec();
    out.extend_from_slice(&size);
    out.extend_from_slice(body);
    out
}

fn rar5_header(kind: u64, type_body: &[u8], extra: &[u8], data: Option<u64>) -> Vec<u8> {
    let mut flags = 0;
    if !extra.is_empty() {
        flags |= 0x1;
    }
    if data.is_some() {
        flags |= 0x2;
    }
    let mut body = vint(kind);
    body.extend(vint(flags));
    if !extra.is_empty() {
        body.extend(vint(extra.len() as u64));
    }
    if let Some(size) = data {
        body.extend(vint(size));
    }
    body.extend_from_slice(type_body);
    body.extend_from_slice(extra);
    rar5_block(&body)
}

#[derive(Clone)]
enum Payload {
    Stored(Vec<u8>),
    /// Compression info and packed bytes, with the declared unpacked size.
    Packed {
        info: u64,
        packed: Vec<u8>,
        size: u64,
    },
    /// A RAR5 file system redirection record: type and target.
    Link(u64, String),
    Directory,
}

#[derive(Clone)]
struct Member {
    name: Vec<u8>,
    host: u64,
    attributes: u64,
    payload: Payload,
}

impl Member {
    fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            host: HOST_UNIX,
            attributes: 0o644,
            payload: Payload::Stored(data.to_vec()),
        }
    }

    fn link(name: &str, kind: u64, target: &str) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            host: HOST_UNIX,
            attributes: 0o120777,
            payload: Payload::Link(kind, target.into()),
        }
    }

    fn directory(name: &str) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            host: HOST_UNIX,
            attributes: 0o755,
            payload: Payload::Directory,
        }
    }

    fn on(mut self, host: u64) -> Self {
        self.host = host;
        if host == HOST_WINDOWS {
            self.attributes = 0x20;
        }
        self
    }

    fn header(&self) -> (Vec<u8>, Vec<u8>) {
        let (flags, size, info, data, extra) = match &self.payload {
            Payload::Stored(bytes) => (0x4, bytes.len() as u64, 0, bytes.clone(), Vec::new()),
            Payload::Packed { info, packed, size } => {
                (0x0, *size, *info, packed.clone(), Vec::new())
            }
            Payload::Link(kind, target) => {
                let mut record = vint(*kind);
                record.extend(vint(0));
                record.extend(vint(target.len() as u64));
                record.extend_from_slice(target.as_bytes());
                let mut extra = vint(record.len() as u64 + 1);
                extra.extend(vint(5));
                extra.extend(record);
                (0x4, 0, 0, Vec::new(), extra)
            }
            Payload::Directory => (0x1, 0, 0, Vec::new(), Vec::new()),
        };
        let mut body = vint(flags);
        body.extend(vint(size));
        body.extend(vint(self.attributes));
        if flags & 0x4 != 0 {
            body.extend(crc32(&[&data]).to_le_bytes());
        }
        body.extend(vint(info));
        body.extend(vint(self.host));
        body.extend(vint(self.name.len() as u64));
        body.extend_from_slice(&self.name);
        let data_size = (!matches!(self.payload, Payload::Directory)).then_some(data.len() as u64);
        (rar5_header(2, &body, &extra, data_size), data)
    }
}

fn rar5_archive(solid: bool, members: &[Member]) -> Vec<u8> {
    let mut out = RAR5_SIGNATURE.to_vec();
    out.extend(rar5_header(
        1,
        &vint(if solid { 0x4 } else { 0 }),
        &[],
        None,
    ));
    for member in members {
        let (header, data) = member.header();
        out.extend(header);
        out.extend(data);
    }
    out.extend(rar5_header(5, &vint(0), &[], None));
    out
}

fn open(bytes: Vec<u8>) -> unrar_rs::RarResult<RarArchive> {
    RarArchive::open(Cursor::new(bytes))
}

/// Decode every member to memory. Returns the output of each member that
/// decoded, and checks no member gave more bytes than it declares.
fn decode_all(bytes: Vec<u8>) -> Vec<unrar_rs::RarResult<Vec<u8>>> {
    let Ok(mut archive) = open(bytes) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for index in 0..archive.len() {
        let declared = archive
            .entry_info(index)
            .and_then(|info| info.unpacked_size);
        let result = archive.by_index(index).and_then(|entry| {
            let mut out = Vec::new();
            entry.copy_to(&mut out).map(|_| out)
        });
        if let (Ok(out), Some(declared)) = (&result, declared) {
            assert!(
                out.len() as u64 <= declared,
                "member {index} gave {} bytes, declared {declared}",
                out.len()
            );
        }
        results.push(result);
    }
    results
}

/// An extraction root inside a parent that must stay as it was.
struct Root {
    _temp: tempfile::TempDir,
    parent: PathBuf,
    root: PathBuf,
}

impl Root {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let root = parent.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(parent.join("secret"), b"outside").unwrap();
        Self {
            _temp: temp,
            parent,
            root,
        }
    }

    fn extract(&self, bytes: Vec<u8>) -> Vec<unrar_rs::RarResult<PathBuf>> {
        let mut archive = open(bytes).unwrap();
        (0..archive.len())
            .map(|index| {
                archive
                    .by_index(index)
                    .and_then(|entry| entry.unpack_in(&self.root))
            })
            .collect()
    }

    /// The parent holds the root and the untouched secret, nothing else.
    fn assert_contained(&self) {
        let mut names = std::fs::read_dir(&self.parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["root", "secret"]);
        let secret = self.parent.join("secret");
        assert!(
            !std::fs::symlink_metadata(&secret)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&secret).unwrap(), b"outside");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(&secret).unwrap().nlink(),
                1,
                "secret gained a hard link"
            );
        }
        for path in walk(&self.root) {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_file() {
                assert_ne!(
                    std::fs::read(&path).unwrap(),
                    b"outside",
                    "{} holds the secret",
                    path.display()
                );
            }
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if std::fs::symlink_metadata(&path).unwrap().is_dir() {
            out.extend(walk(&path));
        }
        out.push(path);
    }
    out
}

fn assert_inside(root: &Path, path: &Path) {
    let root = root.canonicalize().unwrap();
    let parent = path.parent().unwrap().canonicalize().unwrap();
    assert!(
        parent.starts_with(&root),
        "{} is outside {}",
        path.display(),
        root.display()
    );
}

#[test]
fn names_that_climb_out_are_written_inside_the_root() {
    // CVE-2001-1271, CVE-2017-14120, CVE-2022-30333, CVE-2025-6218 and
    // CVE-2025-8088 (UnRAR/WinRAR), CVE-2013-4668 and CVE-2015-2304
    // (libarchive users), CVE-2026-28208, CVE-2026-41245 and CVE-2026-86071
    // (junrar backslash, prefix and directory escapes), CVE-2025-14111: a
    // member name that is absolute, carries a drive or UNC prefix, an NTFS
    // stream, or climbs with `..` in either separator.
    let names = [
        "../escape",
        "../../escape",
        "./../escape",
        "a/../../escape",
        "a/b/../../../escape",
        "/escape",
        "//server/share/escape",
        "C:/escape",
        "C:escape",
        "..\\escape",
        "a\\..\\..\\escape",
        "\\\\?\\C:\\escape",
        "C:\\..\\escape",
        "file.txt:..\\..\\escape",
        "....//escape",
        "a/..",
        "..",
    ];
    for host in [HOST_UNIX, HOST_WINDOWS] {
        for name in names {
            let root = Root::new();
            let member = Member::stored(name, b"payload").on(host);
            let results = root.extract(rar5_archive(false, &[member]));
            assert_eq!(results.len(), 1, "{name}");
            match &results[0] {
                Ok(path) => {
                    assert_inside(&root.root, path);
                    assert_eq!(std::fs::read(path).unwrap(), b"payload", "{name}");
                }
                Err(error) => assert!(matches!(name, ".." | "a/.."), "{name}: {error}"),
            }
            root.assert_contained();
        }
    }
}

#[test]
#[cfg(unix)]
fn symlinks_that_point_out_are_refused() {
    // CVE-2014-9983 and CVE-2017-12938 (UnRAR symlink targets),
    // CVE-2015-6984 and CVE-2026-92205 (libarchive users): a symlink whose
    // target is absolute or climbs above the root.
    let cases = [
        ("link", "/etc/passwd"),
        ("link", "../secret"),
        ("link", "a/../../secret"),
        ("link", "x/../.."),
        ("sub/link", "../../secret"),
        ("sub/link", "../../../../../../secret"),
        ("a/b/link", "../../../secret"),
    ];
    for (name, target) in cases {
        let root = Root::new();
        let results = root.extract(rar5_archive(false, &[Member::link(name, 1, target)]));
        assert!(
            matches!(results[0], Err(RarError::UnsafeLinkTarget { .. })),
            "{name} -> {target}: {:?}",
            results[0]
        );
        root.assert_contained();
    }

    let root = Root::new();
    let results = root.extract(rar5_archive(
        false,
        &[Member::link("sub/link", 1, "../sibling")],
    ));
    assert!(results[0].is_ok(), "{:?}", results[0]);
    root.assert_contained();
}

#[test]
#[cfg(unix)]
fn a_member_under_a_symlink_is_written_inside_the_root() {
    // CVE-2022-30333 and CVE-2022-48579: a symlink extracted first, then a
    // member whose path runs through it. The symlink here stays inside the
    // root, which the target check allows; the later member must still not
    // be written through it.
    let root = Root::new();
    let members = [
        Member::directory("real"),
        Member::link("d", 1, "real"),
        Member::stored("d/file", b"payload"),
    ];
    let results = root.extract(rar5_archive(false, &members));
    let written = results[2].as_ref().unwrap();
    assert_inside(&root.root, written);
    assert_eq!(std::fs::read(written).unwrap(), b"payload");
    assert!(
        !root.root.join("real/file").exists(),
        "written through the symlink"
    );
    root.assert_contained();

    // A symlink already in the root that points outside it.
    let root = Root::new();
    std::os::unix::fs::symlink(&root.parent, root.root.join("d")).unwrap();
    for path in root
        .extract(rar5_archive(
            false,
            &[Member::stored("d/secret", b"payload")],
        ))
        .into_iter()
        .flatten()
    {
        assert_inside(&root.root, &path);
    }
    root.assert_contained();
}

#[test]
fn hard_links_and_file_copies_stay_inside_the_root() {
    // CVE-2026-39243 (hard-link target escape), CVE-2016-5418 (libarchive
    // hard links with data): a hard link (4) or file copy (5) naming a target
    // outside the root must not link or copy it in.
    let targets = [
        "../secret",
        "../../parent/secret",
        "/etc/hostname",
        "a/../../secret",
        "..\\secret",
    ];
    for kind in [4, 5] {
        for target in targets {
            let root = Root::new();
            for path in root
                .extract(rar5_archive(false, &[Member::link("copy", kind, target)]))
                .into_iter()
                .flatten()
            {
                assert_inside(&root.root, &path);
            }
            root.assert_contained();
        }
    }
}

#[test]
#[cfg(unix)]
fn set_id_bits_are_dropped_for_an_unprivileged_extraction() {
    // CVE-2023-49102 class: an archive must not hand an unprivileged
    // extraction a set-user-ID or set-group-ID file. Execute bits are kept,
    // as UnRAR keeps them.
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = Root::new();
    let mut member = Member::stored("tool", b"#!/bin/sh\n");
    member.attributes = 0o106755;
    let path = root
        .extract(rar5_archive(false, &[member]))
        .remove(0)
        .unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[test]
fn headers_that_cannot_be_true_are_errors() {
    // CVE-2020-9308 (libarchive RAR5 header size 0), CVE-2018-25018 (UnRAR
    // QuickOpen::ReadRaw), CVE-2017-12940 (UnRAR ReadHeader15), CVE-2026-78322
    // (overlong names): a block whose sizes do not fit what holds them.
    let main = rar5_header(1, &vint(0), &[], None);
    let file = |body: Vec<u8>| {
        let mut out = RAR5_SIGNATURE.to_vec();
        out.extend(&main);
        out.extend(rar5_block(&body));
        out.extend(rar5_header(5, &vint(0), &[], None));
        out
    };
    let mut cases = Vec::new();

    // Header size zero, with a valid CRC of nothing.
    let mut zero = RAR5_SIGNATURE.to_vec();
    zero.extend(&main);
    zero.extend(crc32(&[&[0]]).to_le_bytes());
    zero.push(0);
    cases.push(("header size zero", zero));

    // Header size larger than the file, past the crate's limit, and a size
    // vint eleven bytes long.
    for (label, size) in [
        ("header past the file", vint(4096)),
        ("header past the limit", vint(u64::from(u32::MAX))),
        ("eleven byte size", [&[0xff; 10][..], &[0x01]].concat()),
    ] {
        let mut bytes = RAR5_SIGNATURE.to_vec();
        bytes.extend(&main);
        bytes.extend(crc32(&[&size]).to_le_bytes());
        bytes.extend(&size);
        bytes.extend([2, 0, 0]);
        cases.push((label, bytes));
    }

    // A name length past the end of its header. UnRAR's RawRead::GetB copies
    // the bytes the header holds and zero-fills the rest, so the name is only
    // what the header holds, never bytes from beyond it.
    let mut body = vint(2);
    body.extend(vint(0));
    body.extend([vint(0), vint(0), vint(0o644), vint(0), vint(HOST_UNIX)].concat());
    body.extend(vint(0xffff));
    body.extend(b"short");
    let archive = open(file(body)).unwrap();
    let names = archive.entries().map(|info| info.name).collect::<Vec<_>>();
    assert_eq!(names, ["short"]);

    // An extra area larger than the header.
    let mut body = vint(2);
    body.extend(vint(0x1));
    body.extend(vint(1 << 20));
    body.extend(
        [
            vint(0),
            vint(0),
            vint(0o644),
            vint(0),
            vint(HOST_UNIX),
            vint(1),
            b"n".to_vec(),
        ]
        .concat(),
    );
    cases.push(("extra past the header", file(body)));

    // A data area that runs past the end of the volume.
    let mut body = vint(2);
    body.extend(vint(0x2));
    body.extend(vint(1 << 40));
    body.extend(
        [
            vint(0x4),
            vint(1 << 40),
            vint(0o644),
            0u32.to_le_bytes().to_vec(),
            vint(0),
            vint(HOST_UNIX),
            vint(1),
            b"n".to_vec(),
        ]
        .concat(),
    );
    cases.push(("data past the volume", file(body)));

    for (label, bytes) in cases {
        let results = decode_all(bytes);
        assert!(results.iter().all(Result::is_err), "{label}: {results:?}");
    }
}

#[test]
fn dictionaries_past_the_limit_are_refused() {
    // CVE-2025-11579 (rardecode unbounded dictionary), CVE-2016-4302 and
    // CVE-2018-1000877 (libarchive zero and reallocated dictionaries): a
    // declared dictionary larger than the limit is refused, whatever the data.
    for (version, code) in [(0u64, 15u64), (1, 31), (1, 0x7fff >> 1)] {
        let info = version | (3 << 7) | (code << 10);
        let member = Member {
            name: b"big".to_vec(),
            host: HOST_UNIX,
            attributes: 0o644,
            payload: Payload::Packed {
                info,
                packed: vec![0; 64],
                size: 1 << 20,
            },
        };
        let bytes = rar5_archive(false, &[member]);
        // Refused when the archive opens, or when the member decodes.
        if open(bytes.clone()).is_err() {
            continue;
        }
        let results = decode_all(bytes);
        assert!(
            !results.is_empty()
                && results.iter().all(|result| matches!(
                    result,
                    Err(RarError::DictionaryTooLarge { .. }
                        | RarError::ResourceLimit { .. }
                        | RarError::UnsupportedCompression { .. })
                )),
            "version {version} code {code}: {results:?}"
        );
    }
}

fn noise(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn noise_in_every_rar5_method_ends_cleanly() {
    // UnRAR CVE-2017-12941, CVE-2017-12942, CVE-2017-20006 (CopyString),
    // 7-Zip CVE-2018-10115 and CVE-2025-53816 (RAR5 window zeroing),
    // libarchive CVE-2015-8934, CVE-2024-48957, CVE-2024-48958,
    // CVE-2025-5915 (filter past the window), CVE-2026-4111 (no forward
    // progress) and CVE-2026-4424: random bytes as the packed data of every
    // method, at the smallest dictionaries, in a non-solid and a solid
    // archive, where a later member runs on the state an earlier one broke
    // (CVE-2026-14164, CVE-2018-1000878).
    for seed in 0..48u64 {
        for method in 1..=5u64 {
            for code in [0u64, 1] {
                let member = |name: &str, solid: bool, offset: u64| Member {
                    name: name.as_bytes().to_vec(),
                    host: HOST_UNIX,
                    attributes: 0o644,
                    payload: Payload::Packed {
                        info: (u64::from(solid) << 6) | (method << 7) | (code << 10),
                        packed: noise(512 + (seed as usize % 7) * 300, seed * 31 + offset),
                        size: 1 << 18,
                    },
                };
                assert_eq!(
                    decode_all(rar5_archive(false, &[member("a", false, 0)])).len(),
                    1
                );
                let solid = [
                    member("a", false, 0),
                    member("b", true, 1),
                    member("c", true, 2),
                ];
                assert_eq!(decode_all(rar5_archive(true, &solid)).len(), 3);
            }
        }
    }
}

/// One RAR4 block: CRC16 of the rest, then the rest.
fn rar4_block(kind: u8, flags: u16, fields: &[u8]) -> Vec<u8> {
    let size = (7 + fields.len()) as u16;
    let mut rest = vec![kind];
    rest.extend(flags.to_le_bytes());
    rest.extend(size.to_le_bytes());
    rest.extend_from_slice(fields);
    let mut out = ((crc32(&[&rest]) & 0xffff) as u16).to_le_bytes().to_vec();
    out.extend(rest);
    out
}

struct Rar4Member {
    name: Vec<u8>,
    flags: u16,
    version: u8,
    method: u8,
    packed: Vec<u8>,
    size: u32,
}

fn rar4_archive(solid: bool, members: &[Rar4Member]) -> Vec<u8> {
    let mut out = RAR4_SIGNATURE.to_vec();
    out.extend(rar4_block(0x73, if solid { 0x0008 } else { 0 }, &[0; 6]));
    for member in members {
        let mut fields = (member.packed.len() as u32).to_le_bytes().to_vec();
        fields.extend(member.size.to_le_bytes());
        fields.push(3);
        let stored = member.method == 0x30;
        fields.extend(if stored { crc32(&[&member.packed]) } else { 0 }.to_le_bytes());
        fields.extend(0x5a21_0000u32.to_le_bytes());
        fields.push(member.version);
        fields.push(member.method);
        fields.extend((member.name.len() as u16).to_le_bytes());
        fields.extend(0o100644u32.to_le_bytes());
        fields.extend_from_slice(&member.name);
        out.extend(rar4_block(0x74, 0x8000 | member.flags, &fields));
        out.extend_from_slice(&member.packed);
    }
    out.extend(rar4_block(0x7b, 0x4000, &[]));
    out
}

#[test]
fn noise_in_every_rar4_method_ends_cleanly() {
    // UnRAR CVE-2017-12941 (Unpack20), CVE-2017-12942 (LongLZ, RAR 1.5),
    // CVE-2012-6706 (VMSF_DELTA) and CVE-2007-3726 (RarVM), 7-Zip
    // CVE-2018-5996 (PPMd), libarchive CVE-2015-8926 and CVE-2019-18408
    // (PPMd after a failure), bulk_extractor CVE-2026-24857: random bytes as
    // the packed data of RAR 1.5, 2.0, 2.6 and 2.9 members, alone and solid.
    for seed in 0..48u64 {
        for version in [15u8, 20, 26, 29] {
            for method in [0x31u8, 0x33, 0x35] {
                let member = |name: &str, flags: u16, offset: u64| Rar4Member {
                    name: name.as_bytes().to_vec(),
                    flags,
                    version,
                    method,
                    packed: noise(512 + (seed as usize % 5) * 400, seed * 17 + offset),
                    size: 1 << 18,
                };
                assert_eq!(
                    decode_all(rar4_archive(false, &[member("a", 0, 0)])).len(),
                    1
                );
                let solid = [
                    member("a", 0, 0),
                    member("b", 0x0010, 1),
                    member("c", 0x0010, 2),
                ];
                assert_eq!(decode_all(rar4_archive(true, &solid)).len(), 3);
            }
        }
        // A RAR 2.9 PPMd block whose model asks for the largest arena, then
        // noise: the arena limit, then the decoder.
        let mut packed = vec![0x80 | 0x20, 0x3f, 0xff];
        packed.extend(noise(1024, seed));
        let results = decode_all(rar4_archive(
            false,
            &[Rar4Member {
                name: b"ppmd".to_vec(),
                flags: 0,
                version: 29,
                method: 0x35,
                packed,
                size: 1 << 18,
            }],
        ));
        assert_eq!(results.len(), 1);
    }
}

#[test]
fn encoded_rar4_names_stay_names() {
    // UnRAR CVE-2017-12940 (EncodeFileName::Decode) and libarchive
    // CVE-2017-14502 (UTF-16 name off by one): a RAR4 Unicode name whose
    // encoded half is cut short or says more than the plain half holds. The
    // name decodes to something, and an extraction under it stays inside the
    // root.
    let mut names = vec![
        b"name\0".to_vec(),
        b"name\0\x00".to_vec(),
        b"name\0\x00\xc0".to_vec(),
        b"name\0\x00\xc0\xff".to_vec(),
        b"name\0\x00\xc0\xff\x01".to_vec(),
        b"\0\x00\xc0\x7f".to_vec(),
        b"../x\0\x00\x80\x2e".to_vec(),
        b"name\0\x00\x80\x01".to_vec(),
    ];
    for seed in 0..256u64 {
        let mut name = b"a/b\0".to_vec();
        name.extend(noise(1 + seed as usize % 40, seed));
        names.push(name);
    }
    let mut extracted = 0;
    let count = names.len();
    for name in names {
        let member = Rar4Member {
            name,
            flags: 0x0200,
            version: 29,
            method: 0x30,
            packed: b"payload".to_vec(),
            size: 7,
        };
        let bytes = rar4_archive(false, &[member]);
        let Ok(archive) = open(bytes.clone()) else {
            continue;
        };
        for index in 0..archive.len() {
            let _ = archive.entry_info(index).map(|info| info.name.len());
        }
        let root = Root::new();
        let mut archive = open(bytes).unwrap();
        for index in 0..archive.len() {
            if let Ok(path) = archive
                .by_index(index)
                .and_then(|entry| entry.unpack_in(&root.root))
            {
                assert_inside(&root.root, &path);
                assert_eq!(std::fs::read(&path).unwrap(), b"payload");
                extracted += 1;
            }
        }
        root.assert_contained();
    }
    // Most names decode to something that can be written; the test is not
    // passing on archives that never open.
    assert!(extracted * 2 > count, "{extracted} of {count} extracted");
}

#[test]
fn a_split_member_without_its_next_volume_is_an_error() {
    // libarchive CVE-2015-8916: a member marked as continuing in the next
    // volume, read from a set that has none, is an error, never a member
    // that ends early as if whole.
    let mut body = vint(2);
    body.extend(vint(0x2 | 0x10));
    body.extend(vint(4));
    body.extend(
        [
            vint(0x4),
            vint(8),
            vint(0o644),
            crc32(&[b"abcdefgh"]).to_le_bytes().to_vec(),
            vint(0),
            vint(HOST_UNIX),
            vint(1),
            b"n".to_vec(),
        ]
        .concat(),
    );
    let mut bytes = RAR5_SIGNATURE.to_vec();
    bytes.extend(rar5_header(1, &vint(0x1), &[], None));
    bytes.extend(rar5_block(&body));
    bytes.extend(b"abcd");
    bytes.extend(rar5_header(5, &vint(0x1), &[], None));
    let results = decode_all(bytes);
    assert!(
        !results.is_empty() && results.iter().all(Result::is_err),
        "{results:?}"
    );
}

#[test]
fn an_oversized_kdf_count_is_refused() {
    // CVE-2007-0855 class (hostile encrypted archives): a RAR5 archive
    // encryption header asking for 2^255 key derivation rounds is refused
    // instead of run, with any password.
    let mut body = vint(4);
    body.extend(vint(0));
    body.extend([vint(0), vint(0), vec![0xff], vec![0x11; 16]].concat());
    let mut bytes = RAR5_SIGNATURE.to_vec();
    bytes.extend(rar5_block(&body));
    bytes.extend(rar5_header(1, &vint(0), &[], None));
    for password in ["", "password", &"x".repeat(1 << 16)] {
        let result = RarArchive::open_with_password(Cursor::new(bytes.clone()), password);
        assert!(
            result.is_err(),
            "password of {} bytes opened",
            password.len()
        );
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar5")
        .join(name)
}

/// Rewrite a RAR5 `.rev` header field and fix the header CRC.
fn forge_rev(bytes: &[u8], offset: usize, value: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[16 + offset..18 + offset].copy_from_slice(&value.to_le_bytes());
    let size = u32::from_le_bytes(out[12..16].try_into().unwrap()) as usize;
    let crc = crc32(&[&out[12..16], &out[16..16 + size]]);
    out[8..12].copy_from_slice(&crc.to_le_bytes());
    out
}

#[test]
fn a_recovery_volume_from_another_set_is_refused() {
    // WinRAR CVE-2023-40477 and UnRAR CVE-2026-14191 (RecVolumes5::ReadHeader
    // sizes its table from the first `.rev`, then indexes it with a later
    // one's numbers): a second `.rev` that states other counts, or a slot
    // past the set, must not reach the table.
    let data = (1..=10)
        .filter(|&n| n != 5)
        .map(|n| format!("rar5_recovery_volumes.part{n:02}.rar"))
        .collect::<Vec<_>>();
    if !data.iter().all(|name| fixture(name).exists())
        || !fixture("rar5_recovery_volumes.part02.rev").exists()
    {
        eprintln!("skipping test: rar5 recovery volume fixtures not present");
        return;
    }
    let first = std::fs::read(fixture("rar5_recovery_volumes.part01.rev")).unwrap();
    let second = std::fs::read(fixture("rar5_recovery_volumes.part02.rev")).unwrap();
    let missing = std::fs::read(fixture("rar5_recovery_volumes.part05.rar")).unwrap();

    // Body offsets: version at 0, data count at 1, recovery count at 3,
    // recovery number at 5.
    for (label, forged, refused) in [
        ("other data count", forge_rev(&second, 1, 11), true),
        ("other recovery count", forge_rev(&second, 3, 3), true),
        ("slot past the set", forge_rev(&second, 5, 0xffff), false),
        ("slot zero", forge_rev(&second, 5, 0), false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for name in &data {
            let path = temp.path().join(name);
            std::fs::copy(fixture(name), &path).unwrap();
            paths.push(path);
        }
        for (name, bytes) in [
            ("rar5_recovery_volumes.part01.rev", &first),
            ("rar5_recovery_volumes.part02.rev", &forged),
        ] {
            let path = temp.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            paths.push(path);
        }
        let options = unrar_rs::RecoveryOptions {
            output_dir: Some(temp.path().to_path_buf()),
            overwrite_existing: false,
            verify_restored: true,
        };
        let result = unrar_rs::restore_volumes_from_paths(&paths, &options);
        let rebuilt = temp.path().join("rar5_recovery_volumes.part05.rar");
        if refused {
            assert!(result.is_err(), "{label}: {result:?}");
            assert!(!rebuilt.exists(), "{label}: rebuilt from a foreign .rev");
        } else {
            // The forged `.rev` does not parse; the first one alone covers
            // the one missing volume.
            assert!(result.is_ok(), "{label}: {result:?}");
            assert_eq!(std::fs::read(&rebuilt).unwrap(), missing, "{label}");
        }
    }
}
