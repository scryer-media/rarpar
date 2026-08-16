//! `test-corpus/sources.json`: the provenance ledger.
//!
//! One entry per fixture path with its size, SHA-256, and *source*: generated
//! on the shared pinned toolchain, imported byte-identically from a pinned
//! upstream commit, or blocked because its provenance is incomplete. The ledger
//! is hand-maintained (only `build --update-ledger` rewrites it, and then only
//! sizes and digests), so it is written one file entry per line to keep diffs
//! reviewable.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::manifest::ToolchainLock;
use super::{
    Result, digest_file, fail, is_sha256_hex, read_to_string, repo_path, valid_repo_relative,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ledger {
    pub(crate) schema_version: u32,
    /// Repository-relative path of the shared toolchain lock.
    pub(crate) toolchains: String,
    pub(crate) generators: BTreeMap<String, Generator>,
    pub(crate) upstreams: BTreeMap<String, Upstream>,
    pub(crate) files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Generator {
    /// Repository-relative path of the generator script.
    pub(crate) path: String,
    /// Toolchain lock ids the generator may invoke.
    pub(crate) toolchains: Vec<String>,
    /// Whether re-running the generator on the pinned toolchain reproduces the
    /// checked-in bytes. Almost always false for RAR output (header times,
    /// random salts) — recorded honestly, never assumed.
    pub(crate) byte_reproducible: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Upstream {
    pub(crate) repository: String,
    /// Full commit SHA. Never a branch or tag name.
    pub(crate) commit: String,
    /// SPDX license identifier of the upstream files.
    pub(crate) license: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) license_path: String,
    /// How the bytes are stored upstream: `raw`, `uuencode` (libarchive keeps
    /// its test archives uuencoded), or `git-lfs` (the pointer's oid is the
    /// SHA-256 of the bytes).
    pub(crate) encoding: String,
    /// A private upstream cannot be re-fetched by the public publish workflow;
    /// its imports are verified against the pinned commit's LFS oids instead.
    #[serde(default)]
    pub(crate) private: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileEntry {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
    /// Container/format label (`rar4`, `rar5`, `rar15`, `par2`, `mkv`, …).
    /// Informational, but the era profiles are checked against it.
    pub(crate) format: String,
    pub(crate) source: Source,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Source {
    Generated {
        generator: String,
        /// Toolchain lock ids that produced this file's bytes.
        toolchains: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        notes: String,
    },
    Upstream {
        upstream: String,
        path: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        notes: String,
    },
    Blocked {
        reason: String,
    },
}

/// One problem found while checking the ledger; collected rather than thrown
/// so a report lists everything wrong at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) path: String,
    pub(crate) message: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

pub(crate) const SUPPORTED_ENCODINGS: [&str; 3] = ["raw", "uuencode", "git-lfs"];

/// Formats that only a tool writes. A generated file in one of these formats
/// has to name the toolchain that wrote it unless its generator is a
/// hand-assembler (no toolchains, byte-reproducible); raw inputs (`bin`,
/// `txt`) may legitimately come from nothing but coreutils.
pub(crate) const TOOL_FORMATS: [&str; 10] = [
    "rar15", "rar20", "rar4", "rar5", "rar4-rev", "rar5-rev", "sfx-rar4", "sfx-rar5", "par2", "mkv",
];

impl Ledger {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let ledger: Ledger = serde_json::from_str(&read_to_string(path)?)
            .map_err(|source| super::error(format!("decode {}: {source}", path.display())))?;
        Ok(ledger)
    }

    pub(crate) fn paths(&self) -> BTreeSet<String> {
        self.files.iter().map(|entry| entry.path.clone()).collect()
    }

    pub(crate) fn blocked(&self) -> Vec<&FileEntry> {
        self.files
            .iter()
            .filter(|entry| matches!(entry.source, Source::Blocked { .. }))
            .collect()
    }

    /// Structural validation against the toolchain lock: shapes, references,
    /// uniqueness. Does not touch the working tree.
    pub(crate) fn validate(&self, lock: &ToolchainLock) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut finding = |path: &str, message: String| {
            findings.push(Finding {
                path: path.to_owned(),
                message,
            })
        };
        if self.schema_version != 1 {
            finding(
                "sources.json",
                format!("schema_version must be 1, got {}", self.schema_version),
            );
        }
        if self.toolchains != super::TOOLCHAINS_FILE {
            finding(
                "sources.json",
                format!(
                    "toolchains must be {}, got {:?}",
                    super::TOOLCHAINS_FILE,
                    self.toolchains
                ),
            );
        }
        let lock_ids = lock.ids();
        for (name, generator) in &self.generators {
            if !valid_repo_relative(&generator.path) {
                finding(
                    name,
                    format!(
                        "generator path {:?} is not repository-relative",
                        generator.path
                    ),
                );
            }
            if generator.toolchains.is_empty() && !generator.byte_reproducible {
                finding(name, "generator declares no toolchains but is not byte-reproducible (only a hand-assembler may use no pinned tool)".to_owned());
            }
            for id in &generator.toolchains {
                if !lock_ids.contains(id) {
                    finding(
                        name,
                        format!("generator toolchain {id:?} is not in the toolchain lock"),
                    );
                }
            }
        }
        for (name, upstream) in &self.upstreams {
            if !upstream.repository.starts_with("https://") {
                finding(
                    name,
                    format!(
                        "upstream repository {:?} is not an https URL",
                        upstream.repository
                    ),
                );
            }
            if upstream.commit.len() != 40
                || !upstream
                    .commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                finding(
                    name,
                    format!(
                        "upstream commit {:?} is not a full lowercase commit SHA",
                        upstream.commit
                    ),
                );
            }
            if upstream.license.trim().is_empty() {
                finding(name, "upstream has no license".to_owned());
            }
            if !SUPPORTED_ENCODINGS.contains(&upstream.encoding.as_str()) {
                finding(
                    name,
                    format!(
                        "upstream encoding {:?} is not one of {:?}",
                        upstream.encoding, SUPPORTED_ENCODINGS
                    ),
                );
            }
        }
        let mut seen = BTreeSet::new();
        for entry in &self.files {
            if !valid_repo_relative(&entry.path) {
                finding(&entry.path, "path is not repository-relative".to_owned());
            }
            if !seen.insert(entry.path.clone()) {
                finding(&entry.path, "path is listed twice".to_owned());
            }
            if !is_sha256_hex(&entry.sha256) {
                finding(
                    &entry.path,
                    format!("sha256 {:?} is not lowercase 64-hex", entry.sha256),
                );
            }
            if entry.format.trim().is_empty() {
                finding(&entry.path, "format is empty".to_owned());
            }
            match &entry.source {
                Source::Generated {
                    generator,
                    toolchains,
                    inputs,
                    ..
                } => match self.generators.get(generator) {
                    None => finding(
                        &entry.path,
                        format!("generator {generator:?} is not declared"),
                    ),
                    Some(declared) => {
                        if toolchains.is_empty()
                            && !declared.toolchains.is_empty()
                            && TOOL_FORMATS.contains(&entry.format.as_str())
                        {
                            finding(
                                &entry.path,
                                format!(
                                    "a generated {} file must name the toolchain that wrote it",
                                    entry.format
                                ),
                            );
                        }
                        for id in toolchains {
                            if !declared.toolchains.contains(id) {
                                finding(
                                    &entry.path,
                                    format!(
                                        "toolchain {id:?} is not one generator {generator:?} may use"
                                    ),
                                );
                            }
                        }
                        for input in inputs {
                            if !valid_repo_relative(input) {
                                finding(
                                    &entry.path,
                                    format!("input {input:?} is not repository-relative"),
                                );
                            }
                        }
                    }
                },
                Source::Upstream { upstream, path, .. } => {
                    if !self.upstreams.contains_key(upstream) {
                        finding(
                            &entry.path,
                            format!("upstream {upstream:?} is not declared"),
                        );
                    }
                    if path.trim().is_empty() {
                        finding(&entry.path, "upstream path is empty".to_owned());
                    }
                }
                Source::Blocked { reason } => {
                    if reason.trim().is_empty() {
                        finding(&entry.path, "blocked entry has no reason".to_owned());
                    }
                }
            }
        }
        findings
    }

    /// Check the ledger against the working tree: every generator script and
    /// declared input exists, and every listed file is present with the
    /// recorded bytes. `require_present` turns a missing fixture into a finding
    /// (build/publish); without it a missing fixture is skipped (a partially
    /// hydrated checkout being verified).
    pub(crate) fn check_tree(&self, root: &Path, require_present: bool) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (name, generator) in &self.generators {
            if !repo_path(root, &generator.path).is_file() {
                findings.push(Finding {
                    path: name.clone(),
                    message: format!(
                        "generator script {} is missing from the tree",
                        generator.path
                    ),
                });
            }
        }
        for entry in &self.files {
            let path = repo_path(root, &entry.path);
            if !path.is_file() {
                if require_present {
                    findings.push(Finding {
                        path: entry.path.clone(),
                        message: "missing from the tree".to_owned(),
                    });
                }
                continue;
            }
            match digest_file(&path) {
                Err(err) => findings.push(Finding {
                    path: entry.path.clone(),
                    message: err.to_string(),
                }),
                Ok(digest) => {
                    if digest.lfs_pointer {
                        findings.push(Finding {
                            path: entry.path.clone(),
                            message: "is a Git LFS pointer, not fixture bytes".to_owned(),
                        });
                    } else if digest.sha256 != entry.sha256 || digest.size != entry.size {
                        findings.push(Finding {
                            path: entry.path.clone(),
                            message: format!(
                                "tree has sha256 {} ({} bytes), ledger says {} ({} bytes)",
                                digest.sha256, digest.size, entry.sha256, entry.size
                            ),
                        });
                    }
                }
            }
            if let Source::Generated { inputs, .. } = &entry.source {
                for input in inputs {
                    if !repo_path(root, input).exists() {
                        findings.push(Finding {
                            path: entry.path.clone(),
                            message: format!("declared input {input} is missing from the tree"),
                        });
                    }
                }
            }
        }
        findings
    }

    /// Refresh sizes and digests of the listed paths from the tree. Provenance
    /// is never touched: a changed fixture still has to have its source edited
    /// by hand, and this only makes the ledger agree with the bytes.
    pub(crate) fn refresh_digests(&mut self, root: &Path) -> Result<usize> {
        let mut changed = 0;
        for entry in &mut self.files {
            let path = repo_path(root, &entry.path);
            if !path.is_file() {
                return fail(format!(
                    "{}: missing from the tree; cannot refresh its digest",
                    entry.path
                ));
            }
            let digest = digest_file(&path)?;
            if digest.lfs_pointer {
                return fail(format!(
                    "{}: is a Git LFS pointer; hydrate it before refreshing",
                    entry.path
                ));
            }
            if digest.sha256 != entry.sha256 || digest.size != entry.size {
                entry.sha256 = digest.sha256;
                entry.size = digest.size;
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// The reviewable on-disk layout: sections pretty-printed, one compact
    /// file entry per line, files sorted by path.
    pub(crate) fn render(&self) -> Result<String> {
        let mut files = self.files.clone();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut out = String::new();
        out.push_str("{\n");
        writeln!(out, "  \"schema_version\": {},", self.schema_version)?;
        writeln!(
            out,
            "  \"toolchains\": {},",
            serde_json::to_string(&self.toolchains)?
        )?;
        write_section(&mut out, "generators", &self.generators)?;
        write_section(&mut out, "upstreams", &self.upstreams)?;
        out.push_str("  \"files\": [\n");
        for (index, entry) in files.iter().enumerate() {
            let comma = if index + 1 == files.len() { "" } else { "," };
            writeln!(out, "    {}{comma}", serde_json::to_string(entry)?)?;
        }
        out.push_str("  ]\n}\n");
        Ok(out)
    }
}

fn write_section<T: Serialize>(
    out: &mut String,
    name: &str,
    value: &BTreeMap<String, T>,
) -> Result<()> {
    let pretty = serde_json::to_string_pretty(value)?;
    // Indent the pretty block by one level under the top-level object.
    let indented: String = pretty
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line.to_owned()
            } else {
                format!("  {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    writeln!(out, "  \"{name}\": {indented},")?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_corpus::manifest::ToolchainLock;

    pub(crate) fn sample_lock() -> ToolchainLock {
        serde_json::from_str(
            r#"{
              "schema_version": 1,
              "docker_base": "debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818",
              "rar_writers": [
                {"id":"rarlab-6.24","image":"i6","platform":"linux/amd64","url":"https://www.rarlab.com/rar/rarlinux-x64-624.tar.gz","sha256":"88e22a8e84125c947637bbf28c746e338a0a63279d80f9f9d7373603875db1eb","binary":"rar"},
                {"id":"rarlab-7.20","image":"i7","platform":"linux/amd64","url":"https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz","sha256":"d3e7fba3272385b1d0255ee332a1e8c1a6779bb5a5ff9d4d8ac2be846e49ca46","binary":"rar"}
              ],
              "video_encoder": {"id":"ffmpeg-7.1-ubuntu2404","image":"jrottenberg/ffmpeg@sha256:292a972c60356abd651d9a4f9c808c13e7473f65ad400b7eb99215f4e571931d","platform":"linux/amd64"},
              "par2_generator": {"id":"par2cmdline-turbo-1.4.0","image":"p","platform":"linux/amd64","url":"https://example.test/p.tar.gz","sha256":"6f2cb042f23d9b0c93f14cc0e16de5bd6e98bf36d8be1f8f2e886fa85ad1b972"}
            }"#,
        )
        .unwrap()
    }

    pub(crate) fn sample_ledger() -> Ledger {
        serde_json::from_str(
            r#"{
              "schema_version": 1,
              "toolchains": "bench/rarpar-bench/config/toolchains.json",
              "generators": {
                "gen.sh": {"path": "gen/gen.sh", "toolchains": ["rarlab-7.20"], "byte_reproducible": false}
              },
              "upstreams": {
                "junrar": {"repository": "https://github.com/junrar/junrar", "commit": "0123456789abcdef0123456789abcdef01234567", "license": "Apache-2.0", "license_path": "LICENSE", "encoding": "raw"}
              },
              "files": [
                {"path": "f/rar5/a.rar", "size": 3, "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "format": "rar5",
                 "source": {"kind": "generated", "generator": "gen.sh", "toolchains": ["rarlab-7.20"], "inputs": ["f/originals/small.txt"]}},
                {"path": "f/rar4/rar15_lz.rar", "size": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "format": "rar15",
                 "source": {"kind": "upstream", "upstream": "junrar", "path": "src/test/resources/x.rar"}}
              ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn a_consistent_ledger_validates_and_round_trips() {
        let ledger = sample_ledger();
        assert!(ledger.validate(&sample_lock()).is_empty());
        let rendered = ledger.render().unwrap();
        let reparsed: Ledger = serde_json::from_str(&rendered).unwrap();
        assert_eq!(reparsed.files.len(), 2);
        assert_eq!(
            reparsed.files[0].path, "f/rar4/rar15_lz.rar",
            "render sorts by path"
        );
        assert!(
            rendered.contains("\n    {\"path\":\"f/rar5/a.rar\""),
            "one compact entry per line:\n{rendered}"
        );
        assert_eq!(
            reparsed.render().unwrap(),
            rendered,
            "render is a fixed point"
        );
    }

    #[test]
    fn structural_problems_are_all_reported() {
        let mut ledger = sample_ledger();
        ledger.files.push(FileEntry {
            path: "f/rar5/a.rar".into(),
            size: 1,
            sha256: "zz".into(),
            format: "".into(),
            source: Source::Generated {
                generator: "missing.sh".into(),
                toolchains: vec!["rarlab-3.93".into()],
                inputs: vec!["/abs".into()],
                notes: String::new(),
            },
        });
        ledger.files.push(FileEntry {
            path: "f/rar4/x.rar".into(),
            size: 1,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            format: "rar4".into(),
            source: Source::Upstream {
                upstream: "nope".into(),
                path: "".into(),
                notes: String::new(),
            },
        });
        ledger.files.push(FileEntry {
            path: "f/rar4/y.rar".into(),
            size: 1,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            format: "rar4".into(),
            source: Source::Blocked { reason: " ".into() },
        });
        ledger
            .generators
            .get_mut("gen.sh")
            .unwrap()
            .toolchains
            .push("rarlab-9.99".into());
        ledger.upstreams.get_mut("junrar").unwrap().commit = "main".into();
        let findings = ledger.validate(&sample_lock());
        let text = findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "listed twice",
            "not lowercase 64-hex",
            "format is empty",
            "generator \"missing.sh\" is not declared",
            "upstream \"nope\" is not declared",
            "upstream path is empty",
            "blocked entry has no reason",
            "not in the toolchain lock",
            "not a full lowercase commit SHA",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    #[test]
    fn a_generated_file_may_only_use_its_generators_toolchains() {
        let mut ledger = sample_ledger();
        if let Source::Generated { toolchains, .. } = &mut ledger.files[0].source {
            toolchains.push("rarlab-6.24".into());
        }
        let findings = ledger.validate(&sample_lock());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("not one generator"));
    }

    #[test]
    fn tree_checks_catch_missing_pointer_and_changed_bytes() {
        let root = std::env::temp_dir().join(format!("xtask-corpus-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("f/rar5")).unwrap();
        std::fs::create_dir_all(root.join("f/rar4")).unwrap();
        std::fs::create_dir_all(root.join("f/originals")).unwrap();
        std::fs::create_dir_all(root.join("gen")).unwrap();
        std::fs::write(root.join("gen/gen.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(root.join("f/originals/small.txt"), "x").unwrap();
        let ledger = sample_ledger();

        // Nothing present: verify mode skips, build mode reports.
        assert!(ledger.check_tree(&root, false).is_empty());
        assert_eq!(ledger.check_tree(&root, true).len(), 2);

        std::fs::write(root.join("f/rar5/a.rar"), "abc").unwrap();
        std::fs::write(root.join("f/rar4/rar15_lz.rar"), "").unwrap();
        assert!(ledger.check_tree(&root, true).is_empty());

        std::fs::write(root.join("f/rar5/a.rar"), "abcd").unwrap();
        let findings = ledger.check_tree(&root, true);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("tree has sha256"));

        std::fs::write(
            root.join("f/rar5/a.rar"),
            "version https://git-lfs.github.com/spec/v1\noid sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nsize 3\n",
        )
        .unwrap();
        let findings = ledger.check_tree(&root, true);
        assert!(findings[0].message.contains("Git LFS pointer"));

        let mut refreshed = ledger.clone();
        std::fs::write(root.join("f/rar5/a.rar"), "abcd").unwrap();
        assert_eq!(refreshed.refresh_digests(&root).unwrap(), 1);
        assert_eq!(refreshed.files[0].size, 4);
        assert!(refreshed.check_tree(&root, true).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
