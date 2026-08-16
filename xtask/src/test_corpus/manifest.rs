//! The published manifest: a pure function of the ledger, the profiles and the
//! toolchain lock, in canonical JSON, addressed by its own BLAKE3 digest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::ledger::{Ledger, Source};
use super::profiles::ProfilesFile;
use super::{Result, blake3_bytes, error, fail, is_blake3_hex, read_to_string};

pub(crate) const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub(crate) const CORPUS_NAME: &str = "rarpar-test-corpus";

/// The subset of `bench/rarpar-bench/config/toolchains.json` the corpus needs:
/// the ids a ledger entry may name and the pinned sources the manifest carries.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ToolchainLock {
    pub(crate) schema_version: u32,
    pub(crate) docker_base: String,
    pub(crate) rar_writers: Vec<RarWriter>,
    pub(crate) video_encoder: VideoEncoder,
    pub(crate) par2_generator: Par2Generator,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RarWriter {
    pub(crate) id: String,
    pub(crate) image: String,
    pub(crate) platform: String,
    pub(crate) url: String,
    pub(crate) blake3: String,
    pub(crate) binary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct VideoEncoder {
    pub(crate) id: String,
    pub(crate) image: String,
    pub(crate) platform: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Par2Generator {
    pub(crate) id: String,
    pub(crate) image: String,
    pub(crate) platform: String,
    pub(crate) url: String,
    pub(crate) blake3: String,
}

impl ToolchainLock {
    pub(crate) fn load(path: &Path) -> Result<(Self, String)> {
        let text = read_to_string(path)?;
        let lock: ToolchainLock = serde_json::from_str(&text)
            .map_err(|source| error(format!("decode {}: {source}", path.display())))?;
        // Schema 2 is the blake3 field set; schema 1 pinned the archives by
        // SHA-256 and cannot be read here.
        if lock.schema_version != 2 {
            return fail(format!(
                "toolchain lock schema_version must be 2, got {}",
                lock.schema_version
            ));
        }
        for writer in &lock.rar_writers {
            if !is_blake3_hex(&writer.blake3) || !writer.url.starts_with("https://") {
                return fail(format!("toolchain lock writer {} is not pinned", writer.id));
            }
        }
        // SHA-256 by specification: an OCI image reference pins its manifest
        // with `@sha256:<hex>`, which is the registry's digest form, not ours.
        if !lock.video_encoder.image.contains("@sha256:") {
            return fail("toolchain lock video encoder is not digest pinned");
        }
        Ok((lock, blake3_bytes(text.as_bytes())))
    }

    pub(crate) fn ids(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self
            .rar_writers
            .iter()
            .map(|writer| writer.id.clone())
            .collect();
        ids.insert(self.video_encoder.id.clone());
        ids.insert(self.par2_generator.id.clone());
        ids
    }
}

/// What the manifest records about the lock: enough to name every toolchain a
/// file was produced with, and to notice when the lock itself moved.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManifestToolchains {
    pub(crate) lock_path: String,
    pub(crate) lock_blake3: String,
    pub(crate) docker_base: String,
    pub(crate) rar_writers: BTreeMap<String, PinnedSource>,
    pub(crate) video_encoder: BTreeMap<String, String>,
    pub(crate) par2_generator: PinnedSource,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct PinnedSource {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) blake3: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManifestGenerator {
    pub(crate) path: String,
    pub(crate) toolchains: Vec<String>,
    pub(crate) byte_reproducible: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManifestUpstream {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) license: String,
    pub(crate) encoding: String,
    pub(crate) private: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManifestFile {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) blake3: String,
    pub(crate) format: String,
    /// `generated` or `upstream`; a `blocked` ledger entry never reaches a manifest.
    pub(crate) source_group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) generator: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) toolchains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream: Option<ManifestFileUpstream>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManifestFileUpstream {
    pub(crate) name: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) schema_version: u32,
    pub(crate) corpus: String,
    pub(crate) object_key_prefix: String,
    pub(crate) toolchains: ManifestToolchains,
    pub(crate) generators: BTreeMap<String, ManifestGenerator>,
    pub(crate) upstreams: BTreeMap<String, ManifestUpstream>,
    pub(crate) profiles: BTreeMap<String, Vec<String>>,
    pub(crate) files: Vec<ManifestFile>,
}

impl Manifest {
    /// Build the manifest. Refuses a ledger with blocked entries: nothing with
    /// incomplete provenance is ever described to a consumer.
    pub(crate) fn build(
        ledger: &Ledger,
        profiles: &ProfilesFile,
        lock: &ToolchainLock,
        lock_blake3: &str,
    ) -> Result<Self> {
        let blocked = ledger.blocked();
        if !blocked.is_empty() {
            let mut listed: Vec<String> = blocked.iter().map(|entry| entry.path.clone()).collect();
            listed.sort();
            return fail(format!(
                "{} ledger path(s) are blocked on incomplete provenance; the corpus cannot be built:\n  {}",
                listed.len(),
                listed.join("\n  ")
            ));
        }
        let resolved = profiles.resolve(&ledger.paths())?;
        let mut files: Vec<ManifestFile> = ledger
            .files
            .iter()
            .map(|entry| {
                let (source_group, generator, toolchains, upstream) = match &entry.source {
                    Source::Generated {
                        generator,
                        toolchains,
                        ..
                    } => (
                        "generated",
                        Some(generator.clone()),
                        toolchains.clone(),
                        None,
                    ),
                    Source::Upstream { upstream, path, .. } => (
                        "upstream",
                        None,
                        Vec::new(),
                        Some(ManifestFileUpstream {
                            name: upstream.clone(),
                            path: path.clone(),
                        }),
                    ),
                    Source::Blocked { .. } => unreachable!("blocked entries were rejected above"),
                };
                ManifestFile {
                    path: entry.path.clone(),
                    size: entry.size,
                    blake3: entry.blake3.clone(),
                    format: entry.format.clone(),
                    source_group: source_group.to_owned(),
                    generator,
                    toolchains,
                    upstream,
                }
            })
            .collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            corpus: CORPUS_NAME.to_owned(),
            object_key_prefix: super::OBJECTS_PREFIX.to_owned(),
            toolchains: ManifestToolchains {
                lock_path: ledger.toolchains.clone(),
                lock_blake3: lock_blake3.to_owned(),
                docker_base: lock.docker_base.clone(),
                rar_writers: lock
                    .rar_writers
                    .iter()
                    .map(|writer| {
                        (
                            writer.id.clone(),
                            PinnedSource {
                                id: writer.id.clone(),
                                url: writer.url.clone(),
                                blake3: writer.blake3.clone(),
                            },
                        )
                    })
                    .collect(),
                video_encoder: BTreeMap::from([
                    ("id".to_owned(), lock.video_encoder.id.clone()),
                    ("image".to_owned(), lock.video_encoder.image.clone()),
                    ("platform".to_owned(), lock.video_encoder.platform.clone()),
                ]),
                par2_generator: PinnedSource {
                    id: lock.par2_generator.id.clone(),
                    url: lock.par2_generator.url.clone(),
                    blake3: lock.par2_generator.blake3.clone(),
                },
            },
            generators: ledger
                .generators
                .iter()
                .map(|(name, generator)| {
                    (
                        name.clone(),
                        ManifestGenerator {
                            path: generator.path.clone(),
                            toolchains: generator.toolchains.clone(),
                            byte_reproducible: generator.byte_reproducible,
                        },
                    )
                })
                .collect(),
            upstreams: ledger
                .upstreams
                .iter()
                .map(|(name, upstream)| {
                    (
                        name.clone(),
                        ManifestUpstream {
                            repository: upstream.repository.clone(),
                            commit: upstream.commit.clone(),
                            license: upstream.license.clone(),
                            encoding: upstream.encoding.clone(),
                            private: upstream.private,
                        },
                    )
                })
                .collect(),
            profiles: resolved,
            files,
        })
    }

    /// Canonical bytes: sorted keys, no insignificant whitespace, `\n`
    /// terminated. The digest of these bytes is the manifest's address.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Round-trip through `Value` so every object's keys are sorted (the
        // crate's default `Value` map is ordered), independent of struct field
        // order.
        let value = serde_json::to_value(self)?;
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let manifest: Manifest = serde_json::from_slice(bytes)
            .map_err(|source| error(format!("decode manifest: {source}")))?;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
            return fail(format!(
                "manifest schema_version {} is not supported",
                manifest.schema_version
            ));
        }
        if manifest.corpus != CORPUS_NAME {
            return fail(format!(
                "manifest describes corpus {:?}, not {CORPUS_NAME}",
                manifest.corpus
            ));
        }
        if manifest.object_key_prefix != super::OBJECTS_PREFIX {
            return fail(format!(
                "manifest object_key_prefix {:?} is not {}",
                manifest.object_key_prefix,
                super::OBJECTS_PREFIX
            ));
        }
        let mut seen = BTreeSet::new();
        for file in &manifest.files {
            if !super::valid_repo_relative(&file.path)
                || !seen.insert(file.path.clone())
                || !is_blake3_hex(&file.blake3)
            {
                return fail(format!(
                    "manifest entry {:?} is malformed or duplicated",
                    file.path
                ));
            }
        }
        for (name, members) in &manifest.profiles {
            for member in members {
                if !seen.contains(member) {
                    return fail(format!(
                        "manifest profile {name} names {member:?}, which is not a manifest file"
                    ));
                }
            }
        }
        Ok(manifest)
    }

    pub(crate) fn file(&self, path: &str) -> Option<&ManifestFile> {
        self.files.iter().find(|file| file.path == path)
    }

    /// The files the named profiles hydrate, deduplicated and sorted.
    pub(crate) fn select(&self, profiles: &[String]) -> Result<Vec<&ManifestFile>> {
        let mut selected = BTreeSet::new();
        for name in profiles {
            let members = self.profiles.get(name).ok_or_else(|| {
                error(format!(
                    "profile {name:?} is not in the manifest (available: {})",
                    self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                ))
            })?;
            selected.extend(members.iter().cloned());
        }
        selected
            .iter()
            .map(|path| {
                self.file(path).ok_or_else(|| {
                    error(format!(
                        "manifest profile member {path:?} has no file entry"
                    ))
                })
            })
            .collect()
    }
}

/// Build metadata for one published manifest. Signed alongside it; never part
/// of the manifest, so the manifest stays recomputable from a checkout.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Provenance {
    pub(crate) schema_version: u32,
    pub(crate) corpus: String,
    pub(crate) manifest_blake3: String,
    pub(crate) toolchain_lock_blake3: String,
    pub(crate) built_at: String,
    pub(crate) source: ProvenanceSource,
    pub(crate) file_count: usize,
    pub(crate) total_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ProvenanceSource {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) ref_name: String,
    pub(crate) workflow_ref: String,
    pub(crate) run_url: String,
    pub(crate) run_attempt: String,
    pub(crate) actor: String,
}

impl Provenance {
    /// Fill from the GitHub Actions environment when present; a local build
    /// records `local` so it can never be mistaken for a workflow publication.
    pub(crate) fn from_environment(
        manifest: &Manifest,
        manifest_blake3: &str,
        lock_blake3: &str,
    ) -> Self {
        let env = |name: &str| std::env::var(name).unwrap_or_default();
        let server = if env("GITHUB_SERVER_URL").is_empty() {
            "https://github.com".to_owned()
        } else {
            env("GITHUB_SERVER_URL")
        };
        let repository = env("GITHUB_REPOSITORY");
        let run_id = env("GITHUB_RUN_ID");
        let run_url = if repository.is_empty() || run_id.is_empty() {
            "local".to_owned()
        } else {
            format!("{server}/{repository}/actions/runs/{run_id}")
        };
        let or_local = |value: String| {
            if value.is_empty() {
                "local".to_owned()
            } else {
                value
            }
        };
        Provenance {
            schema_version: 1,
            corpus: CORPUS_NAME.to_owned(),
            manifest_blake3: manifest_blake3.to_owned(),
            toolchain_lock_blake3: lock_blake3.to_owned(),
            built_at: super::utc_now_rfc3339(),
            source: ProvenanceSource {
                repository: or_local(repository),
                commit: or_local(env("GITHUB_SHA")),
                ref_name: or_local(env("GITHUB_REF")),
                workflow_ref: or_local(env("GITHUB_WORKFLOW_REF")),
                run_url,
                run_attempt: or_local(env("GITHUB_RUN_ATTEMPT")),
                actor: or_local(env("GITHUB_ACTOR")),
            },
            file_count: manifest.files.len(),
            total_bytes: manifest.files.iter().map(|file| file.size).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_corpus::ledger::Source;
    use crate::test_corpus::ledger::tests::{sample_ledger, sample_lock};

    fn sample_profiles() -> ProfilesFile {
        serde_json::from_str(
            r#"{"schema_version":1,"profiles":{
                "rar12":{"include":["f/rar4/rar15_lz.rar"]},
                "rar57":{"include":["f/rar5/**"]},
                "all":{"include":["f/**"]}
            }}"#,
        )
        .unwrap()
    }

    #[test]
    fn manifest_is_canonical_and_a_pure_function_of_its_inputs() {
        let ledger = sample_ledger();
        let lock = sample_lock();
        let first = Manifest::build(&ledger, &sample_profiles(), &lock, "ab").unwrap();
        let second = Manifest::build(&ledger, &sample_profiles(), &lock, "ab").unwrap();
        let bytes = first.canonical_bytes().unwrap();
        assert_eq!(bytes, second.canonical_bytes().unwrap());
        assert!(bytes.ends_with(b"\n"));
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains(": "),
            "canonical JSON has no insignificant whitespace"
        );
        // Sorted keys at every level: "blake3" precedes "path" inside a file entry.
        assert!(text.find("\"corpus\"").unwrap() < text.find("\"files\"").unwrap());
        assert!(
            text.find("\"blake3\":\"af13").unwrap()
                < text.find("\"path\":\"f/rar4/rar15_lz.rar\"").unwrap()
        );
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed, first);
        assert_eq!(
            parsed.canonical_bytes().unwrap(),
            bytes,
            "parse/serialize is a fixed point"
        );

        // A ledger with a different note is the same manifest; a different
        // digest is a different manifest.
        let mut noted = ledger.clone();
        if let Source::Generated { notes, .. } = &mut noted.files[0].source {
            *notes = "regenerated on a Tuesday".into();
        }
        assert_eq!(
            Manifest::build(&noted, &sample_profiles(), &lock, "ab")
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            bytes
        );
        let mut changed = ledger.clone();
        changed.files[0].blake3 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert_ne!(
            Manifest::build(&changed, &sample_profiles(), &lock, "ab")
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn manifest_records_provenance_groups_and_profiles() {
        let manifest =
            Manifest::build(&sample_ledger(), &sample_profiles(), &sample_lock(), "ab").unwrap();
        let generated = manifest.file("f/rar5/a.rar").unwrap();
        assert_eq!(generated.source_group, "generated");
        assert_eq!(generated.generator.as_deref(), Some("gen.sh"));
        assert_eq!(generated.toolchains, vec!["rarlab-7.20"]);
        assert!(generated.upstream.is_none());
        let imported = manifest.file("f/rar4/rar15_lz.rar").unwrap();
        assert_eq!(imported.source_group, "upstream");
        assert!(imported.generator.is_none() && imported.toolchains.is_empty());
        assert_eq!(imported.upstream.as_ref().unwrap().name, "junrar");
        assert_eq!(manifest.profiles["rar12"], vec!["f/rar4/rar15_lz.rar"]);
        assert_eq!(manifest.profiles["all"].len(), 2);
        assert_eq!(manifest.toolchains.rar_writers.len(), 2);
        assert_eq!(manifest.toolchains.lock_blake3, "ab");
        let selected = manifest.select(&["rar12".into(), "rar57".into()]).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(manifest.select(&["nope".into()]).is_err());
    }

    #[test]
    fn blocked_entries_stop_the_build() {
        let mut ledger = sample_ledger();
        ledger.files[0].source = Source::Blocked {
            reason: "urandom input, no generator".into(),
        };
        let err = Manifest::build(&ledger, &sample_profiles(), &sample_lock(), "ab")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked on incomplete provenance"), "{err}");
        assert!(err.contains("f/rar5/a.rar"), "{err}");
    }

    #[test]
    fn parse_rejects_foreign_or_inconsistent_manifests() {
        let manifest =
            Manifest::build(&sample_ledger(), &sample_profiles(), &sample_lock(), "ab").unwrap();
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["corpus"] = serde_json::Value::String("other".into());
        assert!(Manifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["profiles"]["rar12"] = serde_json::json!(["f/not/listed.rar"]);
        assert!(Manifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["object_key_prefix"] = serde_json::Value::String("elsewhere/".into());
        assert!(Manifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn provenance_outside_actions_says_local() {
        let manifest =
            Manifest::build(&sample_ledger(), &sample_profiles(), &sample_lock(), "ab").unwrap();
        // Tests may run inside Actions; only assert the shape and the counts.
        let provenance = Provenance::from_environment(&manifest, "cd", "ab");
        assert_eq!(provenance.manifest_blake3, "cd");
        assert_eq!(provenance.file_count, 2);
        assert_eq!(provenance.total_bytes, 3);
        assert!(!provenance.source.run_url.is_empty());
    }
}
