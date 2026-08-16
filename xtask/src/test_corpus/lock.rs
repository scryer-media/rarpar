//! `test-corpus/lock.json`: which published manifest a checkout hydrates from.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{MANIFESTS_PREFIX, OBJECTS_PREFIX, Result, error, fail, is_sha256_hex, read_to_string};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lock {
    pub(crate) schema_version: u32,
    /// Public read base, e.g. `https://corpus.example.net` (no trailing slash).
    pub(crate) base_url: String,
    pub(crate) manifest: Pinned,
    pub(crate) signature: Signature,
    pub(crate) provenance: Pinned,
    pub(crate) published_from: PublishedFrom,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pinned {
    pub(crate) sha256: String,
    pub(crate) url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signature {
    pub(crate) bundle_url: String,
    /// The exact workflow identity `cosign verify-blob` must find in the
    /// signing certificate: the publish workflow file on `refs/heads/main`.
    pub(crate) certificate_identity: String,
    pub(crate) certificate_oidc_issuer: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublishedFrom {
    pub(crate) commit: String,
    pub(crate) run: String,
}

pub(crate) const PUBLISH_WORKFLOW_IDENTITY: &str = "https://github.com/scryer-media/rarpar/.github/workflows/test-corpus-publish.yml@refs/heads/main";
pub(crate) const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

impl Lock {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let lock: Lock = serde_json::from_str(&read_to_string(path)?)
            .map_err(|source| error(format!("decode {}: {source}", path.display())))?;
        lock.validate()?;
        Ok(lock)
    }

    /// True until an operator has published a corpus and a reviewed PR pinned
    /// it. While unpublished, `fetch` refuses and CI keeps its LFS hydration.
    pub(crate) fn is_unpublished(&self) -> bool {
        self.manifest.sha256.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return fail(format!(
                "lock schema_version must be 1, got {}",
                self.schema_version
            ));
        }
        if self.signature.certificate_identity != PUBLISH_WORKFLOW_IDENTITY {
            return fail(format!(
                "lock certificate_identity must be {PUBLISH_WORKFLOW_IDENTITY}, got {:?}",
                self.signature.certificate_identity
            ));
        }
        if self.signature.certificate_oidc_issuer != GITHUB_OIDC_ISSUER {
            return fail(format!(
                "lock certificate_oidc_issuer must be {GITHUB_OIDC_ISSUER}, got {:?}",
                self.signature.certificate_oidc_issuer
            ));
        }
        if self.is_unpublished() {
            // Nothing else may be set on an unpublished lock: half-filled locks
            // are how a stale URL sneaks past review.
            if !self.base_url.is_empty()
                || !self.manifest.url.is_empty()
                || !self.provenance.sha256.is_empty()
                || !self.provenance.url.is_empty()
                || !self.signature.bundle_url.is_empty()
                || !self.published_from.commit.is_empty()
                || !self.published_from.run.is_empty()
            {
                return fail("lock has no manifest digest but carries other publication fields");
            }
            return Ok(());
        }
        // https only — except loopback, which is no network exposure and is
        // how the fetch path is exercised end to end in tests.
        let loopback = self.base_url.starts_with("http://127.0.0.1:")
            || self.base_url.starts_with("http://localhost:");
        if !(self.base_url.starts_with("https://") || loopback) || self.base_url.ends_with('/') {
            return fail(format!(
                "lock base_url must be an https URL without a trailing slash, got {:?}",
                self.base_url
            ));
        }
        if !is_sha256_hex(&self.manifest.sha256) || !is_sha256_hex(&self.provenance.sha256) {
            return fail("lock manifest/provenance sha256 must be lowercase 64-hex");
        }
        let expected_manifest = self.manifest_url();
        if self.manifest.url != expected_manifest {
            return fail(format!(
                "lock manifest url must be {expected_manifest}, got {:?}",
                self.manifest.url
            ));
        }
        let expected_bundle = format!("{expected_manifest}.sigstore.json");
        if self.signature.bundle_url != expected_bundle {
            return fail(format!(
                "lock bundle url must be {expected_bundle}, got {:?}",
                self.signature.bundle_url
            ));
        }
        let expected_provenance = self.provenance_url();
        if self.provenance.url != expected_provenance {
            return fail(format!(
                "lock provenance url must be {expected_provenance}, got {:?}",
                self.provenance.url
            ));
        }
        if self.published_from.commit.len() != 40
            || !self
                .published_from
                .commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return fail("lock published_from.commit must be a full commit SHA");
        }
        if !self.published_from.run.starts_with("https://") {
            return fail("lock published_from.run must be the workflow run URL");
        }
        Ok(())
    }

    pub(crate) fn manifest_url(&self) -> String {
        format!(
            "{}/{MANIFESTS_PREFIX}{}.json",
            self.base_url, self.manifest.sha256
        )
    }

    pub(crate) fn provenance_url(&self) -> String {
        format!(
            "{}/{MANIFESTS_PREFIX}{}.provenance.json",
            self.base_url, self.manifest.sha256
        )
    }

    pub(crate) fn object_url(&self, sha256: &str) -> String {
        format!("{}/{OBJECTS_PREFIX}{sha256}", self.base_url)
    }

    /// The lock entry a publication produces, ready to paste.
    pub(crate) fn published(
        base_url: &str,
        manifest_sha256: &str,
        provenance_sha256: &str,
        commit: &str,
        run: &str,
    ) -> Self {
        let mut lock = Lock {
            schema_version: 1,
            base_url: base_url.trim_end_matches('/').to_owned(),
            manifest: Pinned {
                sha256: manifest_sha256.to_owned(),
                url: String::new(),
            },
            signature: Signature {
                bundle_url: String::new(),
                certificate_identity: PUBLISH_WORKFLOW_IDENTITY.to_owned(),
                certificate_oidc_issuer: GITHUB_OIDC_ISSUER.to_owned(),
            },
            provenance: Pinned {
                sha256: provenance_sha256.to_owned(),
                url: String::new(),
            },
            published_from: PublishedFrom {
                commit: commit.to_owned(),
                run: run.to_owned(),
            },
        };
        lock.manifest.url = lock.manifest_url();
        lock.signature.bundle_url = format!("{}.sigstore.json", lock.manifest_url());
        lock.provenance.url = lock.provenance_url();
        lock
    }

    pub(crate) fn render(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const OTHER: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn a_published_lock_derives_and_checks_its_urls() {
        let lock = Lock::published(
            "https://corpus.example.net/",
            DIGEST,
            OTHER,
            "0123456789abcdef0123456789abcdef01234567",
            "https://github.com/scryer-media/rarpar/actions/runs/1",
        );
        lock.validate().unwrap();
        assert!(!lock.is_unpublished());
        assert_eq!(
            lock.manifest.url,
            format!("https://corpus.example.net/test-corpus/manifests/sha256/{DIGEST}.json")
        );
        assert_eq!(
            lock.signature.bundle_url,
            format!("{}.sigstore.json", lock.manifest.url)
        );
        assert_eq!(
            lock.provenance.url,
            format!(
                "https://corpus.example.net/test-corpus/manifests/sha256/{DIGEST}.provenance.json"
            )
        );
        assert_eq!(
            lock.object_url(OTHER),
            format!("https://corpus.example.net/test-corpus/objects/sha256/{OTHER}")
        );
        let reparsed: Lock = serde_json::from_str(&lock.render().unwrap()).unwrap();
        assert_eq!(reparsed, lock);

        let mut tampered = lock.clone();
        tampered.manifest.url = "https://elsewhere.example.net/manifest.json".into();
        assert!(
            tampered.validate().is_err(),
            "a manifest URL off the base is rejected"
        );
        let mut tampered = lock.clone();
        tampered.signature.certificate_identity =
            "https://github.com/someone-else/repo/.github/workflows/x.yml@refs/heads/main".into();
        assert!(
            tampered.validate().is_err(),
            "another signer identity is rejected"
        );
        let mut tampered = lock.clone();
        tampered.signature.certificate_oidc_issuer = "https://accounts.google.com".into();
        assert!(tampered.validate().is_err(), "another issuer is rejected");
        let mut tampered = lock.clone();
        tampered.base_url = "http://corpus.example.net".into();
        tampered.manifest.url = tampered.manifest_url();
        tampered.signature.bundle_url = format!("{}.sigstore.json", tampered.manifest_url());
        tampered.provenance.url = tampered.provenance_url();
        assert!(tampered.validate().is_err(), "plain http is rejected");
    }

    #[test]
    fn an_unpublished_lock_is_empty_and_only_empty() {
        let text = format!(
            r#"{{"schema_version":1,"base_url":"","manifest":{{"sha256":"","url":""}},"signature":{{"bundle_url":"","certificate_identity":"{PUBLISH_WORKFLOW_IDENTITY}","certificate_oidc_issuer":"{GITHUB_OIDC_ISSUER}"}},"provenance":{{"sha256":"","url":""}},"published_from":{{"commit":"","run":""}}}}"#
        );
        let lock: Lock = serde_json::from_str(&text).unwrap();
        lock.validate().unwrap();
        assert!(lock.is_unpublished());
        let mut half = lock.clone();
        half.published_from.commit = "0123456789abcdef0123456789abcdef01234567".into();
        assert!(
            half.validate().is_err(),
            "half-filled unpublished lock is rejected"
        );
        let mut stale_base = lock.clone();
        stale_base.base_url = "https://corpus.example.net".into();
        assert!(
            stale_base.validate().is_err(),
            "an unpublished lock carrying a base URL is rejected"
        );
    }
}
