//! Re-fetching public upstream imports at their pinned commits and requiring
//! byte identity — the publish workflow's proof that an `upstream` entry really
//! is the immutable upstream file it claims to be.

use std::collections::BTreeMap;

use super::ledger::{Ledger, Source, Upstream};
use super::{Result, blake3_bytes, fail, http};

/// The raw-content URL for a file at a pinned commit of a GitHub repository.
pub(crate) fn raw_url(upstream: &Upstream, path: &str) -> Result<String> {
    let repository = upstream
        .repository
        .trim_end_matches('/')
        .trim_end_matches(".git");
    let Some(slug) = repository.strip_prefix("https://github.com/") else {
        return fail(format!(
            "upstream {} is not a github.com repository; add a fetcher before verifying it",
            upstream.repository
        ));
    };
    if slug.split('/').count() != 2 {
        return fail(format!(
            "upstream repository {:?} is not owner/repo",
            upstream.repository
        ));
    }
    Ok(format!(
        "https://raw.githubusercontent.com/{slug}/{}/{path}",
        upstream.commit
    ))
}

/// Decode one uuencoded file (the classic `begin <mode> <name>` … `end` form
/// libarchive stores its test archives in). Only the first member is decoded.
pub(crate) fn uudecode(text: &[u8]) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(text).map_err(|_| super::error("uuencoded text is not UTF-8"))?;
    let mut lines = text.lines();
    loop {
        match lines.next() {
            None => return fail("uuencoded input has no begin line"),
            Some(line) if line.starts_with("begin ") => break,
            Some(_) => {}
        }
    }
    let mut out = Vec::new();
    for line in lines {
        if line == "end" {
            return Ok(out);
        }
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let length = (bytes[0].wrapping_sub(32) & 0x3f) as usize;
        if length == 0 {
            // A "`" line marks the end of data.
            continue;
        }
        let mut decoded = Vec::with_capacity(length + 3);
        let data = &bytes[1..];
        for chunk in data.chunks(4) {
            let mut quad = [0u8; 4];
            for (index, value) in chunk.iter().enumerate() {
                quad[index] = value.wrapping_sub(32) & 0x3f;
            }
            decoded.push((quad[0] << 2) | (quad[1] >> 4));
            decoded.push((quad[1] << 4) | (quad[2] >> 2));
            decoded.push((quad[2] << 6) | quad[3]);
        }
        if decoded.len() < length {
            return fail("uuencoded line is shorter than its declared length");
        }
        out.extend_from_slice(&decoded[..length]);
    }
    fail("uuencoded input has no end line")
}

/// One upstream file's verification outcome.
#[derive(Debug)]
pub(crate) struct UpstreamCheck {
    pub(crate) path: String,
    pub(crate) upstream: String,
    pub(crate) outcome: std::result::Result<(), String>,
}

/// Fetch every file imported from a public upstream at its pinned commit and
/// compare digests. Private upstreams are reported as skipped (their imports
/// are verified against the checkout by the ordinary ledger checks).
pub(crate) fn verify_public_upstreams(ledger: &Ledger) -> Vec<UpstreamCheck> {
    let mut checks = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &ledger.files {
        let Source::Upstream { upstream, path, .. } = &entry.source else {
            continue;
        };
        let Some(declared) = ledger.upstreams.get(upstream) else {
            checks.push(UpstreamCheck {
                path: entry.path.clone(),
                upstream: upstream.clone(),
                outcome: Err(format!("upstream {upstream:?} is not declared")),
            });
            continue;
        };
        if declared.private {
            *counts.entry(upstream.as_str()).or_default() += 1;
            continue;
        }
        let outcome = (|| -> Result<()> {
            let url = raw_url(declared, path)?;
            let fetched = http::get_to_vec(&url)?;
            let bytes = match declared.encoding.as_str() {
                "raw" => fetched,
                "uuencode" => uudecode(&fetched)?,
                other => {
                    return fail(format!(
                        "cannot verify encoding {other:?} for a public upstream"
                    ));
                }
            };
            let digest = blake3_bytes(&bytes);
            if digest != entry.blake3 || bytes.len() as u64 != entry.size {
                return fail(format!(
                    "upstream bytes at {url} hash to {digest} ({} bytes); ledger says {} ({} bytes)",
                    bytes.len(),
                    entry.blake3,
                    entry.size
                ));
            }
            Ok(())
        })();
        checks.push(UpstreamCheck {
            path: entry.path.clone(),
            upstream: upstream.clone(),
            outcome: outcome.map_err(|err| err.to_string()),
        });
    }
    for (upstream, count) in counts {
        eprintln!(
            "test-corpus: {count} import(s) from private upstream {upstream} are pinned by commit and verified from the checkout, not re-fetched"
        );
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_urls_pin_the_commit() {
        let upstream = Upstream {
            repository: "https://github.com/libarchive/libarchive".into(),
            commit: "27cbc7827172698143e440801fc0ba39ccb4f1f5".into(),
            license: "BSD-2-Clause".into(),
            license_path: "COPYING".into(),
            encoding: "uuencode".into(),
            private: false,
            notes: String::new(),
        };
        assert_eq!(
            raw_url(&upstream, "libarchive/test/test_read_format_rar.rar.uu").unwrap(),
            "https://raw.githubusercontent.com/libarchive/libarchive/27cbc7827172698143e440801fc0ba39ccb4f1f5/libarchive/test/test_read_format_rar.rar.uu"
        );
        let mut other = upstream.clone();
        other.repository = "https://gitlab.com/x/y".into();
        assert!(raw_url(&other, "a").is_err());
    }

    #[test]
    fn uudecode_round_trips_a_known_encoding() {
        // `printf 'Cat' | uuencode -` style output.
        let encoded = b"begin 644 cat.txt\n#0V%T\n`\nend\n";
        assert_eq!(uudecode(encoded).unwrap(), b"Cat");
        let encoded = b"begin 644 x\n,2&5L;&\\L('=O<FQD\n`\nend\n";
        assert_eq!(uudecode(encoded).unwrap(), b"Hello, world");
        assert!(uudecode(b"no begin\n").is_err());
        assert!(uudecode(b"begin 644 x\n#0V%T\n").is_err(), "missing end");
    }
}
