//! `test-corpus/profiles.json`: named subsets (bundles) of the corpus.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Result, fail, glob, read_to_string};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfilesFile {
    pub(crate) schema_version: u32,
    pub(crate) profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    /// Human-facing purpose: which lane or task hydrates this profile.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) description: String,
    pub(crate) include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) exclude: Vec<String>,
}

impl ProfilesFile {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let profiles: ProfilesFile = serde_json::from_str(&read_to_string(path)?)
            .map_err(|source| super::error(format!("decode {}: {source}", path.display())))?;
        profiles.validate()?;
        Ok(profiles)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return fail(format!(
                "profiles schema_version must be 1, got {}",
                self.schema_version
            ));
        }
        if self.profiles.is_empty() {
            return fail("profiles.json declares no profiles");
        }
        for (name, profile) in &self.profiles {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return fail(format!(
                    "profile name {name:?} must be lowercase letters, digits and dashes"
                ));
            }
            if profile.include.is_empty() {
                return fail(format!("profile {name} includes nothing"));
            }
            for pattern in profile.include.iter().chain(&profile.exclude) {
                if !glob::well_formed(pattern) {
                    return fail(format!(
                        "profile {name} has a malformed pattern {pattern:?}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Resolve every profile against the ledger's paths. A profile that
    /// matches nothing is a configuration error: a lane would hydrate nothing
    /// and its tests would silently skip.
    pub(crate) fn resolve(
        &self,
        paths: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, Vec<String>>> {
        let mut resolved = BTreeMap::new();
        for (name, profile) in &self.profiles {
            let members: Vec<String> = paths
                .iter()
                .filter(|path| {
                    profile
                        .include
                        .iter()
                        .any(|pattern| glob::matches(pattern, path))
                })
                .filter(|path| {
                    !profile
                        .exclude
                        .iter()
                        .any(|pattern| glob::matches(pattern, path))
                })
                .cloned()
                .collect();
            if members.is_empty() {
                return fail(format!("profile {name} resolves to no ledger paths"));
            }
            for pattern in &profile.include {
                if !paths.iter().any(|path| glob::matches(pattern, path)) {
                    return fail(format!(
                        "profile {name}: include pattern {pattern:?} matches no ledger path"
                    ));
                }
            }
            resolved.insert(name.clone(), members);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|path| (*path).to_owned()).collect()
    }

    fn profiles(json: &str) -> ProfilesFile {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn profiles_resolve_with_includes_and_excludes() {
        let file = profiles(
            r#"{"schema_version":1,"profiles":{
                "rar12":{"include":["f/rar4/rar15_lz.rar","f/rar4/rar20_*.rar","f/originals/**"]},
                "rar34":{"include":["f/rar4/**","f/originals/**"],"exclude":["f/rar4/rar15_lz.rar","f/rar4/rar20_*.rar"]},
                "rar57":{"include":["f/rar5/**"]}
            }}"#,
        );
        file.validate().unwrap();
        let ledger = paths(&[
            "f/rar4/rar15_lz.rar",
            "f/rar4/rar20_lz.rar",
            "f/rar4/rar4_store.rar",
            "f/rar5/rar5_store.rar",
            "f/originals/hello.bin",
        ]);
        let resolved = file.resolve(&ledger).unwrap();
        assert_eq!(
            resolved["rar12"],
            vec![
                "f/originals/hello.bin",
                "f/rar4/rar15_lz.rar",
                "f/rar4/rar20_lz.rar"
            ]
        );
        assert_eq!(
            resolved["rar34"],
            vec!["f/originals/hello.bin", "f/rar4/rar4_store.rar"]
        );
        assert_eq!(resolved["rar57"], vec!["f/rar5/rar5_store.rar"]);
    }

    #[test]
    fn empty_and_dead_patterns_are_rejected() {
        let file =
            profiles(r#"{"schema_version":1,"profiles":{"unit":{"include":["f/missing.rar"]}}}"#);
        file.validate().unwrap();
        assert!(file.resolve(&paths(&["f/present.rar"])).is_err());
        let file = profiles(
            r#"{"schema_version":1,"profiles":{"unit":{"include":["f/**"],"exclude":["f/**"]}}}"#,
        );
        assert!(
            file.resolve(&paths(&["f/present.rar"])).is_err(),
            "everything excluded must fail"
        );
        assert!(
            profiles(r#"{"schema_version":1,"profiles":{"Unit":{"include":["f/**"]}}}"#)
                .validate()
                .is_err()
        );
        assert!(
            profiles(r#"{"schema_version":1,"profiles":{"unit":{"include":[]}}}"#)
                .validate()
                .is_err()
        );
        assert!(
            profiles(r#"{"schema_version":1,"profiles":{"unit":{"include":["f/**.rar"]}}}"#)
                .validate()
                .is_err()
        );
        assert!(
            profiles(r#"{"schema_version":2,"profiles":{"unit":{"include":["f/**"]}}}"#)
                .validate()
                .is_err()
        );
    }
}
