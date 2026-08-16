//! A small glob matcher over `/`-separated repository paths.
//!
//! Supported: `**` as a whole path component (zero or more components), `*`
//! (any run of non-`/` characters within a component), `?` (one non-`/`
//! character), and literal characters. That is exactly the vocabulary the CI
//! hydration profiles used with `git lfs pull --include`, so the profiles read
//! the same way they always did.

pub(crate) fn matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    match_components(&pattern, &path)
}

fn match_components(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => {
            // `**` may swallow zero or more path components.
            (0..=path.len()).any(|skip| match_components(rest, &path[skip..]))
        }
        Some((head, rest)) => match path.split_first() {
            None => false,
            Some((component, remaining)) => {
                match_component(head.as_bytes(), component.as_bytes())
                    && match_components(rest, remaining)
            }
        },
    }
}

fn match_component(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| match_component(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && match_component(rest, &text[1..]),
        Some((literal, rest)) => text.first() == Some(literal) && match_component(rest, &text[1..]),
    }
}

/// A pattern is "well-formed" when every `**` stands alone as a component; a
/// `**` glued to other characters is almost always a typo for `*`.
pub(crate) fn well_formed(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.starts_with('/')
        && !pattern.ends_with('/')
        && !pattern.contains("//")
        && pattern
            .split('/')
            .all(|component| component == "**" || !component.contains("**"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_like_the_lfs_include_patterns_did() {
        assert!(matches(
            "crates/unrar-rs/tests/fixtures/**",
            "crates/unrar-rs/tests/fixtures/rar5/a.rar"
        ));
        assert!(matches(
            "crates/unrar-rs/tests/fixtures/**",
            "crates/unrar-rs/tests/fixtures/README.md"
        ));
        assert!(!matches(
            "crates/unrar-rs/tests/fixtures/**",
            "crates/par2-rs/tests/fixtures/x.par2"
        ));
        assert!(matches(
            "crates/par2-rs/tests/fixtures/rar5_lz_plain/**",
            "crates/par2-rs/tests/fixtures/rar5_lz_plain/a.part1.rar"
        ));
        assert!(matches(
            "a/rar5_enc_mv_store.part*.rar",
            "a/rar5_enc_mv_store.part3.rar"
        ));
        assert!(!matches(
            "a/rar5_enc_mv_store.part*.rar",
            "a/rar5_enc_mv_store.rar"
        ));
        assert!(matches("a/rar4_ppm_oldmv*", "a/rar4_ppm_oldmv.r02"));
        assert!(matches("a/rar4_ppm_oldmv*", "a/rar4_ppm_oldmv.rar"));
        assert!(matches("a/x?.rar", "a/x1.rar"));
        assert!(!matches("a/x?.rar", "a/x12.rar"));
        assert!(matches("a/**/b.rar", "a/b.rar"));
        assert!(matches("a/**/b.rar", "a/x/y/b.rar"));
        assert!(!matches("a/*.rar", "a/b/c.rar"), "* must not cross a slash");
        assert!(matches("exact/path.rar", "exact/path.rar"));
        assert!(!matches("exact/path.rar", "exact/path.rar.bak"));
    }

    #[test]
    fn well_formedness_rejects_glued_double_stars_and_absolute_patterns() {
        assert!(well_formed("a/**"));
        assert!(well_formed("a/*.rar"));
        assert!(!well_formed("a/**.rar"));
        assert!(!well_formed("/a"));
        assert!(!well_formed("a/"));
        assert!(!well_formed(""));
        assert!(!well_formed("a//b"));
    }
}
