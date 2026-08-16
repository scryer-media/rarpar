//! Sigstore through `cosign`.
//!
//! The manifest and provenance the publish workflow uploads are signed keyless
//! with the workflow's GitHub OIDC identity; consumers verify the bundle with
//! the exact workflow identity and issuer pinned in `lock.json`. `cosign` is
//! the reference implementation and the only signer/verifier used here.

use std::path::Path;
use std::process::{Command, Stdio};

use super::{Result, error, fail};

pub(crate) const COSIGN_ENV: &str = "RARPAR_COSIGN";

pub(crate) fn cosign_binary() -> String {
    std::env::var(COSIGN_ENV).unwrap_or_else(|_| "cosign".to_owned())
}

pub(crate) fn cosign_available() -> bool {
    Command::new(cosign_binary())
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The exact `cosign verify-blob` invocation. Pure so the identity pinning can
/// be asserted; the identity is matched exactly (`--certificate-identity`),
/// never by regexp, so a workflow on another branch or in a fork can never
/// satisfy it.
pub(crate) fn verify_args(blob: &Path, bundle: &Path, identity: &str, issuer: &str) -> Vec<String> {
    vec![
        "verify-blob".into(),
        "--bundle".into(),
        bundle.to_string_lossy().into_owned(),
        "--certificate-identity".into(),
        identity.into(),
        "--certificate-oidc-issuer".into(),
        issuer.into(),
        blob.to_string_lossy().into_owned(),
    ]
}

pub(crate) fn verify_blob(blob: &Path, bundle: &Path, identity: &str, issuer: &str) -> Result<()> {
    let output = Command::new(cosign_binary())
        .args(verify_args(blob, bundle, identity, issuer))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| error(format!("run cosign: {source}")))?;
    if !output.status.success() {
        return fail(format!(
            "cosign verify-blob rejected {} (bundle {}, identity {identity}, issuer {issuer}): {}",
            blob.display(),
            bundle.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub(crate) fn sign_args(blob: &Path, bundle: &Path) -> Vec<String> {
    vec![
        "sign-blob".into(),
        "--yes".into(),
        "--bundle".into(),
        bundle.to_string_lossy().into_owned(),
        blob.to_string_lossy().into_owned(),
    ]
}

/// Keyless signing under the ambient OIDC identity (GitHub Actions supplies it
/// through `ACTIONS_ID_TOKEN_REQUEST_URL`). Writes a Sigstore bundle.
pub(crate) fn sign_blob(blob: &Path, bundle: &Path) -> Result<()> {
    let output = Command::new(cosign_binary())
        .args(sign_args(blob, bundle))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| error(format!("run cosign: {source}")))?;
    if !output.status.success() {
        return fail(format!(
            "cosign sign-blob failed for {}: {}",
            blob.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !bundle.is_file() {
        return fail(format!(
            "cosign sign-blob wrote no bundle at {}",
            bundle.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn verification_pins_the_exact_identity_and_issuer() {
        let args = verify_args(
            Path::new("manifest.json"),
            Path::new("manifest.json.sigstore.json"),
            "https://github.com/scryer-media/rarpar/.github/workflows/test-corpus-publish.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        );
        assert_eq!(args[0], "verify-blob");
        assert!(args.contains(&"--certificate-identity".to_owned()));
        assert!(
            !args.iter().any(|arg| arg.contains("regexp")),
            "identity is exact, never a regexp"
        );
        assert_eq!(args.last().map(String::as_str), Some("manifest.json"));
        let signing = sign_args(Path::new("m.json"), Path::new("m.json.sigstore.json"));
        assert_eq!(signing[..2], ["sign-blob".to_owned(), "--yes".to_owned()]);
    }

    fn stub_cosign(dir: &Path, exit_code: i32) -> PathBuf {
        let stub = dir.join(if cfg!(windows) {
            "cosign.cmd"
        } else {
            "cosign"
        });
        if cfg!(windows) {
            fs::write(
                &stub,
                format!(
                    "@echo off\r\necho %* > \"{}\"\r\nif \"%1\"==\"sign-blob\" type nul > \"%~4\"\r\nexit /b {exit_code}\r\n",
                    dir.join("args.txt").display()
                ),
            )
            .unwrap();
        } else {
            fs::write(
                &stub,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncase \"$1\" in sign-blob) : > \"$4\";; esac\nexit {exit_code}\n",
                    dir.join("args.txt").display()
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        stub
    }

    #[test]
    fn cosign_outcomes_are_surfaced() {
        let dir = std::env::temp_dir().join(format!("xtask-corpus-cosign-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let _guard = crate::test_corpus::curl::tests::ENV_LOCK.lock().unwrap();

        let ok = stub_cosign(&dir, 0);
        unsafe { std::env::set_var(COSIGN_ENV, &ok) };
        assert!(cosign_available());
        verify_blob(&dir.join("blob"), &dir.join("bundle"), "id", "issuer").unwrap();
        let args = fs::read_to_string(dir.join("args.txt")).unwrap();
        assert!(
            args.contains("verify-blob")
                && args.contains("--certificate-identity")
                && args.contains("id"),
            "{args}"
        );
        sign_blob(&dir.join("blob"), &dir.join("blob.sigstore.json")).unwrap();
        assert!(dir.join("blob.sigstore.json").is_file());

        fs::create_dir_all(dir.join("bad")).unwrap();
        let bad = stub_cosign(dir.join("bad").as_path(), 1);
        unsafe { std::env::set_var(COSIGN_ENV, &bad) };
        assert!(!cosign_available());
        let err = verify_blob(&dir.join("blob"), &dir.join("bundle"), "id", "issuer")
            .unwrap_err()
            .to_string();
        assert!(err.contains("rejected"), "{err}");
        assert!(sign_blob(&dir.join("blob"), &dir.join("blob2.sigstore.json")).is_err());

        unsafe { std::env::set_var(COSIGN_ENV, dir.join("does-not-exist")) };
        assert!(!cosign_available());
        assert!(verify_blob(&dir.join("blob"), &dir.join("bundle"), "id", "issuer").is_err());
        unsafe { std::env::remove_var(COSIGN_ENV) };
        let _ = fs::remove_dir_all(&dir);
    }
}
