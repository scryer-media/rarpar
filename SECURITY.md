# Security Policy

## Supported Versions

Security fixes are provided for `main` and the current `0.4.x` version series.
Older versions should be upgraded before reporting an issue.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting feature for
[`scryer-media/rarpar`](https://github.com/scryer-media/rarpar/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include the affected version or commit, a minimal reproduction, the security
impact, and any mitigations already identified. We will acknowledge reports
within seven days and coordinate disclosure after a fix is available.

## Scope

The `rarpar` CLI and the `reedsolomon-rs`, `unrar-rs`, and `par2-rs` crates are
in scope. Third-party RAR files and PAR2 files should be treated as untrusted
input; reports involving parser crashes, resource exhaustion, path escapes, or
unexpected writes are especially useful.
