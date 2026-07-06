# Contributing to rarpar

## Prerequisites

- Rust (stable toolchain) + Cargo
- `gitleaks` for local pre-commit secret scanning

## Git Hooks

After cloning, run:

```bash
git config core.hooksPath .githooks
```

The versioned `pre-commit` hook blocks commits when `gitleaks` reports staged
secrets or when staged diffs contain machine-local usernames or home-directory
paths.
