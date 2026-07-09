# Packaging

`rarpar` is currently distributed through GitHub Release archives, Homebrew, and
source builds. Future Debian/Ubuntu and RPM packaging should consume the same
generated install tree used by release validation rather than inventing a
separate layout.

## Package Names

- Debian/Ubuntu package: `rarpar`
- RPM package: `rarpar`
- Installed binary: `/usr/bin/rarpar`

## Linux Artifact Policy

Future distro packages should use GNU/glibc Linux builds:

- `linux-x86_64-gnu` for amd64/x86_64 packages
- `linux-arm64-gnu` for arm64/aarch64 packages

The musl archives remain useful as portable direct-download artifacts and as the
Homebrew Linux fallback when the host glibc is too old.

## Package Metadata Defaults

- Summary: `Smart RAR/PAR2 repair and extraction CLI`
- Homepage: `https://github.com/scryer-media/rarpar`
- License: `GPL-3.0-or-later AND UnRAR-restriction`
  - Homebrew represents this as `all_of: ["GPL-3.0-or-later", :cannot_represent]`
    because the UnRAR restriction is not an SPDX license identifier.
- Architecture: native per package, not universal

The binary must remain named `rarpar`. Do not ship aliases or binaries named
`unrar`, `rar`, `par2`, or `par2repair`.

## Install Layout

The `xtask package-root` command stages the package filesystem tree expected by
future distro packages:

```text
/usr/bin/rarpar
/usr/share/man/man1/rarpar.1
/usr/share/bash-completion/completions/rarpar
/usr/share/zsh/site-functions/_rarpar
/usr/share/fish/vendor_completions.d/rarpar.fish
/usr/share/doc/rarpar/README.md
/usr/share/licenses/rarpar/LICENSE
/usr/share/licenses/rarpar/LICENSE.GPL-3.0-or-later
/usr/share/licenses/rarpar/LICENSE.weaver-unrar
```

Expected file modes:

- executable: `0755`
- directories: `0755`
- manpage, completions, README, licenses: `0644`

## Runtime Dependencies

GNU/glibc packages are expected to need no runtime dependency on system
`unrar`, `rar`, `par2`, or `par2repair`. Beyond libc/system libraries, runtime
dependencies should be confirmed from the final release binary before adding
package metadata.

## Future Automation

Do not add `.deb`, `.rpm`, apt repository, yum/dnf repository, maintainer
scripts, service files, or repository signing automation until the release
process is ready for that responsibility.

When package generation begins, `nfpm` is the likely first automation path. It
can consume the existing package-root layout while native distro packaging can
reuse the same staged files later.
