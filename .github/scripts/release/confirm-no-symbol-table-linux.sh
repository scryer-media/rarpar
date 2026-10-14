#!/usr/bin/env bash
# release.yml, build-linux: "Confirm the release binary carries no symbol table".
# The workspace [profile.release] sets strip = true, which removes .symtab: nm
# then prints nothing (it reports "no symbols" on stderr). The imports in
# .dynsym stay, but nm reads those only with -D. Change this check together
# with that profile setting.
set -euo pipefail
exe="$RARPAR_RELEASE_TARGET_DIR/$RELEASE_TARGET/release/rarpar"
symbols="$(nm "$exe")"
if [ -n "$symbols" ]; then
  echo "::error::$exe still carries a symbol table; the workspace [profile.release] strip = true did not reach the build"
  head -n 20 <<< "$symbols"
  exit 1
fi
echo "$exe carries no symbol table"
