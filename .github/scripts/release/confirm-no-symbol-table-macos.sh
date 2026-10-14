#!/usr/bin/env bash
# release.yml, build-macos: "Confirm the release binary carries no symbol table".
# The workspace [profile.release] sets strip = true. A stripped Mach-O
# executable still defines __mh_execute_header, which dyld needs, and still
# lists its undefined imports, so this looks only at defined symbols other
# than that header. Change this check together with that profile setting.
set -euo pipefail
exe="$RARPAR_RELEASE_TARGET_DIR/$RELEASE_TARGET/release/rarpar"
defined="$(nm --defined-only "$exe")"
symbols="$(grep -v ' __mh_execute_header$' <<< "$defined" || true)"
if [ -n "$symbols" ]; then
  echo "::error::$exe still carries a symbol table; the workspace [profile.release] strip = true did not reach the build"
  head -n 20 <<< "$symbols"
  exit 1
fi
echo "$exe defines no symbols beyond __mh_execute_header"
