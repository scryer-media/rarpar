#!/usr/bin/env python3
"""Print the workspace [profile.release] as `cargo build --config` values.

The release jobs build the `cargo package` output unpacked outside the
workspace. There the package is its own workspace root, and Cargo reads
profiles only from the root manifest, so the workspace's [profile.release]
never reaches the shipped binary unless the build passes it explicitly. This
prints one `profile.release.<key>=<value>` line per setting in the workspace
Cargo.toml; build-rarpar.sh and build-rarpar.ps1 pass each line as a
`--config` argument, so the values exist only in Cargo.toml.

Strings are printed as TOML literal strings ('fat'): no shell or Windows
command-line parser has a double quote to strip. The manifest is read line by
line because the Ubuntu 22.04 runners' Python is 3.10, which has no tomllib.
Flat `key = value` settings with string, boolean or integer values are
understood; anything else in the table, a nested [profile.release.*] table,
or a release setting spelled outside the table fails the build rather than
being dropped.

Usage: release_profile.py Cargo.toml
"""

import re
import sys

TABLE = "profile.release"
HEADER = re.compile(r"\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:#.*)?")
SETTING = re.compile(
    r"""([A-Za-z0-9_-]+)\s*=\s*("[^"\\']*"|'[^']*'|true|false|[+-]?[0-9]+)\s*(?:#.*)?"""
)


def dotted(key):
    return re.sub(r"""[\s"']""", "", key)


def release_settings(path):
    table = None
    settings = []
    with open(path, encoding="utf-8") as manifest:
        for number, line in enumerate(manifest, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            header = HEADER.fullmatch(text)
            if header:
                table = dotted(header.group(1))
                if table.startswith(TABLE + "."):
                    raise SystemExit(f"{path}:{number}: [{table}] is not passed to the release build")
                continue
            if table != TABLE:
                key = dotted(text.split("=", 1)[0])
                full = f"{table}.{key}" if table else key
                if full == TABLE or full.startswith(TABLE + "."):
                    raise SystemExit(f"{path}:{number}: write release settings under [{TABLE}]")
                continue
            setting = SETTING.fullmatch(text)
            if setting is None:
                raise SystemExit(f"{path}:{number}: cannot pass `{text}` to cargo --config")
            key, value = setting.groups()
            if value.startswith('"'):
                value = f"'{value[1:-1]}'"
            settings.append(f"{TABLE}.{key}={value}")
    if not settings:
        raise SystemExit(f"{path} sets nothing in [{TABLE}]")
    return settings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: release_profile.py Cargo.toml")
    print("\n".join(release_settings(sys.argv[1])))
