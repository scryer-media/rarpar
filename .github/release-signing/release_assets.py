#!/usr/bin/env python3
"""Collect, verify and finalize binary releases. Uses only the Python stdlib."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


PROVENANCE = "rarpar-provenance.intoto.jsonl"
CHECKSUMS = "SHA256SUMS"
BUNDLE = "SHA256SUMS.sigstore.json"
WORKFLOW = ".github/workflows/release.yml"
BUILDER = (
    "https://github.com/slsa-framework/slsa-github-generator/"
    ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
)
PLATFORMS = (
    "darwin-arm64", "darwin-x86_64", "linux-arm64-gnu-direct",
    "linux-arm64-musl-direct", "linux-x86_64-gnu-direct",
    "linux-x86_64-musl-direct", "windows-arm64", "windows-x86_64",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def archives(tag):
    require(re.fullmatch(r"rarpar-v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", tag),
            "invalid release tag")
    return sorted(f"rarpar-{tag}-{p}.{'zip' if p.startswith('windows-') else 'tar.gz'}"
                  for p in PLATFORMS)


def asset_names(tag):
    return sorted([*archives(tag), CHECKSUMS, BUNDLE, PROVENANCE])


def digest(path):
    with path.open("rb") as stream:
        checksum = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def collect(source, destination, tag):
    expected = archives(tag)
    found = {}
    for path in source.rglob("*"):
        require(not path.is_symlink(), f"symlink in build artifacts: {path}")
        if path.is_file() and (path.name.endswith((".tar.gz", ".zip"))):
            require(path.name in expected, f"unexpected archive: {path.name}")
            require(path.name not in found, f"duplicate archive: {path.name}")
            found[path.name] = path
    require(sorted(found) == expected, "missing platform archives")
    destination.mkdir(parents=True, exist_ok=True)
    require(not any(destination.iterdir()), "asset destination must be empty")
    for name in expected:
        shutil.copyfile(found[name], destination / name)
    (destination / CHECKSUMS).write_text(
        "".join(f"{digest(destination / name)}  {name}\n" for name in expected),
        encoding="utf-8",
    )


def validate_files(directory, tag):
    require(sorted(p.name for p in directory.iterdir()) == asset_names(tag),
            "release must contain exactly eight archives, checksums, signature and provenance")
    for path in directory.iterdir():
        require(path.is_file() and not path.is_symlink(), f"invalid asset: {path.name}")
        require(path.stat().st_size > 0, f"empty asset: {path.name}")
    expected = {name: digest(directory / name) for name in archives(tag)}
    canonical = "".join(f"{sha}  {name}\n" for name, sha in expected.items())
    require((directory / CHECKSUMS).read_bytes() == canonical.encode(),
            "checksum manifest is malformed or archives do not match")
    return expected


def validate_statement(statement, expected, repository, tag, commit):
    require(statement.get("_type") == "https://in-toto.io/Statement/v0.1",
            "unexpected statement type")
    require(statement.get("predicateType") == "https://slsa.dev/provenance/v0.2",
            "unexpected provenance type")
    subjects = statement.get("subject", [])
    require(len(subjects) == len(expected), "incorrect provenance subject count")
    require(sorted(subjects, key=lambda x: x["name"]) == [
        {"name": name, "digest": {"sha256": sha}} for name, sha in expected.items()
    ], "provenance subjects do not match the archive set")
    predicate = statement["predicate"]
    require(predicate.get("builder", {}).get("id") == BUILDER, "untrusted builder")
    source = predicate["invocation"]["configSource"]
    uri = f"git+https://github.com/{repository}@refs/tags/{tag}"
    require(source.get("uri") == uri, "wrong source repository or tag")
    require(source.get("entryPoint") == WORKFLOW, "wrong source workflow")
    require(source.get("digest") == {"sha1": commit}, "wrong source commit")
    require({"uri": uri, "digest": {"sha1": commit}} in predicate.get("materials", []),
            "source material does not match the signed tag commit")


def run(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def verify(directory, repository, tag, commit):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid source commit")
    expected = validate_files(directory, tag)
    identity = f"https://github.com/{repository}/{WORKFLOW}@refs/tags/{tag}"
    run("cosign", "verify-blob", "--new-bundle-format=true",
        "--bundle", str(directory / BUNDLE),
        "--certificate-identity", identity,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        str(directory / CHECKSUMS))
    verified = run("slsa-verifier", "verify-artifact",
        *(str(directory / name) for name in expected),
        "--provenance-path", str(directory / PROVENANCE),
        "--source-uri", f"github.com/{repository}", "--source-tag", tag,
        "--builder-id", BUILDER, "--print-provenance")
    # The pinned verifier prints one authenticated statement per input archive.
    # Inspect its verified output, never an independently decoded unsigned payload.
    decoder = json.JSONDecoder()
    for _ in expected:
        statement, end = decoder.raw_decode(verified.lstrip())
        verified = verified.lstrip()[end:]
        validate_statement(statement, expected, repository, tag, commit)
    require(not verified.strip(), "unexpected extra verified statements")


def release_metadata(repository, tag):
    # REST's tag lookup finds published releases; GraphQL also finds drafts.
    # Only an explicit null release is missing. API/authentication errors fail closed.
    owner, name = repository.split("/")
    query = """query($owner: String!, $name: String!, $tag: String!) {
      repository(owner: $owner, name: $name) {
        release(tagName: $tag) { databaseId }
      }
    }"""
    lookup = json.loads(run("gh", "api", "graphql", "-f", f"query={query}",
                            "-f", f"owner={owner}", "-f", f"name={name}", "-f", f"tag={tag}"))
    require(not lookup.get("errors"), "release lookup failed")
    repo = lookup["data"]["repository"]
    require(repo is not None, "release repository unavailable")
    if repo["release"] is None:
        return None
    release_id = repo["release"]["databaseId"]
    require(isinstance(release_id, int), "invalid release id")
    data = json.loads(run("gh", "api", f"repos/{repository}/releases/{release_id}"))
    require(data.get("tag_name") == tag, "release tag mismatch")
    require(isinstance(data.get("draft"), bool), "missing release draft state")
    return data


def verify_remote(repository, tag, commit):
    metadata = release_metadata(repository, tag)
    require(metadata is not None, "release disappeared")
    require(sorted(a["name"] for a in metadata["assets"]) == asset_names(tag),
            "remote release asset set is incomplete or unexpected")
    with tempfile.TemporaryDirectory(prefix="rarpar-release-verify-") as temp:
        run("gh", "release", "download", tag, "--repo", repository, "--dir", temp)
        verify(Path(temp), repository, tag, commit)
    return metadata


def finalize(directory, repository, tag, commit):
    # Check published releases first: rebuilds can differ and must never replace them.
    current = release_metadata(repository, tag)
    if current is not None and not current["draft"]:
        verify_remote(repository, tag, commit)
        return False
    verify(directory, repository, tag, commit)
    if current is None:
        run("gh", "release", "create", tag, "--repo", repository,
            "--draft", "--verify-tag", "--title", tag, "--notes", f"rarpar {tag}")
    current = release_metadata(repository, tag)
    require(current is not None and current["draft"], "refusing to modify a published release")
    for asset in current["assets"]:
        if asset["name"] not in asset_names(tag):
            run("gh", "release", "delete-asset", tag, asset["name"],
                "--repo", repository, "--yes")
    run("gh", "release", "upload", tag, "--repo", repository, "--clobber",
        *(str(directory / name) for name in asset_names(tag)))
    checked = verify_remote(repository, tag, commit)
    require(checked["draft"], "release was published outside this workflow")
    run("gh", "release", "edit", tag, "--repo", repository, "--draft=false")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("collect", "verify", "finalize"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--commit")
    args = parser.parse_args()
    if args.command == "collect":
        require(args.source is not None, "collect requires --source")
        collect(args.source, args.directory, args.tag)
    else:
        require(args.repository == "scryer-media/rarpar", "unexpected release repository")
        require(args.commit is not None, "source commit required")
        if args.command == "verify":
            verify(args.directory, args.repository, args.tag, args.commit)
        else:
            published = finalize(args.directory, args.repository, args.tag, args.commit)
            if "GITHUB_OUTPUT" in os.environ:
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                    output.write(f"published={str(published).lower()}\n")
            print("Published verified binary release" if published else "Verified existing release; unchanged")


if __name__ == "__main__":
    main()
