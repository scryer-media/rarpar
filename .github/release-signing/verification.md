# Binary release verification

The release workflow runs only for pushed `rarpar-v*` tags. It builds eight
platform archives and publishes these additional assets:

- `SHA256SUMS`: sorted SHA-256 checksums with archive basenames.
- `SHA256SUMS.sigstore.json`: a Sigstore signature bundle for the checksums.
- `rarpar-provenance.intoto.jsonl`: signed SLSA provenance covering all archives.

The workflow checks the signed tag and its existing release-branch ancestry
policy before building. Builds use the triggering commit. All archives must
pass checksum, signature, builder identity, repository, tag, source commit and
provenance subject checks. The workflow downloads and checks the draft's assets
again before making the release public. It does not build or publish containers.

## Verify a download

Use Cosign 3.1.3 and slsa-verifier 2.7.1, the versions used by the workflow.
Obtain the verifier script and signing policy from a trusted repository checkout.
Set `tag` to the desired release and download all eleven assets into an otherwise
empty directory. Verify the tag using the trusted SSH signing policy, then run:

```sh
tag=rarpar-v1.2.3 # Replace with the desired release.
git -c gpg.format=ssh \
  -c gpg.ssh.allowedSignersFile=.github/release-signing/allowed_signers \
  verify-tag "$tag"
commit=$(git rev-parse "$tag^{commit}")
python3 .github/release-signing/release_assets.py verify \
  --directory downloads --repository scryer-media/rarpar \
  --tag "$tag" --commit "$commit"
```

The script verifies the checksum bundle's exact workflow/tag certificate identity
and GitHub OIDC issuer. It then asks slsa-verifier to authenticate every archive
and checks the authenticated statements against the complete expected asset set.
It does not trust an unsigned decoding of the provenance payload.

## Failures and retries

Recover by rerunning the original tag-push workflow. A rerun uses the workflow
version recorded in that run; it cannot pick up later workflow fixes. The existing
tag-signature and release-branch ancestry checks still apply, including the
requirement that the tag includes current `main`.

Failures before draft creation publish nothing. A failed upload or download
verification leaves an unpublished draft, which a retry may repair. An already
published release is verified without changing any assets, even when rebuilt
archives differ. An incomplete or invalid published release fails verification;
this workflow never repairs historical public releases or overwrites their assets.
Expired workflow artifacts require rerunning their producing jobs as well.

The optional Homebrew hook runs only after a newly finalized binary release.
If its push token or signing key is absent, it reports a notice and skips the
tap update while completing the verified binary release.
If enabled, it needs `TAP_PUSH_TOKEN` and `TAP_SIGNING_KEY`; the latter is an SSH
private signing key whose public key is trusted by `allowed_signers`. Commits are
signed and verified before pushing. There is no unsigned fallback.

## Scorecard

New complete releases supply both a recognized signature bundle and provenance.
The Signed-Releases check can improve as old unsigned releases leave its evaluation
window. The badge refreshes on Scorecard's next analysis; publishing an asset does
not synchronously refresh it. Other checks still affect the overall score.

## Local checks

```sh
python3 -B -m unittest discover -s .github/release-signing -p 'test_*.py' -v
actionlint .github/workflows/release.yml .github/workflows/security.yml
zizmor --offline .github/workflows/release.yml .github/workflows/security.yml
```

The regression suite mocks external verifiers and GitHub mutations. It does not
create tags, drafts, releases, signing identities or registry content. Full OIDC
signing can only be demonstrated by a separately authorized release run.
