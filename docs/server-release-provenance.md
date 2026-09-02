# Server release provenance and rollback

Status: **protected release-candidate baseline; independent review still required**

## Release authority

The release job targets the GitHub `release-candidate` environment. That
environment accepts deployments only from protected branches and requires an
explicit approval from the repository administrator before a runner can access
the job permissions or produce attestations. The `main` branch separately
requires a pull request and its Server CI check, blocks force-push and deletion,
and applies those rules to administrators.

Only `huaxianyan` currently has repository access, so the environment approval
is a deliberate second step by the same identity, not independent approval. It
reduces accidental dispatch and direct-push risk but cannot establish separation
of duties. Before production release, add a second trusted reviewer, require at
least one approval from someone other than the last pusher, enable environment
self-review prevention, and verify the resulting audit trail.

## Artifact set

`.github/workflows/release-artifacts.yml` runs on an explicit manual dispatch or
a version tag. It builds the following `CGO_ENABLED=0` artifacts with the exact
Go toolchain required by `go.mod`:

- `sevenmirror-server-linux-amd64`
- `sevenmirror-admin-linux-amd64`
- `sevenmirror-admin-web-linux-amd64`
- `sevenmirror-server-linux-arm64`
- `sevenmirror-admin-linux-arm64`
- `sevenmirror-admin-web-linux-arm64`

Every binary uses `-trimpath`, `-buildvcs=true` and stripped symbols. The builder
requires embedded Go metadata to bind the expected command, GOOS, GOARCH, exact
40-character source revision and `vcs.modified=false`. The `admin-web` artifact
is the independent, loopback-only management process; it is not linked into or
mounted on the public relay handler.

`release-manifest.json` records the source repository, source revision, protocol
version, Go version and each artifact's name, SHA-256, size, command and target.
`SHA256SUMS` is derived from the same sorted inventory. Neither file contains a
build timestamp, runner path or mutable branch name.

The artifact directory rejects symlinks, extra entries, missing entries, duplicate
records, digest/size mismatches and a source revision different from the expected
commit. It can be checked offline after download:

```sh
python3 scripts/build_release_artifacts.py \
  --output ./sevenmirror-server-release \
  --revision <40-character-commit> \
  --verify-only
```

A version-tag run additionally requires the tag to equal
`v$(cat protocol/PROTOCOL_VERSION)` and rejects a protocol version ending in
`-dev`. Manual dispatch remains available for attested release-candidate evidence
without claiming that the development version is a published release.

## Signed GitHub provenance

The workflow passes every binary, manifest and checksum file to the official
`actions/attest` action pinned at
`1e69f48acb82d1966a394da916b4c1698aa569d6` (`v4.2.2`, GitHub-verified commit).
GitHub obtains a short-lived Sigstore certificate through OIDC and publishes a
signed SLSA provenance attestation associated with this public repository.

Verify every downloaded subject against the repository identity:

```sh
for artifact in sevenmirror-server-release/*; do
  gh attestation verify "$artifact" --repo huaxianyan/SevenMirror-Server
done
```

Attestation verifies that GitHub's workflow produced a subject digest for this
repository. It does not prove that the source passed independent review, that a
tag is immutable, or that the binary is safe. The exact manifest source revision
and digest remain the release and rollback identity.

The workflow also uploads the complete set under an artifact name containing the
full source commit. Before building release artifacts, it generates a separate
`sevenmirror-base-image-evidence-<commit>` set containing four CycloneDX SBOMs,
four complete Trivy reports, database metadata, a bounded manifest and checksums.
Every evidence file receives its own GitHub attestation and can be checked with
`scripts/base_image_evidence.py --verify-only`; it is not part of the binary or
OCI graph. GitHub retention is currently 30 days, so durable release hosting and
retention must be decided before production publication.

## Rollback rule

A rollback candidate is acceptable only when:

1. every file passes `gh attestation verify` for this repository;
2. the directory passes the offline manifest verifier for the recorded source
   revision;
3. that exact revision was approved as a release baseline;
4. its protocol and storage compatibility are valid for the target deployment;
5. the matching workspace backup has been retrieved and verified when database
   rollback is required.

Do not select a rollback by mutable tag, filename, workflow status, upload date or
"last known good" label alone. Do not run an older Server binary against a
registry schema it does not support. Restoring registry/authority state requires
the consistent workspace backup procedure and may cause an explicit availability
failure for clients whose accepted roster/cursor state is newer.

## Container channel

The same release workflow also builds and separately attests bounded linux/amd64
and linux/arm64 OCI layout archives. Their content-addressed graph, runtime
identity, immutable base-image inputs, registry boundary and digest-based rollback
are defined in [`server-container-provenance.md`](server-container-provenance.md).
Binary and container artifact sets remain separate verification scopes. After
OCI verification, the protected job uses the exact archives to create one GHCR
multi-architecture index, pulls it back by index digest, revalidates the complete
graph and scans both registry-served runtime platforms. Registry evidence is a
fourth separately attested and uploaded scope; the source-revision tag is not the
deployment identity.

## Remaining signing work

Sigstore/GitHub provenance is not platform-native code signing. Default-branch
run `33587546197` published the public GHCR candidate, verified the registry graph
and runtime scan, and produced attestations that passed after download. A separate
anonymous pull also matched the complete graph. Production release still needs
durable binary hosting, independent release approval, independent approval of
the checked-in GHCR governance baseline, a verified off-registry archive and
disposition of the builder finding. Android and Chrome retain their separate
channel-specific publication boundaries.
