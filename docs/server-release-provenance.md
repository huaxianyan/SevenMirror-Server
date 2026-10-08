# Server release provenance and rollback

Status: **protected release-candidate baseline; independent review still required**

## Release authority

Code acceptance and required Server CI checks happen before a topic branch is
fast-forwarded into protected `main`. Main blocks force-push and deletion; the
current development process does not require a pull request.

Push a release tag after acceptance to publish automatically. The release job
targets the GitHub `release-candidate` environment, which allows only `v*` tags
and has no manual approval or wait timer. Publication still verifies artifacts,
scans runtime inputs and generates provenance.

Independent review remains open. Automatic publication is not an independent
approval and does not change the ledger's `candidate` or `approved` meanings.

## Artifact set

`.github/workflows/release-artifacts.yml` runs only on a version tag. It builds the following `CGO_ENABLED=0` artifacts with the exact
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

A version-tag run requires `vMAJOR.MINOR.PATCH`. The release version comes from
that tag, independently of `protocol/PROTOCOL_VERSION`, which still records the
wire protocol in the artifact manifest. A compatible patch release does not
change the protocol version. There is no manual dispatch entry point.

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

## Published release

The `publish-release` job runs only for a tag and only after the build job
succeeds. It downloads the verified binary artifact set, assembles the release
body from `docs/release-notes/<tag>.md` plus a generated `## 构建信息` table, and
creates the GitHub Release with `gh release create --verify-tag`.

Only the binary set becomes Release assets. The container set stays a workflow
artifact and is distributed through the container registry, which follows the
decided channel split; both sets also contain a `SHA256SUMS` file, and a GitHub
Release cannot hold two assets with the same name.

`docs/release-notes/<tag>.md` is short by design: one summary paragraph, a
`## 主要更新` section, and a link to this document under the tag. Usage,
validation evidence and build ranges belong here or in the README, not in the
release body. `scripts/verify_release_notes.py` enforces that shape, and
`scripts/test_verify_release_notes.py` runs it as part of CI.

The release title is the tag alone. A product-name prefix turns the Release list
into a column of identical truncated names and hides which version each entry is.

### v0.1.1 publication and deployment

Release `v0.1.1` binds source revision
`7de593dfe621296443395a7010f40e3902696199`; its protocol version remains `0.1.0`.
The automatic tag workflow is
[run 37717790152](https://github.com/huaxianyan/SevenMirror-Server/actions/runs/37717790152).
Downloaded binaries and container/registry evidence passed their manifest
verifiers and GitHub attestation verification.

The multi-architecture index is
`sha256:ad55652bcfce2faec73491679f7a94b716171d7555984c4a4e59cd97aa0f5b39`.
Both the deployed relay and admin-web now use that index. Existing deployment
network settings, data mounts and runtime user were preserved. Before switching,
both writers were stopped for a state archive; isolated workspace backups also
passed the image's backup verifier. The relay is healthy, public readiness
returns 200, and the admin HTTPS origin reaches its login page with 200 after
redirects. Workspace identities were preserved.

A separate empty-directory Compose check using the published image confirmed
healthy startup and a single workspace/authority key after repeated startup and
initialization. Its containers and data were removed afterwards.

The deployment retains its pre-upgrade state/configuration backups and old image
IDs for recovery. It does not claim that downgrading a migrated registry is safe:
check storage compatibility and the workspace backup procedure before rollback.
Ledger state remains `candidate`; external review and archive risks remain open.

## Remaining signing work

Sigstore/GitHub provenance is not platform-native code signing. Default-branch
run `33587546197` published the public GHCR candidate, verified the registry graph
and runtime scan, and produced attestations that passed after download. A separate
anonymous pull also matched the complete graph. Production release still needs
durable binary hosting, independent release approval, independent approval of
the checked-in GHCR governance baseline, a verified off-registry archive and
disposition of the builder finding. Android and Chrome retain their separate
channel-specific publication boundaries.
