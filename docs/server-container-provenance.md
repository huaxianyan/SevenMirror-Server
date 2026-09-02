# Server OCI container provenance and rollback

Status: **attested OCI and base-image scan baseline; registry publication and independent review remain required**

## Immutable build inputs

The Dockerfile pins both upstream image indexes by digest:

- `golang:1.25.13-alpine` —
  `sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946`;
- `gcr.io/distroless/static-debian12:nonroot` —
  `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`.

The first is the Docker Official Image registry's OCI index digest; the second is
the Google Container Registry OCI index digest. Digest pinning prevents tag
movement from changing a build silently. It does not by itself audit the images,
prove their maintainers' signing policy or eliminate the need to refresh patched
base images.

The builder runs on the BuildKit host platform and cross-compiles pure-Go
`server` and `admin` binaries for the requested target architecture. Every build
requires a source revision build argument. The final image records canonical OCI
source/revision labels and retains the distroless `nonroot:nonroot` user and
`/app/server` entrypoint.

## Artifact set and offline verification

CI builds separate linux/amd64 and linux/arm64 OCI layouts. The release set
contains exactly:

- `sevenmirror-server-linux-amd64.oci.tar`;
- `sevenmirror-server-linux-arm64.oci.tar`;
- `container-manifest.json`;
- `SHA256SUMS`.

`scripts/build_container_artifacts.py` treats each OCI archive as untrusted. It
rejects links, path traversal, duplicate/non-regular entries, malformed blob
names, unsupported layout/schema versions, multiple top-level image manifests,
unreferenced blobs and every descriptor size/digest mismatch. It follows the OCI
index to the image manifest, config and all layers, then requires:

- exact target OS and architecture;
- source and 40-character revision labels;
- runtime user `nonroot:nonroot`;
- entrypoint `/app/server`;
- at least one layer.

The external manifest records the archive SHA-256/size, OCI image-manifest digest,
config digest, architecture and layer count. Verify a downloaded set from the
approved source checkout:

```sh
python3 scripts/build_container_artifacts.py \
  --output ./sevenmirror-container-release \
  --revision <40-character-commit> \
  --verify-only
```

The OCI **image-manifest digest** is the deployable image identity. The outer tar
SHA-256 protects this particular offline transport file but is not a registry
image digest. Container bytes are not claimed reproducible across BuildKit
versions; acceptance is based on the exact attested archive and verified
content-addressed OCI graph.

BuildKit's embedded provenance and SBOM outputs are disabled for this bounded OCI
layout so the verifier can require that every blob belongs to the one runtime
image. GitHub provenance is generated externally for the archives, manifest and
checksum. Base-image SBOMs are separately named, verified and attested subjects;
they are not silently introduced as unreferenced OCI blobs.

## Base-image SBOM and vulnerability evidence

The release-candidate workflow downloads exact Trivy `0.74.0` Linux amd64 bytes
with checked SHA-256
`2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a`.
`scripts/base_image_evidence.py` reads the two image references directly from the
Dockerfile, so the digest-pinned build and runtime inputs retain one definition
point. It scans the linux/amd64 and linux/arm64 variants of both indexes with the
OS-package scanner and produces four CycloneDX SBOMs plus four complete Trivy JSON
vulnerability reports.

`base-image-manifest.json` binds the exact source revision, requested image index
digests, architecture, Trivy version, Trivy database identity and update time,
UTC observation time, package/component counts, severity counts, raw evidence
filenames and SHA-256 values. The gate rejects a database older than 7 days or
future-dated by more than 5 minutes. Critical and High findings fail unless the
exact purl and vulnerability ID map to an active Server `base-image` entry in the
canonical vulnerability exception registry. Applied exception IDs remain visible
beside the original finding counts; an exception does not turn the report into a
false zero.

The verifier rejects stale database evidence, changed Dockerfile inputs, missing
or extra files, links, checksum or summary drift, malformed finding identities,
and unapproved Critical or High findings. From the approved source checkout, run:

```sh
python3 scripts/base_image_evidence.py \
  --output ./sevenmirror-base-image-evidence \
  --revision <40-character-commit> \
  --verify-only
```

The evidence describes the pinned upstream base images. It does not replace a
scan of the published registry manifest, prove that a registry served the same
content, or independently disposition Medium and lower findings.

## Registry publication boundary

The current workflow does not push to a production registry. GitHub artifact
storage is limited to 30 days and is not a container registry or durable release
host. The base-image scan must succeed before OCI candidate construction, but a
separate scan of the exact published manifest remains mandatory. Before
production deployment, operator evidence must record:

1. registry namespace and access-control policy;
2. exact uploaded per-architecture image-manifest digests;
3. multi-architecture index digest, if one is created;
4. pull-side verification that the registry serves the approved manifests and
   config/layer digests unchanged;
5. retention, deletion, immutability, vulnerability scanning and emergency
   revocation policy;
6. deployment configuration pinned by digest, never by a mutable tag.

Registry credentials must not enter source, release manifests, support bundles or
command logs. Adding a registry push Action requires its own immutable pin,
permission, dependency and credential-flow review.

## Rollback

Select a rollback image only by an independently approved source revision and
exact architecture-specific image-manifest digest. Verify its GitHub attestation,
offline OCI graph, protocol/schema compatibility and matching workspace backup
requirements before deployment. The service definition must pin the chosen
registry digest.

Do not roll back by mutable tag, outer tar filename, upload date, workflow status
or local Docker image name. Do not start an older image against an unsupported
registry schema. A stale workspace restore can be rejected by client rollback
floors and become an availability failure; container rollback does not override
that boundary.
