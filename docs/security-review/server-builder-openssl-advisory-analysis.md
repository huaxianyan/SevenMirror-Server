# Server builder OpenSSL advisory analysis

Status: **internal applicability evidence; finding remains open**

Last reviewed: 2026-09-02

## Finding identity

The digest-pinned `golang:1.25.13-alpine` builder contains both of these Alpine
packages on linux/amd64 and linux/arm64:

- `pkg:apk/alpine/libcrypto3@3.5.7-r0`;
- `pkg:apk/alpine/libssl3@3.5.7-r0`.

Trivy 0.74.0 reports `CVE-2026-14456` as High for each package and identifies
`3.5.8-r0` as fixed. SevenMirror retains that scanner severity and both package
records. OpenSSL's 2026-08-13 advisory classifies the underlying issue as Low;
that vendor difference is context, not a SevenMirror severity downgrade.

The authoritative OpenSSL advisory is:

- <https://openssl-library.org/news/secadv/20260813.txt>

Its OpenSSL 3.5 fix is commit:

- <https://github.com/openssl/openssl/commit/08e7756c3900bcfd77a720e7b74e27d6e4ed01a9>

## Affected behavior and prerequisites

The affected behavior is specific to an OpenSSL QUIC **server listener**. A
remote peer must be able to send valid QUIC Initial packets with unknown
destination connection IDs to that listener faster than the application accepts
the queued connections. The vulnerable implementation then allocates unbounded
pending QUIC channel state. The fix limits the pending queue to 256 by default.

Package presence alone therefore does not establish that the affected listener
exists or is remotely reachable. It does establish that the immutable builder
input contains vulnerable OpenSSL code, so the finding cannot be reported as
removed.

## SevenMirror reachability

The affected QUIC server path is not reached by the current container build or
release runtime:

1. The build stage executes only a source-revision check, two `go build`
   commands, and creation of the empty data directory. It does not start a
   network server or invoke an OpenSSL QUIC API.
2. Both produced executables are built with explicit `CGO_ENABLED=0`. They
   cannot dynamically link the builder's `libcrypto3` or `libssl3` packages.
3. Only `/out` is copied from the builder. Its declared contents are the
   `server` and `admin` Go executables plus the empty `data` directory. No
   builder library or utility is copied.
4. The final stage is the digest-pinned distroless static runtime image. The
   protected base-image and registry-served runtime scans found zero packages
   affected by this advisory and zero findings overall in both architectures.
5. SevenMirror's public transport is HTTPS/WSS through the documented reverse
   proxy boundary; the Server binaries do not implement an OpenSSL QUIC
   listener.

`scripts/base_image_evidence.py` independently re-parses the Dockerfile and
writes these controls into the attested `base-image-manifest.json`. Verification
fails closed if a Go build enables CGO, a new `/out` producer or artifact
appears, the build-stage copy expands beyond `/out`, or the runtime ceases to be
a distroless static image. Focused negative tests cover these changes. This is a
reachability guard, not proof that the upstream packages are fixed.

## Upstream remediation check

A fresh registry and Trivy check on 2026-09-02 found:

- `golang:1.25.13-alpine` still resolves to the pinned multi-architecture digest
  `sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946`;
- both platforms still contain OpenSSL `3.5.7-r0`;
- the then-current `golang:1.27.1-alpine` official image, digest
  `sha256:3f6d04dc61331ee3c2fbbaad62d54412a84680f6a041d269a20a5270a078515b`,
  also contains `3.5.7-r0` on both platforms.

Changing only the Go image tag or refreshing the existing tag would therefore
not remediate this finding. SevenMirror will not replace the official builder
with an ad hoc image, depend on an unpinned package upgrade, or add a broad
scanner ignore merely to produce a zero count.

## Decision and re-evaluation triggers

Current internal assessment: the vulnerable code is present in a builder-only
input but the required OpenSSL QUIC listener is absent, and no affected code is
shipped. The two Trivy records remain open build-tool inventory. There is no
entry in `security/vulnerability-exceptions.json`, no accepted-risk decision,
and no claim of independent approval. Production approval still requires either
an official digest-pinned builder containing the fixed packages or a distinct
reviewer's exact, time-bounded disposition under `docs/vulnerability-management.md`.

Re-run the analysis and protected evidence immediately when any of these occur:

- an official compatible builder digest includes OpenSSL `3.5.8-r0` or later;
- the Go toolchain or builder distribution changes;
- CGO is enabled for a copied executable;
- another builder artifact or directory is copied into the runtime;
- a build step starts a listener or invokes OpenSSL QUIC behavior;
- the runtime image or public transport architecture changes;
- OpenSSL, Alpine, or the scanner materially revises the advisory.
