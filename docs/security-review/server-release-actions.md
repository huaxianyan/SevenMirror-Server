# Server release GitHub Actions review

Status: **internal source and permission review; not independent approval**

The release-artifact workflow adds two official GitHub Actions. Both references
are immutable 40-character commits and are covered by the repository's workflow
pin self-check.

## `actions/attest`

- Commit: `1e69f48acb82d1966a394da916b4c1698aa569d6`
- Release: `v4.2.2`
- Commit verification: GitHub reports a valid verified signature
- Purpose: hash the bounded local artifact subjects, request a short-lived
  Sigstore certificate through GitHub OIDC, sign SLSA provenance and upload the
  attestation to the repository's GitHub attestation API
- Job permissions: `contents: read`, `id-token: write`, `attestations: write`,
  `artifact-metadata: write`
- Secrets: no repository signing key or long-lived token is configured
- Network: GitHub OIDC, attestation and Sigstore services are required

The action receives only the generated release directory. Pairing codes,
transport credentials, authority private keys and runtime databases are not
present in the release job.

## `actions/upload-artifact`

- Commit: `b7c566a772e6b6bfb58ed0dc250532a479d7789f`
- Release: `v6.0.0`
- Commit verification: GitHub reports a valid verified signature
- Purpose: upload the already verified and attested artifact directory with a
  name containing the exact source commit
- Retention: 30 days
- Missing files: fail closed

The upload is transport/storage, not the release identity. Consumers must verify
the per-file attestations and checked-in manifest rather than trusting the ZIP or
artifact name.

## Open review scope

This review confirms source identity, purpose, inputs and least job permissions.
It does not independently audit every transitive npm package in the Actions,
GitHub's hosted runner, Sigstore availability, GitHub artifact retention or the
security of a future durable release host. Recheck both commits and their
published source before the production release baseline.
