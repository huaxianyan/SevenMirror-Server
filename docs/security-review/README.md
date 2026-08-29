# SevenMirror security review package

Status: **review baseline prepared; independent security review has not started and has not passed**

Last updated: 2026-08-29

## Purpose

This directory is the entry point for a release-blocking review of SevenMirror's
Server, Android, Chrome, and cross-client protocol boundaries. It consolidates
the current design and evidence so an independent reviewer can evaluate the
implemented system without reconstructing intent from historical Spike notes.

Preparing this package is an internal engineering activity. A checked internal
evidence item means only that the repository contains the referenced control or
test. It is not an external security finding, certification, penetration test,
or approval to transmit third-party notification content.

## Review baseline

The baseline is the three repositories at or after:

- Server `7095426`;
- Android `49151ad`;
- Chrome `acb02aa`.

The Android and Chrome references identify the current runtime protocol baseline;
later documentation-only changes do not change wire behavior. Before an actual
review begins, record immutable full commit IDs for all three repositories in
the review report and do not silently move the baseline.

The current product gate remains:

> Only app-owned synthetic Android notifications may leave the device. Real
> third-party notification content remains disabled until the blocking review
> findings are resolved and the explicit product gate is changed in a reviewed
> release.

## Package contents

- [`threat-model.md`](threat-model.md) defines assets, actors, trust boundaries,
  data flows, security properties, accepted risks, and out-of-scope claims.
- [`review-checklist.md`](review-checklist.md) maps review questions to concrete
  specifications, source boundaries, automated evidence, and unresolved work.
- [`android-third-party-actions.md`](android-third-party-actions.md) records the
  internal source, dependency, permission, and update-policy review for Android's
  non-official GitHub Actions.
- [`server-canary-scan.md`](server-canary-scan.md) defines the real-binary Server
  credential/plaintext scan, narrow allowed one-time outputs, scanned artifacts,
  and remaining client/deployment coverage.
- [`../caddy-reverse-proxy.md`](../caddy-reverse-proxy.md) defines the checked-in
  Caddy TLS/WebSocket baseline, exact trusted-address policy, reduced access log,
  real-process canary and operator-specific limitations.
- The Chrome repository's `docs/SENSITIVE_DATA.md` defines its endpoint-local
  credential/plaintext inventory, profile-compromise boundary, deterministic
  store test, isolated real-browser profile canary, and remaining endpoint
  coverage.
- [`../../SECURITY.md`](../../SECURITY.md) is the canonical public vulnerability
  reporting, supported-version, disclosure, and security-update policy linked by
  all three repositories.
- [`../adr/ADR-001-protocol-encoding-and-versioning.md`](../adr/ADR-001-protocol-encoding-and-versioning.md)
  defines canonical encoding and pre-v1 version policy.
- [`../adr/ADR-002-device-identity-and-e2ee.md`](../adr/ADR-002-device-identity-and-e2ee.md)
  remains authoritative for Auth HPKE and per-recipient encryption, except where
  its bilateral trust lifecycle is superseded by ADR-005.
- [`../adr/ADR-003-chrome-realtime-connection-and-recovery.md`](../adr/ADR-003-chrome-realtime-connection-and-recovery.md)
  defines MV3 transport, cursor, and snapshot recovery.
- [`../adr/ADR-004-private-admission-and-transport-auth.md`](../adr/ADR-004-private-admission-and-transport-auth.md)
  defines private admission and transport authentication, except where its
  membership trust statements are superseded by ADR-005.
- [`../adr/ADR-005-centralized-workspace-membership-authority.md`](../adr/ADR-005-centralized-workspace-membership-authority.md)
  is authoritative for membership, roles, revocation, and authority rotation.

Canonical protocol specifications and public vectors live in [`../../protocol/`](../../protocol/README.md).
Android and Chrome independently vendor and verify those assets.

## Review roles and independence

At minimum, the release review should name:

1. a project contact who can explain implementation and reproduce evidence;
2. an independent reviewer who did not author the reviewed security-critical
   implementation;
3. an owner for each finding and remediation;
4. the person authorized to decide whether an accepted residual risk is
   compatible with the release claim.

The project author may perform readiness checks and reproduce tests, but may not
mark the independent-review gate passed alone.

## Finding lifecycle

Findings use stable identifiers `SR-<number>` and one of these states:

- `OPEN`: not yet resolved or accepted;
- `IN REVIEW`: remediation or evidence is under review;
- `RESOLVED`: a reviewer verified the remediation against an immutable commit;
- `ACCEPTED RISK`: the product owner accepted a documented residual risk and
  adjusted product claims where necessary;
- `NOT APPLICABLE`: the reviewer documented why the issue is outside the
  supported deployment or threat model.

A finding record must contain severity, affected boundary, reproduction or
reasoning, impact, remediation, verification evidence, reviewer, date, and exact
commit. Do not include credentials, private keys, notification plaintext, or
full private device identifiers in a finding.

Suggested severity meanings:

- `Critical`: practical plaintext disclosure, private-key compromise, arbitrary
  authority replacement, unauthorized business recipient, or remote code/update
  signing compromise;
- `High`: authorization bypass, replayed side effect, cross-device misrouting,
  rollback acceptance, or durable secret disclosure;
- `Medium`: bounded metadata exposure, denial of service beyond documented
  limits, unsafe operational default, or recovery behavior that can violate a
  stated security claim;
- `Low`: hardening, documentation, or defense-in-depth gap with no direct breach
  of a current claim.

## Required review outputs

The independent review is complete only when it produces:

1. the exact three-repository baseline;
2. a completed copy of `review-checklist.md` or an equivalent report;
3. all findings with stable IDs and severity;
4. remediation commits and reviewer verification, or explicit accepted-risk
   decisions;
5. dependency and secret-scan results for the immutable baseline;
6. a statement covering protocol, Server, Android, Chrome, deployment, backup,
   and update-signing scope;
7. a final decision that explicitly says whether third-party notification
   transport may be enabled.

## Current blockers before review sign-off

The initial readiness audit has identified these open items; the detailed list
and evidence are in the checklist:

- the new three-repository Gitleaks history gate and its narrow public-vector
  allowlist still require independent review against the release baseline;
- Android now has strict Gradle locks, artifact verification, and a blocking
  release-runtime OSV gate, but its complete plugin/build-tool audit still has
  upstream findings requiring explicit triage, remediation, or accepted risk;
- Server's real-binary canary covers pairing and credential rotation HTTP,
  old/pending WebSocket authentication and sensitive artifacts. A separate
  pinned Caddy gate now covers real TLS termination, WebSocket forwarding,
  trusted client-address derivation and reduced access logs. Operator-specific
  certificate renewal, firewall and backup/support/log-shipping pipelines remain
  open. Chrome now has local non-headless interaction DOM evidence, while a pinned
  CI browser plus crash/sync/OS artifacts and Android system artifacts remain open;
- removal of `/v1/devices/register` and schema-v8 fail-closed migration of
  historical `legacy_active` rows now have internal evidence, but still require
  release-baseline and independent-review confirmation;
- Android HPKE requires a software-accessible private scalar after Keystore
  unwrap and needs focused memory/lifecycle review;
- local registry/authority consistency and isolated restore now have a real-admin CI drill, while authority PKCS#8 encryption, access control, off-host retention and retrieval evidence remain delegated to the operator's backup system;
- the documented Android signing-key backup still requires a verified copy on a
  separate encrypted physical medium;
- host-local trusted-proxy policy, configurable finite abuse limits and
  single-process slow-client/capacity checks have internal evidence, while
  distributed proxy coordination, reconnect storms and deployment throughput
  remain undecided;
- two-real-device OEM background and network-transition validation remains open;
- no independent reviewer has reviewed the Auth HPKE, canonical codecs,
  membership authority, cursor, or snapshot-reset implementation.

These items do not imply a known exploit. They prevent a production security
claim until reviewed and resolved or explicitly accepted.
