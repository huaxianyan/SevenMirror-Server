# SevenMirror security review checklist

Status: internal evidence index; all independent-review boxes are initially open

Last updated: 2026-08-28

## 1. How to use this checklist

This checklist is not a pass/fail assertion by the implementation author. For
each item, the independent reviewer should:

1. record the exact Server, Android, and Chrome commit IDs;
2. inspect the cited design and implementation rather than relying on the
   description in this file;
3. reproduce relevant tests or provide equivalent analysis;
4. mark the review box only after resolving or recording every resulting
   finding;
5. cite finding IDs for every exception or accepted risk.

Internal readiness states mean:

- `EVIDENCE`: implementation or tests exist and are ready for review;
- `PARTIAL`: some evidence exists, but a control, automation, or decision is
  missing;
- `OPEN`: no sufficient control or decision currently exists;
- `EXTERNAL`: the only missing step is independent specialist review.

None of these states means independently verified.

## 2. Review record

| Field | Value |
| --- | --- |
| Server full commit | _record before review_ |
| Android full commit | _record before review_ |
| Chrome full commit | _record before review_ |
| Server deployment/configuration baseline | _record before review_ |
| Reviewer(s) | _record before review_ |
| Project contact | _record before review_ |
| Review start/end | _record before review_ |
| Finding report location and digest | _record before review_ |
| Final release decision | _not decided_ |
| Third-party notification gate | **disabled** |

## 3. Initial readiness findings

These are known review-preparation findings, not claims that an exploit exists.
Severity is provisional until an independent reviewer assesses realistic impact.

| ID | Provisional severity | State | Required disposition |
| --- | --- | --- | --- |
| SR-001 | High | OPEN | Complete independent protocol and cryptographic review of Auth HPKE, canonical encodings, identity binding, replay, and domain separation before v1 freeze. |
| SR-002 | Medium | EVIDENCE | All three CI workflows now run SHA-pinned Gitleaks Action v3.0.0 with scanner v8.30.1 over full Git history. The only path allowlist is the published deterministic `protocol/test-vectors/` tree; Server documentation false positives use exact fingerprints. Independent review and release-candidate execution remain required. |
| SR-003 | Medium | PARTIAL | Server now runs `govulncheck v1.1.4`; its first CI run found 12 reachable Go 1.24.13 standard-library vulnerabilities, so the enforced source/CI/container floor is now Go 1.25.13. Chrome runs `npm audit` against `package-lock.json` and the initial High-severity `nanoid` finding is fixed at 3.3.18. Android now has strict Gradle locks, SHA-256 artifact verification, a reproducible release-runtime inventory, and a SHA-pinned OSV Scanner v2.5.1 blocking gate with zero current runtime findings. Its separate complete plugin/build-tool audit still reports upstream findings and intentionally remains non-blocking pending triage, remediation, or time-bounded accepted-risk decisions. Vulnerability database timestamp evidence and the cross-repository exception policy also remain open. |
| SR-004 | Medium | EVIDENCE | Server publishes the canonical `SECURITY.md`; Android and Chrome link to it from repository-local policies and expose component-specific private-report links. All three repositories have GitHub Private Vulnerability Reporting enabled. The policy states that no production version is currently supported, defines response targets, coordinated disclosure, research boundaries, report hygiene, and future security-update trust. Release-baseline verification remains required. |
| SR-005 | High | OPEN | Remove the frozen `/v1/devices/register`/`legacy_active` trust path before release, or obtain explicit review and a migration/disable policy proving it cannot become a parallel trust source. |
| SR-006 | Medium | PARTIAL | Review Android HPKE private-scalar unwrap, in-memory copies, zeroization limits, crash diagnostics, and the absence of hardware-backed P-256 HPKE operations. |
| SR-007 | High | PARTIAL | Define and test encrypted, access-controlled, off-host authority-key plus consistent-registry backup/restore operations; the PKCS#8 file itself is currently unencrypted. |
| SR-008 | Medium | PARTIAL | Inventory and disclose sensitive endpoint-local plaintext. Chrome necessarily persists decrypted notification/reconciliation state and raw transport credentials in its profile; establish retention, clearing, profile-compromise, and diagnostic policy. |
| SR-009 | Medium | OPEN | Complete and verify an Android release-signing-key backup on a separate encrypted physical or otherwise independently durable medium. |
| SR-010 | Medium | OPEN | Decide deployment-aware trusted-proxy handling and configurable connection/rate limits; test that proxy headers cannot bypass or collapse abuse controls. |
| SR-011 | High | EXTERNAL | Review registration → possession proof → approval → promotion → `SNO1`, including interruption, replay, concurrent approval/revocation, and stale MV3 Worker deployment. |
| SR-012 | High | EXTERNAL | Review relay retention, cumulative ACK, eviction, `SNR1`, fixed high-water snapshot recovery, and certified source-key replacement failure. |
| SR-013 | Medium | OPEN | Implement reproducible static and runtime scans for credentials and unexpected business plaintext in Server logs/SQLite/WAL/URLs and client diagnostics/storage, with explicit expected-local-plaintext allowlists. |
| SR-014 | Medium | PARTIAL | Every external Action reference is pinned to an immutable 40-character commit and CI rejects tag/branch references. All retained Actions use Node.js 24. Internal source review removed the redundant unsigned `setup-android` after its production dependencies reported a High finding. The unsigned emulator Action reproduced its committed JavaScript, uses fixed workflow inputs with a read-only job, and retains a visible Moderate `uuid` finding whose affected buffered API is not reached; it has a 2026-09-29 recheck deadline. Independent review and release-channel provenance/signing verification remain open. |
| SR-015 | High | OPEN | Keep third-party notification transport disabled until security findings and two-real-Android OEM/network validation are complete and a reviewed release explicitly changes the gate. |

Accepted-risk decisions must name the affected product claim. “Self-hosted” or
“uses E2EE” is not by itself a disposition for any finding.

## 4. Architecture and trust claims

- [ ] **A-01 — Single trust source.** Confirm ADR-005 authority-signed workspace
  membership is the only runtime source of device identity, role, and revocation.
  Search for bilateral approved-peer, `sntrust1:`, and legacy fallbacks in all
  business sender/receiver paths. (`EXTERNAL`; SR-005)
- [ ] **A-02 — Relay separation.** Confirm the relay never parses or branches on
  encrypted business message type, title, body, reply, action, removal, ACK,
  media, snapshot request, or recovery request ID. Start with
  `server/internal/relay/` and `server/protocol/encrypted-envelope-v1.md`.
  (`EVIDENCE`)
- [ ] **A-03 — Metadata claim.** Confirm documentation and UI do not claim to hide
  workspace/device routing, timing, size, queue, cursor, or IP metadata.
  (`PARTIAL`)
- [ ] **A-04 — Endpoint-compromise boundary.** Confirm product claims do not imply
  protection after arbitrary code execution in an authorized Android/Chrome
  endpoint or after malicious authority approval. (`PARTIAL`; SR-006, SR-008)
- [ ] **A-05 — Three-repository consistency.** Verify canonical Server protocol
  assets match Android/Chrome vendored assets and recorded SHA-256 values at the
  immutable baseline. (`EVIDENCE`)

## 5. Protocol encoding and cryptography

Primary references:

- `server/docs/adr/ADR-001-protocol-encoding-and-versioning.md`;
- `server/docs/adr/ADR-002-device-identity-and-e2ee.md`;
- `server/protocol/routing-header-v1.md`;
- `server/protocol/encrypted-envelope-v1.md`;
- `server/protocol/encrypted-payload-v1.md`;
- `server/protocol/test-vectors/`.

- [ ] **C-01 — Suite construction.** Verify RFC 9180 mode, KEM/KDF/AEAD identifiers,
  Auth HPKE sender authentication, public-key validation, and platform library
  behavior against the RFC and independent vectors. (`EXTERNAL`; SR-001)
- [ ] **C-02 — Domain separation.** Enumerate every `info`, AAD, signature input,
  hash preimage, and key-ID derivation. Confirm distinct protocols cannot accept
  each other's bytes. (`EXTERNAL`; SR-001)
- [ ] **C-03 — Canonical encodings.** Fuzz fixed binary frames and canonical
  protobuf decoders for duplicate fields, unknown fields, overlong varints,
  non-canonical order/defaults, truncation, trailing bytes, size/count overflow,
  and decode/re-encode ambiguity. (`PARTIAL`; SR-001)
- [ ] **C-04 — Routing binding.** Verify workspace, sender, recipient, key IDs,
  sequence, and relevant schema/version are authenticated and checked against
  authority state before plaintext is used. (`EVIDENCE`)
- [ ] **C-05 — Per-recipient encryption.** Prove fanout creates a fresh envelope
  for each exact recipient and does not reuse a shared workspace content key.
  (`EVIDENCE`)
- [ ] **C-06 — Sequence and replay.** Verify allocation durability, crash behavior,
  duplicate/concurrent receive behavior, sender-key transitions, and separation
  from notification revision, relay cursor, and operation idempotency.
  (`EVIDENCE`)
- [ ] **C-07 — Randomness and nonce safety.** Trace all random inputs for identities,
  HPKE encapsulation, credentials, pairing/rotation codes, operation IDs, and
  request IDs. Verify no test fixture RNG reaches production. (`EXTERNAL`; SR-001)
- [ ] **C-08 — Error oracles.** Review cryptographic and HTTP errors for useful
  recipient/key/proof oracles, timing distinctions, and accidental plaintext.
  (`PARTIAL`)
- [ ] **C-09 — Forward-secrecy claim.** Confirm documentation explicitly states
  that compromise of a long-lived recipient identity key can expose historical
  captured application envelopes for that key. Decide whether this is acceptable
  for v1. (`PARTIAL`)
- [ ] **C-10 — Chrome Ed25519 fallback.** Verify fallback occurs only for explicit
  WebCrypto `NotSupportedError`, uses fixed `@noble/curves` behavior with
  `{ zip215: false }`, and fails closed for all other errors. (`EVIDENCE`)

## 6. Authority, roster, role, and revocation

Primary references:

- `server/docs/adr/ADR-005-centralized-workspace-membership-authority.md`;
- `server/protocol/workspace-membership-v1.md`;
- `server/docs/workspace-authority-key-lifecycle.md`.

- [ ] **M-01 — Certificate binding.** Verify every certificate binds exact
  workspace, device ID/type, role set, HPKE key and key ID, validity/lifecycle
  fields, and authority identity without substitution ambiguity. (`EVIDENCE`)
- [ ] **M-02 — Roster canonicality.** Verify sort order, uniqueness, count limits,
  epoch/digest chaining, revocation representation, and signature input.
  (`EVIDENCE`)
- [ ] **M-03 — Rollback floors.** Verify authority and roster floors are committed
  before dependent business state, survive restart, and reject older Server,
  backup, or cached Worker state. (`EVIDENCE`)
- [ ] **M-04 — Authority rotation.** Verify old/new double signatures, previous
  digest/key/epoch, exact next activation roster, time semantics, interruption,
  partial rollout, and offline-device recovery. (`EXTERNAL`; SR-001)
- [ ] **M-05 — Equivocation.** Determine what a malicious authority/Server can do
  by signing different same-epoch or divergent roster views. Verify detection,
  operational visibility, and recovery claims. (`OPEN`; SR-001)
- [ ] **M-06 — Role enforcement.** For every payload type, list allowed sender and
  recipient roles and verify both sender construction and receiver acceptance.
  (`EVIDENCE`)
- [ ] **M-07 — Revocation window.** Reproduce DB commit to active-socket close and
  reconnect denial. Confirm the product states the bounded approximately 250 ms
  plus query window, not zero-window revocation. (`EVIDENCE`)
- [ ] **M-08 — Key replacement.** Verify a same-device HPKE key replacement cannot
  be silently accepted by an active send, receive, or recovery session.
  (`EVIDENCE`)
- [ ] **M-09 — Authority custody.** Verify the private key is absent from ordinary
  business SQLite and relay hot paths; review file permission checks, symlink and
  file-replacement handling, process access, backup, restore, and deletion.
  (`PARTIAL`; SR-007)

## 7. Registration, proof, approval, and transport authentication

Primary references:

- `server/docs/membership-http-v1.md`;
- `server/docs/adr/ADR-004-private-admission-and-transport-auth.md`;
- `server/protocol/device-auth-frame-v1.md`;
- `server/protocol/transport-credential-rotation-v1.md`.

- [ ] **R-01 — Registration default.** Verify there is no open registration mode;
  only an administrator-issued, short-lived, single-use code can start
  registration. (`EVIDENCE`)
- [ ] **R-02 — Strict HTTP.** Verify exact `POST application/json`, bounded body and
  response, unknown/duplicate/trailing-field rejection, canonical unpadded
  Base64URL, canonical decimal epoch, and redirect rejection in both clients.
  (`EVIDENCE`)
- [ ] **R-03 — Credential placement.** Verify pairing codes, transport credentials,
  rotation codes, and auth tokens never enter URLs, redirects, referrers, or
  routine Server logs. (`PARTIAL`; SR-013)
- [ ] **R-04 — Possession proof.** Verify the challenge proves possession of the
  exact submitted HPKE key and is bound to workspace/device/registration state,
  expiry, and single use. Review replay and chosen-key behavior. (`EXTERNAL`;
  SR-011)
- [ ] **R-05 — State-machine interruption.** Kill/restart Server, Android process,
  and MV3 Worker before and after every durable registration transition. Verify
  no pending record is promoted without proof and approval. (`PARTIAL`; SR-011)
- [ ] **R-06 — Approval race.** Test duplicate/concurrent approval, proof versus
  revocation, approval versus expiry, and stale admin references. (`EVIDENCE`)
- [ ] **R-07 — Pending isolation.** Prove `pending_proof` and `pending_approval`
  records cannot establish business relay or appear as authorized recipients.
  (`EVIDENCE`)
- [ ] **R-08 — Exact `SNO1`.** Verify clients do not report authenticated/online or
  promote pending credentials for timeout, socket open, arbitrary bytes, or any
  acknowledgement other than exact `SNO1`. (`EVIDENCE`)
- [ ] **R-09 — Credential rotation.** Verify exact-device binding, current proof,
  client-generated pending secret, atomic switch, versioned active-socket close,
  response-loss recovery, and no identity replacement. (`EVIDENCE`)
- [ ] **R-10 — Legacy endpoint.** Determine whether `/v1/devices/register` and
  `legacy_active` can be removed before release. If retained, prove new clients
  cannot consume it and it cannot authorize a parallel un-certified business
  identity. (`OPEN`; SR-005)
- [ ] **R-11 — Abuse controls.** Test source-address derivation, proxy behavior,
  bounded limiter memory, registration/rotation/connection floods, slow body,
  slow WebSocket auth, and reconnect storms. (`PARTIAL`; SR-010)

## 8. Relay delivery, cursor, and snapshot recovery

Primary references:

- `server/protocol/relay-delivery-v1.md`;
- `server/docs/adr/ADR-003-chrome-realtime-connection-and-recovery.md`.

- [ ] **D-01 — Explicit durability.** Verify bare `SNE1` is online-only and only
  `SNQ1 || SNE1` permits durable retention. Reply and both snapshot directions
  must remain bare `SNE1`. (`EVIDENCE`)
- [ ] **D-02 — Opaque persistence.** Inspect SQLite schema and relay code to confirm
  durable rows contain ciphertext plus required routing/delivery metadata, not
  parsed business fields. (`EVIDENCE`)
- [ ] **D-03 — Recipient scope.** Verify delivery IDs/cursors are scoped to exact
  `(workspaceId, recipientDeviceId)` and cannot acknowledge another recipient's
  queue. (`EVIDENCE`)
- [ ] **D-04 — Commit/ACK order.** Verify Server commits before delivery and Chrome
  advances/ACKs only after authenticated decode, durable business reconciliation,
  and required presentation. Test crash at each boundary. (`EVIDENCE`)
- [ ] **D-05 — Duplicate delivery.** Deliver duplicate `SND1`, reconnect around
  ACK loss, and reorder frames. Confirm replay/business state remains convergent.
  (`EVIDENCE`)
- [ ] **D-06 — Queue limits.** Reproduce the 4,096-delivery and 64 MiB per-recipient
  bounds, exact eviction ordering, queue-byte accounting, and resulting gap.
  Review ciphertext-size and recipient-amplification denial of service.
  (`PARTIAL`; SR-012)
- [ ] **D-07 — `SNR1` semantics.** Confirm reset high-water alone never advances a
  cursor or skips missing business history. (`EVIDENCE`)
- [ ] **D-08 — Fixed recovery session.** Confirm recovery durably pins request ID,
  exact high-water, expected sources, exact authority-certified source key IDs,
  and completed sources. (`EVIDENCE`)
- [ ] **D-09 — Recovery authorization changes.** Revoke or replace a source during
  recovery and verify fail-closed behavior without silent key substitution or
  premature reset acceptance. (`EVIDENCE`)
- [ ] **D-10 — Reverse-gap prevention.** Verify snapshot requests/responses cannot
  themselves enter durable history and create an endless reverse recovery gap.
  (`EVIDENCE`)
- [ ] **D-11 — Recovery availability.** Document behavior when a certified source
  is offline forever, revoked, destroyed, or has lost snapshot state. Confirm no
  unsafe “skip” UX is presented as successful reconciliation. (`PARTIAL`)

## 9. Notification, operation, and media semantics

- [ ] **O-01 — Notification identity.** Verify state keys use source device plus
  notification identity and revision, so identical package/local IDs from two
  Android devices do not collide. (`EVIDENCE`)
- [ ] **O-02 — Revision monotonicity.** Test old upsert after removal, duplicate
  revision, removed-without-revision, restart, and snapshot high-water boundaries.
  (`EVIDENCE`)
- [ ] **O-03 — Exact action binding.** Verify every Chrome button/reply/dismiss is
  bound at presentation time to exact notification ID, revision, action ID, and
  source; later shortcut-setting changes must not reinterpret a button index.
  (`EVIDENCE`)
- [ ] **O-04 — Execute once.** Test duplicate operations in parallel and after
  Android process restart. A fresh envelope tuple with the same canonical payload
  and business idempotency key must not repeat a side effect. (`EVIDENCE`)
- [ ] **O-05 — Stale operation.** Verify action, reply, and clear against an old
  revision fail without affecting the current notification. (`EVIDENCE`)
- [ ] **O-06 — Terminal uncertainty.** Verify `OUTCOME_UNKNOWN` is never displayed
  as success and never automatically or explicitly re-executed. (`EVIDENCE`)
- [ ] **O-07 — Reply boundary.** Verify reply is online-only, one-shot, absent from
  durable alarm drain, and has no resend UI. (`EVIDENCE`)
- [ ] **O-08 — Android capabilities.** Confirm raw `PendingIntent`, `RemoteInput`,
  intents, component names, and capability tokens never leave Android.
  (`EXTERNAL`)
- [ ] **O-09 — Media bounds.** Fuzz decoding and normalization around PNG-only,
  256 px longest side, 128 KiB item limit, exact SHA-256, malformed images,
  decompression/resource abuse, and text fallback. (`PARTIAL`)
- [ ] **O-10 — Platform impersonation.** Confirm Chrome does not synthesize actions
  the source notification did not expose and labels SevenMirror-owned interaction
  surfaces appropriately. (`PARTIAL`)

## 10. Key, credential, and local-data storage

- [ ] **K-01 — Android HPKE wrapping.** Review AES-GCM key generation and alias,
  nonce generation, public-key AAD, backup exclusion, missing/corrupt wrapper,
  key invalidation, restore, and fail-closed identity mismatch. (`PARTIAL`;
  SR-006)
- [ ] **K-02 — Android scalar lifetime.** Trace every HPKE private-key byte array and
  copy through sender/receiver/error paths. Assess best-effort zeroization and
  JVM/native-library copies without claiming guaranteed memory erasure.
  (`PARTIAL`; SR-006)
- [ ] **K-03 — Android transport credentials.** Verify wrapping, dual-slot rotation,
  backup exclusion, log/exception behavior, and fail-closed corruption.
  (`EVIDENCE`)
- [ ] **K-04 — Chrome HPKE identity.** Verify production generates and restores a
  non-extractable P-256 `CryptoKey`, rejects extractable/mismatched keys, and uses
  fallback only as documented. (`EVIDENCE`)
- [ ] **K-05 — Chrome profile secrets.** Inventory raw transport credentials,
  pending membership state, operation payloads, decrypted notification state,
  and reply text in IndexedDB/storage. Define retention and clearing semantics;
  document that OS/profile compromise exposes them. (`PARTIAL`; SR-008)
- [ ] **K-06 — Identity loss.** Delete/corrupt identity stores or create transport
  binding mismatch. Confirm both clients fail closed and require revocation plus
  new registration rather than silent replacement. (`EVIDENCE`)
- [ ] **K-07 — Authority key file.** Test restrictive permissions, regular-file and
  symlink handling, oversized/corrupt PKCS#8, wrong public key, missing file, and
  restore consistency. (`EVIDENCE`; operational protection remains SR-007)
- [ ] **K-08 — Authority backup.** Perform an encrypted off-host backup and restore
  drill using a consistent authority registry, verify manifest/digest, and prove
  an old backup cannot silently roll clients back. (`OPEN`; SR-007)
- [ ] **K-09 — Release-signing keys.** Verify repository exclusions, CI secret
  scope, fixed Android certificate fingerprint, Chrome packaging/update policy,
  rotation/recovery, and independently durable encrypted backup. (`PARTIAL`;
  SR-009, SR-014)

## 11. Plaintext, credential, log, and diagnostic audit

The scan must distinguish forbidden leakage from expected endpoint-local data.
A blanket search for words such as `title` is not sufficient, and public fixed
vectors are not secrets.

- [ ] **P-01 — Tracked-secret scan.** All three CI workflows use full-history
  checkout plus SHA-pinned Gitleaks Action v3.0.0/scanner v8.30.1. The local
  baseline found only deterministic public protocol vectors and four exact
  Server documentation false positives; narrow path/fingerprint exclusions make
  the rescans clean. Independently review every exclusion and rerun on the exact
  release commits. (`EVIDENCE`; SR-002)
- [ ] **P-02 — Server logs.** Exercise success and all validation/error paths with
  unique canary credentials and business strings. Confirm structured Server logs
  and HTTP errors contain neither canary. (`PARTIAL`; SR-013)
- [ ] **P-03 — Admin stdout.** Confirm one-time pairing/rotation codes are emitted
  only by explicit admin commands to the operator's stdout, never copied to
  routine Server logs. Document terminal history, CI log, and support-bundle
  handling. (`PARTIAL`; SR-013)
- [ ] **P-04 — Server SQLite/WAL.** Search a live and cleanly shut down database,
  WAL, SHM, backup, and temporary files for raw canary credentials and business
  plaintext. Expected result: hashed admission secrets and opaque business
  ciphertext only. (`PARTIAL`; existing hash-only tests; SR-013)
- [ ] **P-05 — URLs and redirects.** Capture HTTP/WebSocket requests and ensure
  credentials occur only in protected bounded bodies/auth frames, never URL,
  query, fragment, redirect target, or referrer. (`PARTIAL`; SR-013)
- [ ] **P-06 — Android diagnostics.** Search logcat, crash/error strings,
  SharedPreferences/databases, Auto Backup, screenshots, and exported debug
  artifacts using canaries. Classify intentional local state. (`OPEN`; SR-013)
- [ ] **P-07 — Chrome diagnostics.** Search service-worker/page console, extension
  errors, IndexedDB/storage, notifications, crash artifacts, and exported profile
  data using canaries. Classify expected local plaintext and ensure options/popup
  diagnostics do not expose secrets. (`OPEN`; SR-008, SR-013)
- [ ] **P-08 — Test evidence hygiene.** Scan `.tools` acceptance artifacts before
  sharing. Redact credentials, private keys, notification plaintext, and full
  private device/workspace IDs; do not mutate canonical raw evidence without
  preserving access-controlled originals and documenting redaction. (`OPEN`)
- [ ] **P-09 — Retention and deletion.** Define queue retention, client state
  retention, revocation cleanup, uninstall/profile deletion, backup inclusion,
  and support artifact retention. Verify implementation and privacy text.
  (`OPEN`; SR-008)

## 12. Input handling, denial of service, and deployment

- [ ] **S-01 — Parser fuzzing.** Run maintained fuzz/property tests over every
  relay frame, routing header, envelope, canonical protobuf payload, membership
  object, and strict JSON endpoint. (`PARTIAL`)
- [ ] **S-02 — Resource bounds.** Verify HTTP/WebSocket body/frame, ciphertext,
  media, roster/revocation, queue, connection, pending registration, and database
  growth limits, including integer overflow and many-recipient amplification.
  (`PARTIAL`)
- [ ] **S-03 — TLS/WSS policy.** Verify non-loopback plaintext endpoints are
  rejected, redirects are not followed, hostname/private-CA validation is exact,
  and production builds cannot silently trust debug CAs. (`EVIDENCE`)
- [ ] **S-04 — Reverse proxy.** Test direct deployment and supported proxy
  deployment. Define which forwarded headers, if any, are trusted and only from
  configured proxy addresses. (`OPEN`; SR-010)
- [ ] **S-05 — Security headers/origin.** Review HTTP response headers, WebSocket
  origin policy and browser applicability, caching of credential responses, and
  content-type sniffing. (`OPEN`)
- [ ] **S-06 — Database failure.** Test disk full, WAL failure, corruption, partial
  migration, backup restore, queue write/ACK races, and fail-closed startup.
  (`PARTIAL`)
- [ ] **S-07 — Time behavior.** Review wall-clock use for expiry and authority
  transitions under clock rollback/forward, suspend, and malicious Server time.
  (`PARTIAL`)
- [ ] **S-08 — Operational least privilege.** Define Server OS account, data/key
  directory ownership, file modes, backup account, network exposure, container
  user/filesystem, and log access. (`OPEN`)

## 13. Supply chain, CI, and releases

- [ ] **B-01 — Dependency inventory.** Produce locked Go, npm, Gradle/plugin, GitHub
  Action, base-image, and cryptographic-library inventory for the baseline.
  (`PARTIAL`)
- [ ] **B-02 — Vulnerability scan.** Server CI runs `govulncheck v1.1.4` against
  reachable Go code. Its first run found 12 reachable standard-library findings
  under Go 1.24.13; `go.mod`, CI, and the container builder now enforce the fixed
  Go 1.25.13 floor. Chrome CI runs `npm audit --audit-level=high` against the
  lockfile; the initial `nanoid < 3.3.18` High finding was remediated. Android
  locks real build/test/runtime classpaths in strict mode, verifies artifact
  SHA-256 metadata, regenerates an exact 90-package release-runtime inventory,
  and runs SHA-pinned OSV Scanner v2.5.1. The release-runtime gate currently has
  zero findings. A separate scan of the complete 472-package artifact/plugin
  metadata reports 21 affected build-tool packages and 86 vulnerability records;
  it remains non-blocking so these upstream findings stay visible rather than
  being broadly ignored or mislabeled as APK runtime vulnerabilities. Triage,
  remediation or time-bounded accepted-risk decisions, vulnerability database
  timestamp evidence, and the cross-repository exception policy remain
  open. (`PARTIAL`; SR-003)
- [ ] **B-03 — Secret scan gate.** All three pull-request/push workflows now scan
  full Git history using Gitleaks Action v3.0.0 pinned to commit
  `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e` and scanner v8.30.1. The sole path
  allowlist covers published deterministic protocol vectors; Server document
  false positives are exact fingerprints. Independent exclusion review remains
  required. (`EVIDENCE`; SR-002)
- [ ] **B-04 — CI action trust.** Every external Action is pinned to an immutable
  40-character commit, and each primary CI job rejects future tag/branch refs.
  Retained Actions use Node.js 24, and GitHub verifies the selected official
  `actions/*` commits. Internal review of the two unsigned Android Actions is
  recorded in `android-third-party-actions.md`: the redundant `setup-android`
  was removed after its locked `undici` reported a High finding; the emulator
  Action's committed JavaScript reproduced exactly and its Moderate `uuid`
  finding is not reachable through the reviewed no-buffer call paths. The
  emulator job now has only `contents: read`, and monthly/pre-release review is
  required. Independent review remains required. (`EVIDENCE`; SR-014)
- [ ] **B-05 — Generated/vendored protocol.** Verify generation is reproducible,
  diffs are reviewed, upstream hashes fail closed, and temporary generator tools
  cannot enter releases accidentally. (`PARTIAL`)
- [ ] **B-06 — Artifact signing/provenance.** Verify Android certificate identity,
  Chrome extension packaging/update identity, Server image/binary provenance,
  checksums/attestations, and rollback policy. (`PARTIAL`; SR-014)
- [ ] **B-07 — Vulnerability intake.** All three public repositories enable
  GitHub Private Vulnerability Reporting and publish repository-local
  `SECURITY.md` entry points. Server owns the single canonical policy; it states
  that `0.1.x-dev` has no production support, targets acknowledgement within 3
  business days and initial triage within 7 calendar days, defines coordinated
  disclosure and research boundaries, and rejects credentials or real
  notification content in reports. Verify the links and policy against the
  release baseline. (`EVIDENCE`; SR-004)
- [ ] **B-08 — License and dependency policy.** Confirm cryptographic and fallback
  dependency versions/licenses are fixed as documented and upgrades require
  vectors plus security review. (`EVIDENCE`)

## 14. Product gates and release validation

- [ ] **G-01 — Synthetic-only enforcement.** Inspect release source and artifact to
  prove network fanout accepts only SevenMirror's app-owned notification. No
  debug flag, remote config, or UI control may enable third-party content.
  (`EVIDENCE`; SR-015)
- [ ] **G-02 — Two-real-device matrix.** Complete two physical Android devices
  across relevant OEM background restrictions, battery optimization, process
  death, notification behavior, and real network transitions with two independent
  Chrome identities. (`OPEN`; SR-015)
- [ ] **G-03 — Enrollment UX.** Ensure future Camera QR carries only an
  authority-registration bootstrap and does not revive `sntrust1:` bilateral
  trust. Review shoulder-surfing, code expiry, origin binding, and approval
  confirmation before implementation. (`OPEN`)
- [ ] **G-04 — User-facing privacy.** Explain what content leaves Android, which
  authorized devices receive it, metadata visible to the relay, local Chrome
  retention, revocation limits, and how to revoke/re-enroll after key loss.
  (`OPEN`)
- [ ] **G-05 — Diagnostic separation.** Confirm production UI does not expose raw
  credentials, private IDs, protocol enums, replay/cursor internals, test actions,
  or raw exceptions. Keep required diagnostics access-controlled or development
  only. (`PARTIAL`)
- [ ] **G-06 — Compatibility decision.** Decide the pre-v1 upgrade window,
  fail-closed behavior for unsupported bytes/state, and migration policy before
  declaring protocol v1 frozen. (`OPEN`; SR-001)
- [ ] **G-07 — Independent conclusion.** Obtain a report that explicitly covers
  all three clients/server, all unresolved findings, and whether third-party
  notification transport may be enabled. (`OPEN`; SR-001, SR-015)

## 15. Minimum reproducible evidence bundle

The final review record should contain commands/tool versions and sanitized
results for at least:

1. all three repositories' clean status and full commit IDs;
2. Server Go tests, static analysis, protocol vectors, race/concurrency tests,
   and selected fuzz runs;
3. Android unit/lint/build checks plus relevant instrumented Keystore/storage/
   receiver tests on named API levels;
4. Chrome typecheck/lint/tests/build and runtime non-extractable-key checks;
5. cross-client canonical vector verification;
6. secret-history and current-tree scans;
7. dependency vulnerability scans with triage;
8. Server canary scans over logs, URL captures, SQLite/WAL/SHM, backup, and
   ciphertext queue;
9. Android/Chrome canary scans with expected local-plaintext classification;
10. registration interruption/race matrix;
11. revocation and authority-rotation rollback/equivocation matrix;
12. queue eviction/cursor/ACK/snapshot source-key matrix;
13. immutable release artifact identities and signing/provenance verification;
14. two-real-Android plus two-Chrome release validation.

Evidence must not publish raw tokens, pairing/rotation codes, private keys,
notification/reply plaintext, private CA/signing material, or full private device
identifiers. Use unique non-secret canary labels and truncated/digested identifiers
where correlation is required.

## 16. Sign-off

The gate remains closed unless all of the following are true:

- [ ] every checklist item is reviewed or linked to a documented finding;
- [ ] every Critical/High finding is `RESOLVED` or explicitly `ACCEPTED RISK` by
  an authorized owner with compatible product claims;
- [ ] Medium findings have remediation or time-bounded accepted-risk decisions;
- [ ] secret, dependency, and plaintext/credential scans are reproducible on the
  immutable release candidate;
- [ ] artifact signing/provenance and operational backup recovery are verified;
- [ ] the two-real-Android release matrix passes;
- [ ] the independent reviewer signs the exact commits and report digest;
- [ ] the final decision explicitly authorizes or rejects enabling third-party
  notification transport.

Until then, SevenMirror remains a synthetic-notification Alpha and the protocol
remains provisional.
