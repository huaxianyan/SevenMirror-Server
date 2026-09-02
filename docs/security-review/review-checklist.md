# SevenMirror security review checklist

Status: internal evidence index; all independent-review boxes are initially open

Last updated: 2026-09-02

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
| SR-003 | Medium | PARTIAL | Server's pinned govulncheck emits bounded JSON evidence and rejects stale/future vuln.go.dev state, toolchain drift or reachable findings; 19 current module-only informational IDs remain visible beside reachable count zero. Run `33584395156` confirmed 20 base-image findings per builder architecture（2 High／6 Medium／12 Low）and zero findings in both runtime architectures. High `CVE-2026-14456` remains in builder-only Alpine `libcrypto3`／`libssl3` `3.5.7-r0`; fixed `3.5.8-r0` is not yet in the pinned upstream index. Build-stage findings remain visible as non-shipped build-tool inventory while runtime Critical／High findings block; the Server finding still needs remediation or independent disposition before production. Registry run `33587546197` pulled the published index back by digest, matched the pre-publication graph, scanned both served runtime manifests with zero findings, and produced 8 evidence subjects that passed offline and attestation verification. The canonical exception registry remains empty. Chrome's locked npm audit evidence currently reports zero findings. Android protected run `33629467649` bound one OSV Scanner 2.5.1 command to the exact 90-package runtime and 372-package complete inventories at revision `f077ad0607a71d39f64ee5554baeb61ff3b73e00`; runtime remains 0 affected／0 findings and build tooling remains 2／2, with scanner/provider identity, input/inventory hashes, complete report and honest command-completion time while provider database time stays explicitly null. The downloaded evidence passed the checked-in offline verifier. Audited resolution pins followed by the AGP `9.4.0`／Gradle `9.6.0` built-in Kotlin migration removed the four AGP 8.13 detached-tooling affected versions without ignores, reducing the build-tool baseline from 21 affected packages／86 records to 2／2. Both residual records are `GHSA-r937-wjx7-w2jp` for Kotlin Gradle Plugin `2.2.10` and `2.3.20`; upstream stable Kotlin ends at `2.4.10`, while the first fixed version is pre-release `2.4.20-Beta1`. The upstream fix is confined to unsafe KAPT incremental-cache deserialization. Android verifies that `2.2.10` is metadata-only, resolves the executable plugin to `2.3.20`, and has no KAPT plugin, dependency or task. CI and protected release now fail if any KAPT task appears, incremental KAPT is enabled or Gradle build caching is enabled. This is an enforced reachability mitigation, not an exception or independent risk acceptance; both package records remain open until a compatible stable fix or independent exact, time-bounded disposition. These two packages, the Server builder finding and remaining release-channel scans remain open. |
| SR-004 | Medium | EVIDENCE | Server publishes the canonical `SECURITY.md`; Android and Chrome link to it from repository-local policies and expose component-specific private-report links. All three repositories have GitHub Private Vulnerability Reporting enabled. The policy states that no production version is currently supported, defines response targets, coordinated disclosure, research boundaries, report hygiene, and future security-update trust. Release-baseline verification remains required. |
| SR-005 | High | EVIDENCE | `/v1/devices/register` is no longer mounted. Schema v8 revokes historical `legacy_active` rows, removes their outstanding rotation codes, and installs insert/update rejection triggers. Authentication, session authorization, rotation-code issuance, and rotation now require `approved`. Unit tests cover route absence, migration rejection, credential denial, and schema enforcement; the real-binary canary also requires legacy-route `404`. Release-baseline execution and independent review remain required. |
| SR-006 | Medium | PARTIAL | Review Android HPKE private-scalar unwrap, in-memory copies, zeroization limits, crash diagnostics, and the absence of hardware-backed P-256 HPKE operations. |
| SR-007 | High | PARTIAL | The admin CLI now uses SQLite's online backup API to atomically package a consistent registry snapshot with the exact authority key selected from that snapshot. Canonical nested manifests, digests, SQLite integrity/schema checks, authority derivation, exact entries, permissions, exclusive restore and rollback cleanup fail closed. A real-binary CI canary deletes the live state, restores both artifacts into empty destinations, and creates a second verified backup. The PKCS#8 remains intentionally unencrypted; an access-controlled encrypted off-host system, retrieval evidence, stale-backup/rollback drill and independent review remain required. |
| SR-008 | Medium | PARTIAL | Chrome inventories raw credentials, non-extractable identity keys, decrypted notification/action state, reply retention, `chrome.storage`, URL/UI surfaces, profile-compromise limits, and deletion gaps. The isolated profile canary covers extension IndexedDB placement, restart, native notifications, diagnostics, `chrome.storage`, interaction URL and closed-profile export. The non-headless Cent Browser check now drives the built page through the unmodified production Worker using a verified authority-signed Chrome／Android roster. It covers target/source rendering, exact reply/revision/action binding, certified Android recipient resolution, canonical schema-v2 one-shot pending-action persistence, immediate input clearing and URL/diagnostic absence without adding a production debug endpoint. Product retention/clearing, a pinned CI browser artifact, live relay/Android execution, backup/sync, crash/memory, IME and OS-notification-history evidence remain open. |
| SR-009 | Medium | OPEN | Complete and verify an Android release-signing-key backup on a separate encrypted physical or otherwise independently durable medium. |
| SR-010 | Medium | PARTIAL | Server accepts one canonical `X-Forwarded-For` address only from explicitly configured canonical proxy CIDRs; direct peers ignore forwarded headers. Membership, rotation and relay-auth attempt rates, bounded client buckets, concurrent unauthenticated sockets, HTTP header/body reads and `SNA1` wait are configurable with finite defaults and fail-closed validation. Real-process CI covers trusted-address isolation, per-endpoint limits, bucket exhaustion, pre-auth capacity and slow termination. A separate regression gate runs four 32-client reconnect waves, re-establishes 32 sessions, delivers 2,000 exact online ciphertext frames, then commits／delivers／cumulatively acknowledges 500 durable SQLite-backed frames and bounds RSS plus post-cleanup descriptors／handles. Distributed limiter/proxy topologies, actual TLS/load-balancer/container/storage/network capacity, durable-delivery load, sustained production duration and operator firewall validation remain open. |
| SR-011 | High | EXTERNAL | Review registration → possession proof → approval → promotion → `SNO1`, including interruption, replay, concurrent approval/revocation, and stale MV3 Worker deployment. |
| SR-012 | High | EXTERNAL | Review relay retention, cumulative ACK, eviction, `SNR1`, fixed high-water snapshot recovery, and certified source-key replacement failure. |
| SR-013 | Medium | PARTIAL | Server CI exercises real pairing/rotation issuance, authority registration, legacy-route `404`, credential rotation, WebSocket authentication and sensitive-state scans. Separate gates cover pinned Caddy TLS/WebSocket/trusted-proxy/reduced logs, consistent local workspace backup/restore, and an aggregate-only support summary derived from real runtime/access logs. The summary drops raw events, details, paths and admin output; the dynamic canary scans it with the same credentials and business plaintext. Android API 29 scans real Keystore-backed stores. Chrome combines deterministic stores, a closed real-profile scan and a local non-headless production-Worker interaction check. External backup transport/retention, real container log drivers/exporters/support portals/operator terminal retention, certificate/log-retention evidence, a pinned Chrome CI browser, Chrome crash/memory/sync/OS artifacts, Android privileged/system/business artifacts and release-baseline execution remain open. |
| SR-014 | Medium | PARTIAL | Every external Action reference is pinned to an immutable 40-character commit and CI rejects tag/branch references. Server protected run `33587546197` published verified OCI layouts to the public, repository-linked GHCR package without rebuilding, computed index digest `sha256:37499955cf4b8e18b4f008d1d35425c41d2faeeeb2d3e7b9f8e5ca4c46817f9d` before upload, pulled it back by digest, matched both platform graphs and scanned both served runtimes. The 8 registry evidence subjects passed offline and attestation verification; a clean anonymous pull independently matched the complete graph. Chrome builds a deterministic file-inventoried submission ZIP; Android verifies one certificate DER plus embedded identity. All three release workflows use GitHub-verified `actions/attest v4.2.2`. Active no-bypass main rulesets and protected environments require PR／CI and explicit deployment approval, but the sole administrator still performs both dispatch and approval, so this is not independent release authority. GHCR retention/deletion/emergency-revocation policy, durable binary hosting, Chrome Web Store publication, Android distribution evidence, a second release approver and independent review remain open. |
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
- [ ] **R-03 — Credential placement.** The real-binary Server canary gate keeps
  pairing/rotation codes and current/pending credentials in bounded HTTP bodies
  or binary WebSocket auth frames, rejects redirects and query-bearing targets,
  and proves neither text nor decoded bytes enter effective targets, fixed
  errors, routine Server output or the test proxy access log. The separate real
  Caddy gate validates TLS termination, full WebSocket forwarding, exact proxy
  trust and a reduced method/path/status log without query, header or body
  canaries. Operator-specific log shipping and retention remain open.
  (`PARTIAL`; SR-013)
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
- [ ] **R-10 — Legacy endpoint removal.** Confirm `/v1/devices/register` is not
  mounted, schema v8 fail-closed revokes historical `legacy_active` rows and
  rejects recreation, and only `approved` devices can authenticate, rotate or
  remain routed. Repeat against the release baseline. (`EVIDENCE`; SR-005)
- [ ] **R-11 — Abuse controls.** Reproduce source-address derivation, configurable
  membership/rotation/relay-auth limits, bounded limiter memory, pre-auth capacity,
  and slow header/body/WebSocket-auth termination. CI also requires 160 successful
  reconnect/final authentications, 2,000 exact online deliveries, 500 exact
  durable deliveries with queue high-water／ACK-to-zero convergence, online and
  durable floors of 100／50 frames/s, RSS growth at most 128 MiB, and bounded
  descriptor／handle cleanup. Test distributed proxy coordination and the intended
  TLS/load-balancer/container/
  durable-delivery workload at production duration and capacity.
  (`PARTIAL`; single-process regression gates are `EVIDENCE`, remaining scope is SR-010)

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
- [ ] **K-03 — Android transport credentials.** Current, pending-rotation, and
  pending-enrollment tokens use distinct Keystore-backed AES-GCM persistence.
  API 29 canary instrumentation finds neither raw nor Base64 token bytes in
  mutable app-private state, generated errors, or own-process logcat; the
  release manifest disables backup. Physical-device backup/migration evidence
  remains required. (`EVIDENCE`; SR-013)
- [ ] **K-04 — Chrome HPKE identity.** Verify production generates and restores a
  non-extractable P-256 `CryptoKey`, rejects extractable/mismatched keys, and uses
  fallback only as documented. (`EVIDENCE`)
- [ ] **K-05 — Chrome profile secrets.** `docs/SENSITIVE_DATA.md` inventories raw
  transport/pending-membership credentials, the non-extractable identity,
  operation/reply payloads, decrypted notification state, `chrome.storage`, and
  URL/UI surfaces. It documents 30-day pending-action retention, indefinite
  notification revision state, current deletion gaps, and OS/profile-compromise
  exposure. `scripts/chrome_profile_canary.py` verifies the production MV3 origin
  across browser restart and closed-profile export; the non-headless interaction
  check crosses the production Worker with a verified signed roster and verifies
  target-only rendering, certified recipient resolution, exact canonical one-shot
  pending-action persistence, input clearing and URL/diagnostic absence. Product
  clearing, a pinned CI browser artifact, live relay/Android execution, backup/sync,
  crash/memory and OS-history controls remain open. (`PARTIAL`; SR-008)
- [ ] **K-06 — Identity loss.** Delete/corrupt identity stores or create transport
  binding mismatch. Confirm both clients fail closed and require revocation plus
  new registration rather than silent replacement. (`EVIDENCE`)
- [ ] **K-07 — Authority key file.** Test restrictive permissions, regular-file and
  symlink handling, oversized/corrupt PKCS#8, wrong public key, missing file, and
  restore consistency. (`EVIDENCE`; operational protection remains SR-007)
- [ ] **K-08 — Authority backup.** Reproduce the online SQLite snapshot plus exact
  authority binding, manifest/digest/integrity verification, exclusive isolated
  restore, and restored-state canary. Then perform an encrypted off-host retrieval
  drill and prove stale state cannot silently roll clients back. (`PARTIAL`; the
  local consistency/restore control is `EVIDENCE`, operational protection remains
  SR-007)
- [ ] **K-09 — Release-signing keys.** Android application/version and public
  certificate fingerprints now have one canonical checked-in identity consumed
  by Gradle and the APK verifier. CI requires all signing secrets, verifies one
  signer from certificate DER, binds APK metadata and removes reconstructed JKS
  state in an `always()` step. Verify protected release authority, repository
  administration/secret scope, Chrome store identity, rotation/recovery, and an
  independently durable encrypted Android key backup. (`PARTIAL`; SR-009,
  SR-014)

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
- [ ] **P-02 — Server logs.** CI exercises real binary startup/shutdown,
  registration, successful and replayed rotation, malformed business-canary
  inputs, and old/pending WebSocket authentication. Captured stdout/stderr and
  fixed HTTP errors contain no raw or encoded canary. The aggregate support
  summary retains only runtime level and method/status counts. Real container
  log drivers, exporters and release retention remain open. (`PARTIAL`; SR-013)
- [ ] **P-03 — Admin stdout.** The canary gate verifies explicit admin commands
  emit pairing and exact-device rotation codes exactly once, then keeps those
  one-time delivery channels in memory. The support builder has no admin-output
  input and records that admin output is excluded. Actual terminal scrollback,
  shell/session recording and retention remain operator evidence. (`PARTIAL`; SR-013)
- [ ] **P-04 — Server SQLite/WAL.** CI searches the live and stopped SQLite, WAL,
  SHM, authority directory, logs, HTTP errors, aggregate support summary and
  temporary run files for pairing-code and transport-token text/decoded bytes
  plus unique business plaintext. The durable relay restart test independently
  scans an encrypted business canary. External database backups remain open.
  (`PARTIAL`; SR-013)
- [ ] **P-05 — URLs and redirects.** The Server canary refuses redirects, records
  exact registration/rotation and direct/proxy WebSocket targets, rejects query
  strings, and scans them for credentials and business plaintext. Its test-only
  proxy records only method/path/status and intentionally does not forward the
  WebSocket upgrade. Production proxy/TLS/access-log configuration and
  client-side referrer evidence remain open. (`PARTIAL`; SR-013)
- [ ] **P-06 — Android diagnostics.** `docs/SENSITIVE_DATA.md` classifies
  forbidden secrets, expected app-private protocol/result state, and OS-visible
  business content. API 29 instrumentation persists real wrapped HPKE/current/
  pending/enrollment secrets, then scans raw/standard-Base64/Base64URL variants
  across SharedPreferences, databases, files, cache, no-backup storage,
  rejection errors, and own-process logcat. Privileged logcat, heap/crash/ANR,
  screenshots, OEM backup/migration, debug exports, and full business-content
  canaries remain open. (`PARTIAL`; SR-006, SR-013)
- [ ] **P-07 — Chrome diagnostics.** `docs/SENSITIVE_DATA.md` classifies expected
  endpoint-local state. The deterministic store test covers field-level
  placement and fixed errors. `scripts/chrome_profile_canary.py` additionally
  launches production `dist/` in a fresh headless Cent Browser profile, captures
  Worker diagnostics, exercises real WebCrypto/IndexedDB/`chrome.storage`/
  notifications, restarts the browser, and scans the closed profile export. The
  recorded run scanned 17,744,071 bytes: each raw current/pending token and each
  expected title/body/reply appeared in one extension IndexedDB file; encoded
  token, diagnostic, storage and URL matches were zero. The separate non-headless
  canary crosses the production Worker, verifies authority-certified recipient
  resolution and canonical one-shot reply persistence, and retains zero URL or
  diagnostic matches. A pinned CI browser, crash/memory, OS notification history,
  sync/backup, IME and screen-capture artifacts remain open.
  (`PARTIAL`; SR-008, SR-013)
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
- [ ] **S-04 — Reverse proxy.** The supported Caddy baseline keeps Server on
  loopback, terminates TLS, forwards WebSockets and overwrites client-address
  state. Server trusts one canonical forwarded address only from configured
  canonical CIDRs; CI verifies spoof and bucket-isolation behavior. Validate the
  operator's exact firewall, certificate renewal and service topology.
  (`PARTIAL`; SR-010)
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

- [ ] **B-01 — Dependency inventory.** Go, npm, Gradle/plugin and retained GitHub
  Action inventories are locked. Server now pins the multi-platform OCI index
  digests for its Go 1.25.13 Alpine builder and distroless Debian 12 nonroot
  runtime and records the resolved content-addressed image graph. A
  checksum-pinned Trivy release gate now produces four CycloneDX base-image SBOMs
  and four complete vulnerability reports with database freshness and exact
  exception binding. Default-branch base-image and published-runtime sets have
  passed offline and attestation verification; cryptographic-library baseline
  review remains open. (`PARTIAL`)
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
  remediation or time-bounded accepted-risk decisions remain open. Server's
  bounded govulncheck evidence now records and enforces vuln.go.dev database
  freshness. Chrome binds one npm audit query to its exact lockfile digest,
  registry, tool versions and UTC completion time while keeping provider database
  time explicitly null. The canonical exception registry is empty and validates
  exact finding/purl/scope, distinct owner/approver and expiry. Server's
  base-image mechanism preserves all severities and blocks unapproved runtime
  Critical／High findings. High `CVE-2026-14456` remains visible in two
  builder-only Alpine packages. Android protected run `33592520227` bound the
  exact runtime and complete inventories, scanner/provider identity, full report
  and honest command-completion time into three offline-verifiable, attested
  subjects; provider database time remains explicitly null. Protected run
  `33597387301` first reduced Android build-tool findings from 21 packages／86
  records to 5／7 through audited resolution pins. Protected run `33611975598`
  then verified AGP `9.4.0`／Gradle `9.6.0`, the new DSL and built-in Kotlin,
  reducing the complete inventory to 372 packages and findings to 2／2 while
  runtime remains zero. Both remaining records are cache-disabled Kotlin Gradle
  Plugin versions and still require independent disposition. Default-branch and
  published-manifest evidence are verified; residual Android and Server
  build-tool dispositions remain open. (`PARTIAL`; SR-003)
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
- [ ] **B-06 — Artifact signing/provenance.** Server CI builds source-bound Linux
  binaries and two architecture-specific OCI layouts with pinned base-image
  indexes. The OCI verifier follows every descriptor, rejects unreferenced blobs,
  and binds image-manifest/config/layers, platform, nonroot user, entrypoint and
  source labels. Chrome builds a deterministic source-bound submission ZIP;
  Android binds an exact signed APK, certificate DER and embedded identity. All
  three manual/tag jobs define OIDC/Sigstore GitHub attestations and commit-named
  uploads. Rollback requires exact approved source/digest and channel
  compatibility. Default-branch attestation and protected-environment execution
  have been verified. Server GHCR publication, pull-side graph/runtime evidence
  and anonymous digest pull have also been verified. Production still requires
  an approved package retention/deletion policy, independent release authority,
  durable binary hosting, Android distribution identity, and Chrome Web Store
  identity.
  (`PARTIAL`; SR-014)
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
