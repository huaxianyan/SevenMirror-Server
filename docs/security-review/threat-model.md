# SevenMirror threat model

Status: internal review baseline; independent validation required

Last updated: 2026-08-28

## 1. System and security objective

SevenMirror mirrors Android notifications to authorized Chrome devices and
routes explicit Chrome actions back to the exact source Android device.
SevenMirror is self-hosted and requires end-to-end encryption for all business
payloads. The relay may authenticate devices, route opaque envelopes, retain
selected ciphertext, and expose delivery cursors, but must not learn notification
content or business message types.

The primary security objective is:

> Only a device with a currently authorized workspace certificate, an allowed
> role, and the required recipient private key can send or read a business
> payload; an accepted action can affect only the exact notification revision on
> the exact certified source Android device.

Transport authentication is not the business trust source. Authority-signed
workspace state is the only membership, role, identity-key, and revocation trust
source.

## 2. Release scope

The current review covers:

- one self-hosted Server and its SQLite/WAL state;
- one authority signing key per workspace;
- multiple Android senders and multiple Chrome recipients/invokers;
- registration, HPKE possession proof, administrator approval, certificate and
  roster promotion, credential rotation, revocation, and authority rotation;
- RFC 9180 authenticated HPKE, signed routing metadata, replay rejection, and
  per-recipient sequence state;
- online-only and durable relay delivery, cumulative acknowledgement, history
  gaps, and snapshot recovery;
- notification upsert, removal, action invocation/result/acknowledgement, reply,
  media, and recovery payloads;
- Android Keystore wrapping, Chrome non-extractable WebCrypto keys, Server
  authority-key custody, backups, logs, local persistence, and build/update
  signing boundaries.

The reviewed product gate permits only app-owned synthetic Android notification
fixtures to enter the network. Third-party notifications are deliberately
outside the enabled Alpha behavior, even though the protocol is intended to
carry them after release gates are met.

## 3. Assets

### 3.1 Confidential assets

- notification title, body, app identity, action labels, reply text, and media;
- the semantic business message type and operation details;
- Android `PendingIntent` and `RemoteInput` capabilities, which must remain on
  the source Android device;
- HPKE identity private keys on Android and Chrome;
- Server authority private keys and Android/Chrome release-signing private keys;
- pairing codes, transport credentials, credential-rotation codes, and pending
  possession-proof material;
- decrypted business payloads in process memory;
- notification and action state stored locally after decryption.

### 3.2 Integrity and authorization assets

- authority certificate, roster, revocation set, authority epoch, and rollback
  floor;
- device certificate binding of workspace, device, role, HPKE identity key, and
  validity;
- authority transition binding old/new authority keys and the exact activation
  roster;
- routing header, envelope sender/recipient identities, per-recipient sequence,
  and replay tuple;
- `(sourceDeviceId, notificationId, revision)` notification identity;
- action identifier, operation idempotency key, and terminal action result;
- relay delivery ID, recipient cursor, cumulative ACK, snapshot request ID,
  fixed high-water, and certified source-key pin;
- release artifacts and update provenance.

### 3.3 Availability and privacy metadata assets

- service availability and bounded reconnect behavior;
- ciphertext queue availability until ACK or documented eviction;
- workspace/device relationships, recipient routing, timing, ciphertext size,
  connection address, queue depth, and cursor movement;
- administrator-visible device names and membership lifecycle state.

SevenMirror E2EE protects business plaintext, not all traffic metadata.

## 4. Actors and capabilities

### 4.1 Network attacker

Can observe, delay, drop, replay, reorder, and modify traffic; can present an
untrusted TLS certificate; and can attempt HTTP/WebSocket redirects. The attacker
does not initially control a trusted private CA or an endpoint.

### 4.2 Curious or compromised relay operator

Controls the Server process, SQLite/WAL files, relay queue, scheduling, and
network responses. Can observe routing metadata and ciphertext. If the operator
also controls the workspace authority private key, the stronger authority
attacker model applies.

### 4.3 Authority administrator

Can approve, revoke, and assign roles to devices and can operate authority backup
and rotation. A malicious or compromised authority can authorize an attacker
controlled recipient. E2EE does not protect future content against recipients
validly authorized by a compromised authority.

### 4.4 Unauthorized remote client

Has no valid transport credential, certificate, roster membership, or private
identity key. It may obtain an unconsumed pairing code, steal one authentication
factor, send malformed frames, open many connections, or replay captured bytes.

### 4.5 Revoked or stale member

Retains old credentials, certificates, rosters, ciphertext, and private keys. It
may reconnect during the bounded revocation observation window, attempt rollback,
or replay prior operations. It cannot be forced to erase plaintext delivered
before revocation.

### 4.6 Compromised endpoint or local user account

Can read the endpoint's decrypted notifications, invoke local capabilities, and
potentially access process memory or browser/Android application storage with the
privileges of that account. Android Keystore wrapping and Chrome non-extractable
keys reduce ordinary export risk but do not make an actively compromised endpoint
safe.

### 4.7 Malicious notification source

Controls notification text, media, labels, update frequency, and Android action
shape. It may attempt oversized content, parser confusion, deceptive labels,
resource exhaustion, or reuse of local notification identifiers.

### 4.8 Build or dependency attacker

Can compromise a dependency, CI action, package registry, developer environment,
or signing process and attempt to ship modified Server, Android, or Chrome code.

## 5. Trust boundaries

### TB-1: Android notification source to SevenMirror listener

Third-party notification content crosses from another app into SevenMirror's
privileged notification-listener process. The current Alpha gate admits only a
notification whose package is SevenMirror's own package. Android retains all
executable `PendingIntent` and `RemoteInput` objects.

### TB-2: Endpoint plaintext to E2EE envelope

Android and Chrome process plaintext locally, serialize a canonical protobuf
payload, and use an independently encrypted Auth HPKE envelope for each recipient.
Only routing metadata is outside the encrypted payload and is authenticated as
AAD.

### TB-3: Endpoint to network transport

HTTP membership/rotation and WebSocket relay traffic cross an attacker-controlled
network. Non-loopback deployments require HTTPS/WSS. Clients reject redirects;
WebSocket transport is not authenticated until exact `SNO1` is received.

### TB-4: Relay transport identity to workspace membership

A transport credential admits a socket but does not authorize a business message.
Clients validate authority-signed certificate/roster state, role, sender identity,
recipient identity, sequence, and replay state independently of relay admission.
Pending-proof and pending-approval devices must not enter business relay.

### TB-5: Server hot path to authority key

The relay and ordinary membership request path use public authority material and
signed records. The authority private key is a restricted file outside the
ordinary SQLite business database and is used only by explicit administrative
operations. Backup currently relies on an external encrypted backup system to
protect the otherwise unencrypted PKCS#8 file.

### TB-6: Relay queue and cursor to endpoint reconciliation

Durable `SNQ1` ciphertext may be retained per recipient and delivered as `SND1`.
A cumulative `SNC2` ACK permits deletion. Eviction creates `SNR1`, which is only
a gap signal: Chrome must pin an exact high-water and exact authority-certified
source identities, reconcile all required snapshots, and only then advance the
cursor. Snapshot request and response remain online-only bare `SNE1` frames.

### TB-7: OS/browser persistence

Android stores HPKE private bytes encrypted by a non-exportable Keystore AES-GCM
key. Chrome stores a non-extractable WebCrypto `CryptoKey` in IndexedDB. Both
clients durably retain authority floors, membership, replay, sequence, cursor,
and business reconciliation state. Decrypted Chrome notification state and
pending operation payloads are sensitive local data even when no private key is
exportable.

### TB-8: source repository to release artifact

CI, dependencies, developer workstations, signing keys, and distribution channels
sit between reviewed source and installed binaries/extensions. A protocol review
does not establish artifact provenance by itself.

## 6. Data flows and required checks

### 6.1 Registration and promotion

1. An administrator generates a short-lived, single-use pairing code.
2. A client submits strict bounded JSON over HTTPS without credentials in the URL.
3. The Server returns an HPKE-encrypted possession challenge and transport
   credential while the device remains `pending_proof`.
4. The client proves possession of the submitted HPKE private key.
5. The device remains `pending_approval` until an administrator approves its
   role and identity.
6. The Server atomically creates authority-signed membership state.
7. The client validates certificate, roster, rollback floors, and local identity
   binding before promotion.
8. Exact `SNO1` is required before transport becomes authenticated.

Review must verify interruption and retry at every state transition, pairing-code
replay, challenge replay, approval races, revocation of pending records, stale
Worker behavior, redirect rejection, and absence of raw credentials from logs,
URLs, SQLite, and WAL.

### 6.2 Notification fanout

1. Android extracts one eligible notification and allocates a durable revision.
2. For each authorized recipient, Android resolves the exact certified HPKE key,
   allocates a recipient-specific sequence, encodes canonical plaintext, and
   creates a distinct Auth HPKE envelope.
3. The relay routes the opaque envelope online or durably according to its
   explicit frame prefix.
4. Chrome verifies authority membership/role, sender key, recipient binding,
   Auth HPKE authentication, sequence/replay tuple, schema, source/revision
   monotonicity, and media bounds before presentation and cursor advancement.

Review must verify that one recipient cannot decrypt another recipient's envelope,
that source-device identity prevents notification-ID collision, and that no
presentation failure is acknowledged as reconciled.

### 6.3 Action, reply, and removal

1. Chrome binds a UI action to an exact source, notification, revision, and action
   ID when the notification is presented.
2. It sends an encrypted operation only to the authority-certified source key.
3. Android rejects stale revisions and unauthorized sender roles, and executes an
   operation at most once under the business idempotency key.
4. Durable results distinguish success, failure, and terminal uncertainty.
5. Reply is one-shot and online-only; it is neither alarm-drained nor explicitly
   resent.
6. Notification removal is authoritative only when emitted by the source Android
   with a revision.

Review must verify that transport send is never interpreted as execution success,
that `OUTCOME_UNKNOWN` is not retried as safe, and that fresh envelope replay
tuples do not create a second business side effect.

### 6.4 Revocation and authority rotation

1. The Server commits revocation and publishes a later signed roster.
2. Authorization monitoring closes or rejects transport sessions after the
   documented bounded observation interval.
3. Clients reject revoked senders and recipients under current authority state.
4. Authority rotation requires old/new signatures, exact workspace and previous
   state, monotonic authority epoch, and an exact next activation roster.
5. Clients durably preserve rollback floors across restart.

Review must consider Server/authority compromise, equivocation, partial rollout,
backup rollback, source-key replacement during snapshot recovery, and devices
that were offline throughout a transition.

## 7. Security properties and current controls

| Property | Current design control | Evidence class |
| --- | --- | --- |
| Business confidentiality from relay | Per-recipient RFC 9180 Auth HPKE; relay handles opaque `SNE1` | Protocol specs, vectors, cross-client tests |
| Sender authentication | Auth HPKE plus authority-certified sender identity and role | Specs and client authorization tests |
| Recipient isolation | Exact recipient device/key binding and independently encrypted envelope | Protocol and fanout acceptance |
| Replay resistance | Durable per-recipient sequence and replay tuple, separate business idempotency | Client storage and receiver tests |
| Exact action routing | Source device, notification ID, revision, and action ID binding | Schema and 2×2 acceptance |
| Membership integrity | Authority-signed certificate/roster; monotonic epoch/digest floors | ADR-005, codec and lifecycle tests |
| Authority transition integrity | Old/new double signature and exact activation roster | Protocol vector and rotation acceptance |
| Transport privacy/integrity | TLS/WSS outside loopback, redirect refusal, exact `SNO1` gate | Client/server tests and non-loopback acceptance |
| Credential-at-rest reduction | Server stores hashes; Android/Chrome protected local stores | Store tests and source review |
| Gap recovery integrity | Fixed `SNR1` high-water and certified source-key pinning | ADR-003 and recovery tests |
| Bounded relay retention | Per-recipient count/byte limits and cumulative ACK | Relay Delivery v1 and store tests |
| Third-party data containment | Runtime package-name gate admits app-owned fixture only | Android source boundary |

These are implementation claims awaiting independent verification, not review
conclusions.

## 8. Explicit residual risks and limitations

### 8.1 Authority compromise

A workspace authority can authorize a malicious device and role. Once that state
is accepted, clients will encrypt future content to that authorized recipient.
Authority rotation repairs future trust only after clients receive and accept a
valid transition. It does not erase data already delivered.

### 8.2 Endpoint compromise

An attacker controlling an authorized Android or Chrome endpoint can read that
endpoint's plaintext and use its authorized capabilities. Non-exportable key
policies are not a sandbox against arbitrary code running with endpoint
privileges. Android HPKE operations currently unwrap a software-usable private
scalar into process memory.

### 8.3 No application-layer forward secrecy after key compromise

Long-lived recipient identity keys decrypt envelopes captured for those keys.
TLS may provide transport forward secrecy, but the current application protocol
does not rotate ephemeral content keys to provide post-compromise or historical
forward secrecy. This must be reviewed as an explicit product risk rather than
implied otherwise.

### 8.4 Metadata leakage

The relay observes workspace/device routing relationships, connection and message
timing, ciphertext lengths, delivery IDs, queue sizes, and cursor movement. E2EE
does not hide this metadata.

### 8.5 Availability

A relay or network attacker can drop, delay, reorder, or evict ciphertext and can
prevent snapshot responses. Recovery detects and reconciles supported gaps but
cannot guarantee availability. Queue bounds intentionally trade retention for
bounded Server resources. Configurable finite client buckets, attempt rates,
pre-authentication slots and HTTP／WebSocket authentication deadlines bound one
Server process; they do not coordinate distributed proxies or prove production
capacity under reconnect storms.

### 8.6 Revocation is not retroactive

Revocation cannot erase plaintext, screenshots, exports, or ciphertext already
obtained by a member. Server enforcement also has a documented bounded window of
approximately one authorization-monitor interval after database commit; the
project does not claim zero-window revocation.

### 8.7 Operator-managed secrets and backups

The Server authority key is a restricted unencrypted PKCS#8 file. The admin CLI
uses SQLite's online backup API and canonical manifests to bind one consistent
registry snapshot to the exact authority key selected from that snapshot; CI
performs an isolated local restore through the real binary. The resulting backup
still contains plaintext PKCS#8 and registry data and must be protected by an
access-controlled external encrypted off-host system. Availability and
confidentiality therefore still depend on operator transport, retention,
retrieval, deletion and stale-backup procedures that the local canary cannot
prove. Android release-signing recovery similarly depends on a verified
off-machine encrypted backup that is not yet recorded as complete.

### 8.8 Pre-v1 compatibility

The `0.1.x-dev` protocol is provisional. There is no stable v1 compatibility
promise or general version negotiation. Review fixes may intentionally change
wire or stored state before v1 freeze.

### 8.9 Browser notification platform limits

Chrome notification APIs do not support inline text input, so reply uses a
SevenMirror-owned interaction window. `onClosed(notificationId, byUser)` cannot
classify every closure gesture. These are product/API limitations and must not be
misrepresented as cryptographic guarantees.

## 9. Out of scope and non-goals

The current design does not claim to protect against:

- a fully compromised authorized endpoint;
- a malicious authority intentionally authorizing a recipient;
- plaintext copied before revocation;
- traffic analysis or recipient-relationship hiding;
- denial of service by the relay or network;
- weaknesses in Android, Chrome, WebCrypto, Android Keystore, OS account security,
  or device hardware outside how SevenMirror configures and invokes them;
- third-party notification compatibility, privacy semantics, or OEM behavior,
  because third-party network transport remains disabled;
- secure Camera QR enrollment, because no current authority-based Camera QR flow
  has been designed or enabled;
- a stable v1 migration guarantee before protocol freeze.

The historical bilateral `sntrust1:` trust model is not an alternate supported
trust source and must not be revived by future enrollment UX.

## 10. Review priorities

Independent review should prioritize, in order:

1. canonical bytes, domain separation, Auth HPKE setup, nonce/sequence rules, and
   sender/recipient identity binding;
2. authority certificate/roster verification, rotation, rollback, equivocation,
   revocation, and role enforcement;
3. action idempotency, revision binding, reply one-shot behavior, and terminal
   uncertainty;
4. recipient cursor, ACK deletion, eviction, `SNR1`, snapshot high-water, and
   source-key pinning;
5. registration/proof/approval state transitions and transport promotion;
6. private-key/credential persistence, logs, diagnostics, URLs, SQLite/WAL,
   IndexedDB, Android storage, backup, and release signing;
7. malformed input, resource exhaustion, dependency/build compromise, and
   deployment defaults.
