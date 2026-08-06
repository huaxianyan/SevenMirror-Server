# ADR-002: Device identity, trust, and end-to-end encryption

- Status: **Proposed — SPIKE-004 cryptography and identity persistence validated; lifecycle integration pending**
- Date: 2026-07-27
- Owners: Server, Android, and Chrome projects

## Context

Notification content, replies, action parameters, icons, and avatars must be unreadable to the server. The server is still allowed to authenticate transport clients, route messages, enforce workspace membership, retain short-lived ciphertext, and observe unavoidable metadata such as device identifiers, message sizes, and timing.

TLS is mandatory but is not E2EE. Administrator pairing codes authorize registration with a private server instance; they do not establish cryptographic trust between devices.

The initial platform floor is Android API 29 and Chrome Manifest V3. A usable design therefore needs mature implementations on Android/JVM and browser WebCrypto, explicit sender authentication, per-device revocation, replay handling, and no plaintext fallback.

## Decision candidate

Use one independently generated static HPKE identity key pair per device and encrypt each business message independently for each recipient with RFC 9180 authenticated mode.

SPIKE-004 pins this suite:

| Parameter | Value |
| --- | --- |
| HPKE mode | `Auth` (`0x02`) |
| KEM | `DHKEM(P-256, HKDF-SHA256)` (`0x0010`) |
| KDF | `HKDF-SHA256` (`0x0001`) |
| AEAD | `AES-128-GCM` (`0x0001`) |
| HPKE `info` | UTF-8 `SyncNotifications-E2EE-v1` |
| Public-key encoding | RFC 9180 P-256 uncompressed point, 65 bytes |
| Private-key encoding in test vectors only | 32-byte big-endian scalar |

Authenticated HPKE combines the sender's pinned static key with an ephemeral KEM key. A recipient only accepts a ciphertext when it opens using both its own private key and the trusted sender public key. This prevents the server from fabricating business messages despite knowing every device public key.

No custom cryptographic primitive is introduced. Android uses Bouncy Castle's RFC 9180 implementation; Chrome uses `@hpke/core` over WebCrypto. The server never receives private keys or plaintext.

## Identity and key identifiers

- A `device_id` is an administrative/routing identifier, not a cryptographic identity.
- Cryptographic identity is the pinned HPKE public key.
- `sender_key_id` and `recipient_key_id` are the full SHA-256 digest of the 65-byte serialized public key. Wire representations use all 32 bytes; user interfaces may show a grouped prefix plus a safety number.
- A key must never be silently replaced just because the server directory reports a new value.
- Test-vector private keys are public test material and must never be copied into production code or storage.

## Registration versus E2EE trust

Registration has two separate gates:

1. **Server admission:** an administrator-issued, short-lived, single-use pairing code permits a device to create transport credentials and join the private instance.
2. **Device trust:** an already trusted device verifies the new device key by QR transfer and/or a human-compared safety number before exchanging business messages with it.

The first device in a new workspace is explicitly marked as the trust root using trust-on-first-use during workspace creation. Adding later devices requires approval from an existing trusted device. Server admission alone never makes a device an E2EE recipient.

Each device stores a local pinned peer directory. A server-provided directory entry is untrusted until approved by the local trust workflow or authenticated by the old pinned key during rotation.

## Per-recipient encryption

A sender creates a separate authenticated HPKE ciphertext for every currently trusted recipient, including its other devices when cross-device state requires it. The server may route a batch, but every sealed item has exactly one recipient key.

The encrypted payload contains all business semantics, including:

- message type;
- notification title, body, app identity, icon, and avatar;
- action definitions and reply text;
- notification keys and revisions;
- action results and state transitions.

The clear routing header contains only what the server needs:

- protocol and E2EE suite versions;
- workspace, sender device, and recipient device IDs;
- sender and recipient key IDs;
- random 128-bit message ID;
- mandatory sender sequence;
- creation and mandatory expiry times.

Business `MessageType` must move inside the ciphertext. A future protocol revision will replace the provisional envelope fields that currently expose it.

Routing Header v1 is a fixed 160-byte, big-endian structure specified in `protocol/routing-header-v1.md`. It begins with ASCII `SNH1`, pins E2EE suite `1`, reserves zero flags, uses fixed 16-byte workspace/device/message IDs and full 32-byte key IDs, and limits expiry to 24 hours. The sender serializes it once and passes those exact bytes as HPKE AAD. The transport carries those same bytes without reserialization. The server parses them for routing; recipients authenticate the original byte sequence before trusting parsed fields. Fixed offsets avoid protobuf canonicalization and parser-ambiguity dependencies. Any server modification causes AEAD opening to fail.

Encrypted Envelope v1 is the binary WebSocket framing specified in `protocol/encrypted-envelope-v1.md`: ASCII `SNE1`, the exact 160-byte header, a fixed 65-byte uncompressed P-256 encapsulated key, a 32-bit ciphertext length, and 16..524288 ciphertext bytes. The full frame is bounded to 249..524521 bytes and forbids trailing data. The relay must enforce the maximum before payload-sized allocation.

## Replay and expiry

HPKE authentication does not itself remember previously opened one-shot ciphertexts. Recipients therefore maintain a persistent replay ledger keyed by:

```text
(sender_key_id, message_id)
```

Processing order is:

1. apply cheap syntax, size, and expiry limits;
2. locate the locally pinned sender key;
3. open/authenticate HPKE using the exact routing-header bytes as AAD;
4. atomically record the replay tuple before applying a side effect;
5. reject duplicates, expired items, unknown keys, authentication failures, and stale notification revisions.

Replay records live at least until the envelope expiry plus clock-skew allowance. Chrome persists this state in an atomic IndexedDB read/write transaction; Android persists it in an atomic SQLite transaction. Both fail closed at capacity rather than evicting an unexpired record. Integration must still prove that authenticated tuples are committed before notification side effects.

## Key storage

### Android

Bouncy Castle HPKE currently requires software-accessible P-256 private scalar bytes. Production storage will encrypt those bytes with an Android Keystore non-exportable AES-GCM wrapping key. Plain private bytes may exist only transiently in process memory and must never enter logs, backups, intents, or analytics. Hardware-backed wrapping is used where available.

This is weaker than performing the entire private-key operation inside Android Keystore and must be reviewed before this ADR becomes Accepted.

### Chrome

Production Chrome keys should be generated as non-extractable WebCrypto `CryptoKey` objects and persisted by structured clone in IndexedDB. The SPIKE serializes private keys only to create reproducible cross-platform vectors; that API is test-only. If the selected HPKE library cannot operate with a persisted non-extractable key, the design must not be accepted until a safe adapter or alternative implementation is proven.

Exporting keys for backup is not part of MVP.

## Rotation

- Rotation creates a new key and key ID without overwriting the old pin.
- While the old key is still trusted, the device sends an authenticated, encrypted key-transition message to every trusted peer.
- Peers pin the new key only after opening that transition with the old key.
- Senders switch new ciphertexts to the new recipient key after acknowledgement.
- Old private keys remain available only for a bounded grace period and are then destroyed.
- Lost-key rotation, where the old key cannot authenticate the transition, requires the same out-of-band verification as adding a new device.

Regular rotation bounds historical exposure but is not a full ratchet.

## Revocation

Revocation has two layers:

1. the server immediately disables the device transport credential and stops routing to/from it;
2. trusted devices receive an authenticated encrypted revocation event, remove the peer key from recipient sets, and stop accepting it as a sender.

A malicious server can suppress a revocation event just as it can suppress any message. Clients must surface stale/offline device state and allow local manual distrust. Once senders stop producing ciphertext for the revoked recipient key, the server cannot recover future plaintext.

## Security properties and limitations

This candidate provides:

- confidentiality and integrity against an honest-but-curious or message-modifying server;
- cryptographic sender authentication to a recipient that has pinned the correct sender key;
- per-recipient ciphertext and straightforward recipient removal;
- AAD protection for routing identity, key IDs, IDs, expiry, and ordering metadata;
- tamper rejection and application-level replay rejection.

It does not provide:

- metadata hiding for device IDs, timing, sizes, online state, or message frequency;
- availability against a server that drops or delays traffic;
- protection after an endpoint itself is compromised;
- full forward secrecy for old ciphertext after compromise of a static recipient private key;
- post-compromise security or a double ratchet.

Per-message ephemeral encapsulation alone does not prevent a later stolen recipient static key from opening retained old ciphertext. Short server retention, expiry, and rotation limit but do not eliminate this risk. A Noise/ratcheting follow-up is required if full forward secrecy becomes a release requirement.

## Alternatives considered

### TLS only

Rejected. The server could read all business payloads.

### HPKE base mode without sender authentication

Rejected. Anyone with a recipient public key, including the server, could fabricate valid ciphertexts.

### Custom group symmetric key

Rejected for MVP. Membership changes, removal, epoch transitions, and multi-device recovery are substantially harder to implement safely.

### Pairwise Noise sessions

Still a possible later replacement. Noise can provide forward secrecy with suitable handshakes and rekeying, but persistent asynchronous session state, out-of-order delivery, multi-recipient fan-out, and MV3 lifecycle recovery add significantly more Phase 0 risk.

### Separate signature plus base HPKE

Not selected. Authenticated HPKE already binds the sender static KEM key and avoids a second identity key and cross-platform signature encoding. Standalone signatures may still be needed later for auditable directory objects or asynchronous trust grants.

## Validation evidence

SPIKE-004 currently demonstrates:

- identical P-256 key derivation from fixed RFC 9180 IKM in Chrome and Android/JVM;
- Chrome-produced authenticated HPKE vector opened by Android;
- Android-produced authenticated HPKE vector opened by Chrome;
- ciphertext, AAD, and sender-key substitution rejection;
- bounded duplicate/expiry policy prototypes;
- persistent Android SQLite and Chrome IndexedDB replay ledgers with atomic check-and-record, expiry cleanup, concurrent duplicate rejection, and fail-closed capacity behavior;
- successful Bouncy Castle HPKE and Android Keystore-wrapped persistence execution on Android 10 / API 29 and Pixel 10 Pro / Android 16;
- non-extractable Chrome WebCrypto key persistence through the IndexedDB unit path;
- unchanged Chrome identity fingerprint after actual MV3 Worker termination and full browser restart on 2026-08-06;
- a real Chrome replay tuple accepted once, rejected immediately, and still rejected after full browser restart on 2026-08-06;
- identical 160-byte Routing Header v1 encoding and strict malformed-header rejection in Go, Kotlin, and TypeScript;
- HPKE authentication failure after modifying a byte in the encoded routing header;
- identical bounded Encrypted Envelope v1 framing and strict malformed-frame rejection in Go, Kotlin, and TypeScript;
- Android/Chrome receiver pipelines proving authentication precedes atomic replay consumption and tampered ciphertext does not consume a tuple;
- Chrome TypeScript checks, Vitest, and production bundling.

Canonical vectors:

- `protocol/test-vectors/hpke-auth-p256-aes128gcm.json`
- `protocol/test-vectors/routing-header-v1.json`
- `protocol/test-vectors/encrypted-envelope-v1.json`

## Acceptance gates

This ADR remains Proposed until all are complete:

- integration tests with actual payload parsing and notification side effects after replay acceptance;
- ADR-001 review/freeze and relay enforcement of WebSocket frame-size limits before allocation;
- pairing QR/safety-number transcript and trust-state UX review;
- rotation, revocation, and lost-device integration tests;
- independent security review before real notification content is enabled.
