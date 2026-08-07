# SPIKE-004: Android/Chrome authenticated E2EE interoperability

Status: cross-platform core and Android/Chrome production-key persistence paths validated

## Question

Can Android API 29+ and Chrome MV3 use a mature common E2EE construction that keeps all business payloads opaque to the server, authenticates senders, rejects tampering, and supports per-device removal?

## Candidate

RFC 9180 HPKE Auth mode:

```text
DHKEM(P-256, HKDF-SHA256)
HKDF-SHA256
AES-128-GCM
info = "SyncNotifications-E2EE-v1"
```

Implementations:

- Android: `org.bouncycastle:bcprov-jdk18on:1.85`
- Chrome: `@hpke/core:1.9.0` using WebCrypto

See `docs/adr/ADR-002-device-identity-and-e2ee.md` for the trust and lifecycle proposal.

## Automated evidence

Canonical vectors:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
protocol/test-vectors/routing-header-v1.json
protocol/test-vectors/encrypted-payload-v1.json
protocol/test-vectors/encrypted-envelope-v1.json
```

It contains only public test key material and includes:

1. deterministic Chrome-generated sender, recipient, and ephemeral keys;
2. an authenticated Chrome ciphertext opened by Android;
3. a captured Android-generated authenticated ciphertext opened by Chrome;
4. fixed HPKE `info`, AAD, and plaintext bytes.

Validated behavior:

- both platforms derive identical RFC 9180 P-256 keys from fixed IKM;
- each platform opens ciphertext emitted by the other;
- a substituted sender public key fails authentication;
- modified AAD fails authentication;
- modified ciphertext fails authentication;
- duplicate and expired message policy prototypes behave as expected;
- Android SQLite and Chrome IndexedDB ledgers atomically retain replay tuples across store reconstruction, serialize concurrent attempts, purge expired records, and fail closed at capacity;
- Go, Kotlin, and TypeScript encode and decode the same fixed 160-byte Routing Header v1 vector;
- routing metadata is fixed-width, business message type remains encrypted, malformed headers fail closed, and any byte modification is rejected when the original header is used as HPKE AAD;
- Go, Kotlin, and TypeScript encode the same bounded Encrypted Envelope v1 frame; truncation, trailing bytes, bad magic, invalid P-256 points, and ciphertext outside 16..524288 bytes fail closed;
- Android and Chrome receiver pipelines return plaintext only after identity checks, HPKE authentication, and an atomic accepted replay-ledger write; tampered ciphertext does not consume replay state;
- Go, Kotlin, and TypeScript encode and strictly validate canonical protobuf `action.invoke` and `action.result` payloads, including revision, opaque action ID, idempotency key, optional reply text, bounded result detail, and explicit local execution status;
- the canonical HPKE envelope now contains that payload, so Android opens and parses the exact Chrome-produced action frame;
- Android commits both the envelope replay tuple and a persistent 30-day operation-idempotency tuple before exposing an action to the side-effect callback; completed canonical results are cached and recovered for logical duplicates, while a reserved operation with no result returns `OUTCOME_UNKNOWN` without re-execution;
- Android assigns random 16-byte action IDs for every notification revision and resolves encrypted requests only against its process-local `PendingIntent`/`RemoteInput` table; instrumented tests cover one successful invocation, duplicate result recovery, stale revision, and unknown action rejection;
- the Go WebSocket adapter caps reads at 524521 bytes before routing, rejects oversized/text/malformed frames, binds authenticated workspace and sender device IDs to the header, and forwards ciphertext unchanged;
- a durable SQLite/WAL private registry now hashes pairing/device credentials, transactionally consumes one-time 192-bit codes, validates P-256 identities, and survives restart; raw-credential persistence is explicitly scanned in tests;
- the mounted relay requires a bounded 68-byte first-message `SNA1` credential within five seconds, rejects ordinary web origins, rate-limits authentication, maintains Ping/Pong liveness, and has an integration test from durable registration through Hub identity establishment.

## Runtime evidence

- Android 10 / API 29 emulator HPKE and Keystore persistence instrumented tests: passed
- Pixel 10 Pro, Android 16 / API 36 HPKE and Keystore persistence instrumented tests: passed
- Android/JVM unit tests: passed
- Chrome non-extractable CryptoKey + IndexedDB unit path: passed
- Chrome Vitest and TypeScript: passed
- Chrome production Vite build: passed
- Real Chrome unpacked extension retained the same non-extractable identity fingerprint after MV3 Worker termination and full browser restart: passed (2026-08-06)
- Real Chrome replay ledger returned `accepted`, then `duplicate`, and remained `duplicate` after full browser restart; explicit Worker-only termination was unavailable, but full exit necessarily terminated the Worker: passed (2026-08-06)

## Important scope boundary

The spike APIs that serialize private keys exist only for reproducible vectors. They are not approved production key storage. Server admission and transport authentication are provisional under ADR-004 and do not establish E2EE device trust. Real notification content remains blocked until client credential storage, trusted-device approval, revocation/rotation, offline transport, and security-review gates pass.

## Remaining exit evidence

- Android/Chrome registration, protected transport-credential storage, and `SNA1` connection integration
- connect the completed cached `action.result` sender/receiver to authenticated online/offline transport
- administrator-secret lifecycle, trusted-proxy policy, device trust, rotation, and immediate revocation integration tests
