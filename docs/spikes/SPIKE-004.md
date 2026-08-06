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
- routing metadata is fixed-width, business message type remains encrypted, malformed headers fail closed, and any byte modification is rejected when the original header is used as HPKE AAD.

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

The spike APIs that serialize private keys exist only for reproducible vectors. They are not approved production key storage. Real notification content remains blocked until ADR-002's persistence, replay, pairing, revocation, and API 29 gates pass.

## Remaining exit evidence

- integration that records replay tuples before applying notification side effects
- final outer encrypted-envelope framing and transport size limits
- device trust, rotation, and revocation integration tests
