# SPIKE-004: Android/Chrome authenticated E2EE interoperability

Status: cross-platform core and Android API 29/36 persistence validated; real Chrome restart gate remains

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

Canonical vector:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
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
- duplicate and expired message policy prototypes behave as expected.

## Runtime evidence

- Android 10 / API 29 emulator HPKE and Keystore persistence instrumented tests: passed
- Pixel 10 Pro, Android 16 / API 36 HPKE and Keystore persistence instrumented tests: passed
- Android/JVM unit tests: passed
- Chrome non-extractable CryptoKey + IndexedDB unit path: passed
- Chrome Vitest and TypeScript: passed
- Chrome production Vite build: passed

## Important scope boundary

The spike APIs that serialize private keys exist only for reproducible vectors. They are not approved production key storage. Real notification content remains blocked until ADR-002's persistence, replay, pairing, revocation, and API 29 gates pass.

## Remaining exit evidence

- Chrome non-extractable CryptoKey fingerprint through actual Worker/browser restart
- persistent replay ledger on both clients
- final AAD/routing-header codec
- device trust, rotation, and revocation integration tests
