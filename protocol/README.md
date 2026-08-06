# Protocol

This directory is the canonical source for protocol schemas and cross-client test vectors.

The current schema is **provisional**. Do not treat `0.1.0-dev` as a compatibility promise. ADR-001 and ADR-002 must be accepted before protocol v1 is frozen.

Client repositories vendor a tagged copy of these files and record schema integrity metadata. They must not depend on a relative path to this repository.

`test-vectors/hpke-auth-p256-aes128gcm.json` is the canonical SPIKE-004 Android/Chrome interoperability vector. Its private keys are intentionally public test material and must never be used for production identity or payload encryption.

`routing-header-v1.md` defines the provisional fixed 160-byte routing header that is authenticated as the exact HPKE AAD. `test-vectors/routing-header-v1.json` is the canonical Go/Kotlin/TypeScript codec vector.

`encrypted-envelope-v1.md` defines the bounded binary WebSocket frame carrying the routing header, P-256 encapsulated key, and ciphertext. `test-vectors/encrypted-envelope-v1.json` binds that frame to the HPKE and routing-header vectors.
