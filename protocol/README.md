# Protocol

This directory is the canonical source for protocol schemas and cross-client test vectors.

The current schema is **provisional**. Do not treat `0.1.0-dev` as a compatibility promise. ADR-001, ADR-002, ADR-003, and ADR-004 must be accepted before protocol v1 is frozen.

Client repositories vendor a tagged copy of these files and record schema integrity metadata. They must not depend on a relative path to this repository.

`test-vectors/hpke-auth-p256-aes128gcm.json` is the canonical SPIKE-004 Android/Chrome interoperability vector. Its private keys are intentionally public test material and must never be used for production identity or payload encryption.

`routing-header-v1.md` defines the provisional fixed 160-byte routing header that is authenticated as the exact HPKE AAD. `test-vectors/routing-header-v1.json` is the canonical Go/Kotlin/TypeScript codec vector.

`encrypted-payload-v1.md` and `proto/notification/v1/payload.proto` define the canonical protobuf plaintext carried inside HPKE. `test-vectors/encrypted-payload-v1.json` fixes the first `action.invoke` encoding; the same schema also defines bounded `action.result` messages and `OUTCOME_UNKNOWN` recovery semantics.

`encrypted-envelope-v1.md` defines the bounded binary WebSocket frame carrying the routing header, P-256 encapsulated key, and ciphertext. `test-vectors/encrypted-envelope-v1.json` binds that frame to the HPKE, routing-header, and encrypted-payload vectors.

`device-auth-frame-v1.md` defines the provisional fixed 68-byte first WebSocket binary authentication message and the server's fixed 4-byte `SNO1` success acknowledgement. `test-vectors/device-auth-frame-v1.json` fixes both cross-client codec values using public test credentials. It is a server-admission credential format, not an E2EE message or trust mechanism.

```text
device-auth-frame-v1.md SHA-256: 0b0070a2c6d1ffee926b3ef57dddbc3c89fd226863dfedbea867c4f30756b4b9
device-auth-frame-v1.json SHA-256: 1896def3b76e7c3dbd2d59c30df684587159fb7134121a927c652fc276879076
```

Generated code is committed for reproducible client builds. Regenerate the Go files with the pinned remote plugin:

```sh
buf lint
buf generate
```
