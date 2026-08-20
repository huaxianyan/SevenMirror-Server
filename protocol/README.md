# Protocol

This directory is the canonical source for protocol schemas and cross-client test vectors.

The current schema is **provisional**. Do not treat `0.1.0-dev` as a compatibility promise. Applicable security and transport ADRs, including ADR-005 centralized workspace membership, must be implemented and independently reviewed before protocol v1 is frozen.

Client repositories vendor a tagged copy of these files and record schema integrity metadata. They must not depend on a relative path to this repository.

`test-vectors/hpke-auth-p256-aes128gcm.json` is the canonical SPIKE-004 Android/Chrome interoperability vector. Its private keys are intentionally public test material and must never be used for production identity or payload encryption.

`routing-header-v1.md` defines the provisional fixed 160-byte routing header that is authenticated as the exact HPKE AAD. `test-vectors/routing-header-v1.json` is the canonical Go/Kotlin/TypeScript codec vector.

`encrypted-payload-v1.md` and `proto/notification/v1/payload.proto` define the canonical protobuf plaintext carried inside HPKE. `test-vectors/encrypted-payload-v1.json` fixes action, synthetic text `notification_upsert`/`notification_removed`, and active snapshot-manifest encodings; the same schema also defines bounded `action.result` messages and `OUTCOME_UNKNOWN` recovery semantics.

`e2ee-identity-key-transition-v1.md` defines old-key-authenticated transition, new-key-addressed peer ACK, new-key-authenticated commit, durable dual-key state, and the strict lost-identity recovery boundary. `test-vectors/e2ee-identity-key-transition-v1.json` fixes all three canonical schema-v2 payloads using public test keys only.

`encrypted-envelope-v1.md` defines the bounded binary WebSocket frame carrying the routing header, P-256 encapsulated key, and ciphertext. `test-vectors/encrypted-envelope-v1.json` binds that frame to the HPKE, routing-header, and encrypted-payload vectors.

`device-auth-frame-v1.md` defines the provisional fixed 68-byte first WebSocket binary authentication message and the server's fixed 4-byte `SNO1` success acknowledgement. `test-vectors/device-auth-frame-v1.json` fixes both cross-client codec values using public test credentials. It is a server-admission credential format, not an E2EE message or trust mechanism.

`transport-heartbeat-v1.md` defines the post-`SNO1` four-byte `SNH1`/`SNH2` liveness exchange. The relay consumes it outside the ciphertext hub; it carries no identifiers, credentials, cursor, operation, or business content and is not a delivery acknowledgement.

`transport-credential-rotation-v1.md` defines client-generated pending credentials, exact device-bound single-use administrator authorization, atomic credential-version replacement, and lost-response recovery. Rotation changes relay admission only and leaves the device tuple and E2EE identity unchanged.

`workspace-membership-v1.md` and `proto/membership/v1/membership.proto` define the ADR-005 pending identity-possession proof, authority-signed device certificate, monotonic signed roster, roles, and revocation contract. `test-vectors/workspace-membership-v1.json` fixes canonical proof/certificate/initial-roster/revoked-roster bytes, digests, and Ed25519 signatures using public test material only.

`trusted-device-pairing-v1.md` defines the older server-independent bidirectional QR and 60-bit safety-code transcript. It remains only as a frozen provisional 1 × 1 spike artifact while ADR-005 replacement is implemented; it must not be expanded into the production membership trust source.

```text
device-auth-frame-v1.md SHA-256: 0b0070a2c6d1ffee926b3ef57dddbc3c89fd226863dfedbea867c4f30756b4b9
device-auth-frame-v1.json SHA-256: 1896def3b76e7c3dbd2d59c30df684587159fb7134121a927c652fc276879076
trusted-device-pairing-v1.md SHA-256: e013d6a59b3ddae4826875603b3b431d460751a2ff93c143e13b2dbfe6093706
trusted-device-pairing-v1.json SHA-256: a7254975e5c831133453ff107b97323e722385c7ae44d5a5732cb8b27eeff861
transport-credential-rotation-v1.md SHA-256: 6f8fb759ce11ca2b7f8470b830ae99feaf199ec2272318224deb2ae0cd190294
e2ee-identity-key-transition-v1.md SHA-256: 665e676d3ac0620cdb10d48a0e0c5ecc1d0ffb2cb1997caf724e9e94a33fb323
e2ee-identity-key-transition-v1.json SHA-256: f87f605480d320b622d3810a250f445b40ba0bc6aec27a2a6f5630f87d29c3d0
membership.proto SHA-256: b1289be14a8a8cfb0ae2723f269b10596824ba2e6e9f2a4185f2f61d07465a00
workspace-membership-v1.md SHA-256: b140696d9a7a7db200db9c76784a0e5c097ed3ea4dc2f67536fcd3fe1ea1ac89
workspace-membership-v1.json SHA-256: 63531283fde5fe440a78137936508bf188f199365c9dae2f9d3a9d398d18f3d9
```

Generated code is committed for reproducible client builds. Regenerate the Go files with the pinned remote plugin:

```sh
buf lint
buf generate
```
