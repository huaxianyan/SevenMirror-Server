# Protocol

This directory is the canonical source for protocol schemas and cross-client test vectors.

The current schema is **provisional**. Do not treat `0.1.0` as a compatibility promise. Applicable security and transport ADRs, including ADR-005 centralized workspace membership, must be implemented and independently reviewed before protocol v1 is frozen.

Client repositories vendor a tagged copy of these files and record schema integrity metadata. They must not depend on a relative path to this repository.

`test-vectors/hpke-auth-p256-aes128gcm.json` is the canonical SPIKE-004 Android/Chrome interoperability vector. Its private keys are intentionally public test material and must never be used for production identity or payload encryption.

`routing-header-v1.md` defines the provisional fixed 160-byte routing header that is authenticated as the exact HPKE AAD. `test-vectors/routing-header-v1.json` is the canonical Go/Kotlin/TypeScript codec vector.

`encrypted-payload-v1.md` and `proto/notification/v1/payload.proto` define the canonical protobuf plaintext carried inside HPKE. `test-vectors/encrypted-payload-v1.json` fixes action invocation, bounded notification application metadata, action descriptors and media, `notification_removed`, and active snapshot-manifest encodings; the same schema also defines bounded `action.result` messages and `OUTCOME_UNKNOWN` recovery semantics.

`e2ee-identity-key-transition-v1.md` defines old-key-authenticated transition, new-key-addressed peer ACK, new-key-authenticated commit, durable dual-key state, and the strict lost-identity recovery boundary. `test-vectors/e2ee-identity-key-transition-v1.json` fixes all three canonical schema-v2 payloads using public test keys only.

`encrypted-envelope-v1.md` defines the bounded binary WebSocket frame carrying the routing header, P-256 encapsulated key, and ciphertext. `test-vectors/encrypted-envelope-v1.json` binds that frame to the HPKE, routing-header, and encrypted-payload vectors.

`device-auth-frame-v1.md` defines the provisional fixed 68-byte first WebSocket binary authentication message and the server's fixed 4-byte `SNO1` success acknowledgement. `test-vectors/device-auth-frame-v1.json` fixes both cross-client codec values using public test credentials. It is a server-admission credential format, not an E2EE message or trust mechanism.

`transport-heartbeat-v1.md` defines the post-`SNO1` four-byte `SNH1`/`SNH2` liveness exchange. The relay consumes it outside the ciphertext hub; it carries no identifiers, credentials, cursor, operation, or business content and is not a delivery acknowledgement.

`relay-delivery-v1.md` defines explicit online-only versus durable ciphertext submission, recipient-specific delivery IDs, cumulative cursor ACK, caught-up markers, and snapshot-required gaps. `test-vectors/relay-delivery-v1.json` fixes every binary wrapper around the existing canonical encrypted envelope. The relay sees only the requested transport policy and never the encrypted business type.

`transport-credential-rotation-v1.md` defines client-generated pending credentials, exact device-bound single-use administrator authorization, atomic credential-version replacement, and lost-response recovery. Rotation changes relay admission only and leaves the device tuple and E2EE identity unchanged.

`workspace-membership-v1.md` and `proto/membership/v1/membership.proto` define the ADR-005 pending identity-possession proof, authority-signed device certificate, monotonic signed roster, roles, revocation, and dual-signed authority-key transition contract. `test-vectors/workspace-membership-v1.json` fixes canonical proof/certificate/initial-roster/revoked-roster and authority-transition/activation-roster bytes, digests, and Ed25519 signatures using public test material only.

`trusted-device-pairing-v1.md` defines the older server-independent bidirectional QR and 60-bit safety-code transcript. It remains only as a frozen provisional 1 × 1 spike artifact while ADR-005 replacement is implemented; it must not be expanded into the production membership trust source.

```text
device-auth-frame-v1.md SHA-256: 2526f6c3f5fd5b5403cbf741ebd07a349d229023032903bdf22e5c56a0151c2b
device-auth-frame-v1.json SHA-256: 1896def3b76e7c3dbd2d59c30df684587159fb7134121a927c652fc276879076
trusted-device-pairing-v1.md SHA-256: 24bedac04327fa36205ee11ca39cfdc45f6edba40671fbdcec7810d86e397473
trusted-device-pairing-v1.json SHA-256: a7254975e5c831133453ff107b97323e722385c7ae44d5a5732cb8b27eeff861
transport-credential-rotation-v1.md SHA-256: 6f8fb759ce11ca2b7f8470b830ae99feaf199ec2272318224deb2ae0cd190294
relay-delivery-v1.md SHA-256: f4a827814754c3b6be54cecf77f3470865c5a69294b62a3da48102af2fdd7659
relay-delivery-v1.json SHA-256: 72cc3efb0d135c1fdc00d2bd25f4b9d206b15b9ac99fef849dcf55e3fb20dc65
e2ee-identity-key-transition-v1.md SHA-256: 665e676d3ac0620cdb10d48a0e0c5ecc1d0ffb2cb1997caf724e9e94a33fb323
e2ee-identity-key-transition-v1.json SHA-256: f87f605480d320b622d3810a250f445b40ba0bc6aec27a2a6f5630f87d29c3d0
membership.proto SHA-256: f704f6820622638fe0712fb91ef4d9a16fe6f9d77907fab9aa76797ce9b13d51
workspace-membership-v1.md SHA-256: 1a93f7eb91f9b84ca7f225cf10a3603d9a7d451e1704ee05d743ad965a789dad
workspace-membership-v1.json SHA-256: b4b8de3ab665daac3d503ef28a68f3b00f8000be53fa3a5d81abe871b85a2beb
payload.proto SHA-256: 171bffe8e2403f7256a87de42198e4c94f1803355d61a9c7b8f4eae521d3698b
encrypted-payload-v1.md SHA-256: b83d785ae53c066ded6b032a0cacc52dd7da6d9b7723da3b831adf6ae64eeb07
encrypted-payload-v1.json SHA-256: a07cf24d34359e57c03338c2707cfc947d3a414f60d26cacdfac7fd3a3aaf8cc
```

Generated code is committed for reproducible client builds. Regenerate the Go files with the pinned remote plugin:

```sh
buf lint
buf generate
```
