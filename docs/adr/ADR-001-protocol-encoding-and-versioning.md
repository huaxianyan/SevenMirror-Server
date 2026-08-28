# ADR-001: Protocol encoding and versioning

- Status: **Accepted for the provisional pre-v1 protocol — encoding boundaries are implemented and cross-client vectors are enforced; compatibility remains intentionally unfrozen until protocol v1**
- Date: 2026-08-28
- Owners: Server, Android, and Chrome projects

## Context

SevenMirror transports security-sensitive messages across Go, Android/Kotlin, and Chrome/TypeScript. The relay must parse enough metadata to authenticate and route a bounded frame, but it must not learn notification content, actions, replies, media, snapshot contents, or operation results.

A single serialization mechanism is not suitable for every boundary:

- relay-facing headers and control frames need fixed bounds and parser-independent canonical bytes;
- encrypted business payloads need an evolvable structured schema;
- exact bytes used as HPKE AAD, signatures, digests, durable retries, and idempotency evidence must not be reserialized differently by another runtime;
- Manifest V3 suspension and Android process death require persisted protocol records to remain byte-identical across reconstruction.

The project is not yet released as protocol v1. Premature compatibility negotiation would preserve experimental shapes and create parallel implementations before a stable external consumer exists.

## Decision

### One canonical definition per protocol object

The Server repository `protocol/` directory is the authoritative source for schemas, specifications, and public cross-client vectors. Android and Chrome vendor exact copies and record canonical LF-byte SHA-256 values plus an upstream reference. Generated code is committed, but generated output is never edited as a second definition.

A protocol change is made in this order:

1. update the Server specification or schema and its canonical vector;
2. verify the Server codec;
3. vendor the exact assets into Android and Chrome;
4. verify each client's recorded hashes and independent codec behavior;
5. enable runtime behavior only after all affected clients consume the definition.

### Fixed binary transport boundary

Relay-visible frames use bounded, fixed binary encodings with ASCII magic values and big-endian integers:

- `SNH1` Routing Header v1 is exactly 160 bytes and is authenticated as the exact HPKE AAD;
- `SNE1` Encrypted Envelope v1 carries that unchanged header, one 65-byte P-256 encapsulated key, a bounded ciphertext length, and no trailing bytes;
- `SNA1`／`SNO1` authenticate the WebSocket transport before any relay or business frame;
- `SNH1`／`SNH2` heartbeat frames are transport liveness signals and are not delivery acknowledgements;
- Relay Delivery v1 uses `SNQ1`, `SNC1`, `SNC2`, `SND1`, `SND2`, and `SNR1` wrappers around an existing canonical envelope or one unsigned 64-bit cursor value.

Parsers reject wrong magic, reserved bits, unsupported versions, invalid lengths, out-of-range integers, and trailing bytes before payload-sized allocation. The relay forwards the exact authenticated envelope bytes; it does not reconstruct a routing header.

### Canonical protobuf inside E2EE

Encrypted business plaintext and authority objects use Protocol Buffers because they require structured evolution across three runtimes. Acceptance requires more than ordinary protobuf decoding:

- reject unknown fields, duplicate singular fields, non-minimal varints, non-canonical field order where the specification fixes it, unsupported schema versions, trailing data, and semantic limit violations;
- decode, validate, re-encode canonically, and require byte equality before accepting security-sensitive or durable protocol objects;
- sign, hash, retry, and persist the exact canonical bytes rather than a reconstructed object;
- keep user-visible localized sentences outside protocol and durable state. Protocols carry stable enums, codes, and source-provided user data.

`PendingIntent`, `RemoteInput`, Android resource identifiers, URIs, file paths, and external media URLs never enter the cross-device schema.

### Version policy before v1

The current protocol remains provisional `0.1.x-dev`:

- there is no version negotiation layer and no claim to support a previous stable protocol;
- an unsupported outer-frame or payload version is rejected rather than downgraded;
- coordinated breaking changes are allowed before v1 when all three repositories update their vectors and vendored hashes;
- new encoders emit only the current canonical schema;
- decode-only compatibility is permitted only for exact bytes already persisted by a released development build and only when the compatibility boundary is documented and bounded. It must not create a second sending path or weaken current semantics.

The existing action schema-v1 decode-only path is such a bounded migration: it accepts only the historical ordinary action lifecycle, never schema-v1 dismiss, while all new action encoding remains schema v2.

Protocol v1 may be frozen only after the external security review and release compatibility policy decide the supported upgrade window. At that point, compatibility changes require a new ADR amendment and explicit cross-version vectors.

### Independent state dimensions

The following monotonic or idempotent dimensions remain separate and must not be inferred from one another:

- envelope replay tuple `(sender_key_id, message_id)`;
- per-recipient sender sequence;
- notification revision and source snapshot high-water;
- workspace authority and signed-roster epochs;
- recipient relay delivery cursor and cumulative ACK;
- operation idempotency key and authenticated action result ACK.

A transport send, relay ACK, or roster membership does not prove visible presentation or Android side-effect completion.

### Transport policy remains explicit

The relay cannot inspect encrypted business type. A sender therefore chooses policy in the outer transport encoding:

- bare `SNE1` is online-only;
- `SNQ1 || SNE1` explicitly permits durable recipient delivery.

One-shot replies and snapshot recovery request／response traffic remain bare online-only envelopes. No receiver may infer permission to delay a message from its encrypted payload.

## Consequences

### Positive

- Go, Kotlin, and TypeScript authenticate and persist the same bytes.
- Fixed relay parsers have explicit allocation and ambiguity bounds.
- Business schemas can evolve without revealing message type to the relay.
- Pre-v1 development can correct real protocol defects without maintaining hypothetical compatibility modes.
- Hash-pinned vendoring makes an unintended cross-repository drift a build failure.

### Negative

- Canonical protobuf validation requires stricter codecs than default generated decoders.
- Every protocol change must be synchronized across three repositories.
- There is no mixed-version availability guarantee before v1.
- Decode-only migrations for persisted development data require narrow, explicit review.

## Rejected alternatives

### Protobuf for every outer frame

Rejected because relay-facing AAD and control frames benefit from fixed offsets, exact bounds, and no parser-specific canonicalization behavior.

### JSON protocol messages

Rejected for binary ciphertext transport and signed objects because duplicate keys, number representation, Unicode normalization, and canonicalization would add unnecessary ambiguity.

### Relay inspection of encrypted payload type

Rejected because it would either require plaintext business metadata or give the relay decryption capability.

### Add negotiation for every experimental schema

Rejected before v1 because there is no stable external compatibility contract and parallel send paths would increase security and maintenance cost.

### Shared workspace ciphertext

Rejected by ADR-005. Each recipient retains an independent identity, envelope, sequence, ciphertext, replay tuple, and delivery cursor.

## Validation evidence

- Cross-client fixed vectors cover Routing Header, Encrypted Envelope, Encrypted Payload, device authentication, workspace membership, Auth HPKE, and Relay Delivery v1.
- Android and Chrome CI verify vendored protocol hashes against canonical LF bytes.
- Strict codecs reject malformed, unknown, duplicate, non-canonical, oversized, and trailing inputs.
- Real `2 Android × 2 Chrome` acceptance demonstrated independent recipient delivery cursors, two-source notification-key isolation, online-only recovery traffic, cumulative ACK, snapshot-required recovery, and convergence after Server, Android, browser, and Worker restart.

## Release gate

Before freezing protocol v1:

1. complete an independent security review of protocol specifications, parsers, cryptographic binding, and retained compatibility paths;
2. decide the supported client upgrade window and whether one previous stable protocol is required;
3. remove or explicitly classify frozen spike-only protocol artifacts that are not product runtime inputs;
4. publish immutable protocol assets and hashes under a release tag.
