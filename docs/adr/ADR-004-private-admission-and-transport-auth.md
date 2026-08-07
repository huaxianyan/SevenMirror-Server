# ADR-004: Private instance admission and WebSocket transport authentication

- Status: **Proposed — server persistence and authentication slice implemented; client lifecycle and security review pending**
- Date: 2026-08-06
- Owners: Server, Android, and Chrome projects

## Context

Knowing a self-hosted instance URL must not permit registration or relay use.
Transport authentication is separate from E2EE identity: the server needs to
enforce workspace membership and routing, while trusted devices—not the
server—decide whether an HPKE identity may receive business ciphertext.

Chrome's standard WebSocket API cannot set an `Authorization` header. Putting a
long-lived bearer credential in a URL, query parameter, or cookie risks proxy,
browser-history, and access-log disclosure. The private-instance flow also
needs durable restart-safe membership without requiring PostgreSQL.

## Decision candidate

### Durable private registry

Use embedded SQLite through the pure-Go `modernc.org/sqlite` driver. Enable
foreign keys, WAL, a bounded busy timeout, explicit transactional migrations,
and fail startup when the database schema is newer than the binary.

Persist only administrative metadata:

- random 16-byte workspace and device IDs;
- device type and bounded display name;
- 65-byte P-256 E2EE public key;
- SHA-256 hashes of pairing and device authentication secrets;
- registration, last-online, expiry, consumption, and revocation timestamps.

Never persist notification payloads, reply text, E2EE private keys, or raw
pairing/device credentials in these tables.

### Local administrator authority

The local admin CLI directly opens the protected SQLite data path. It creates a
workspace and issues a device-type-bound pairing secret with 192 bits of CSPRNG
entropy, ten-minute default validity, 24-hour hard maximum, optional exact
device-name binding, and single-use transactional consumption. There is no
network admin endpoint and no public-registration switch.

Operating-system/data-file authorization is the current local CLI boundary.
Administrator-secret lifecycle, backup, and recovery remain unresolved and are
required before this ADR can be accepted.

### Device registration credential

A valid pairing code permits one registration request. The server validates the
device type, name, and uncompressed P-256 point, then generates random IDs and a
32-byte device credential. The raw credential is returned once; SQLite stores
only SHA-256 of it. Pairing-code consumption and device insertion occur in one
transaction, so concurrent use accepts exactly one device.

Registration attempts are bounded, strict JSON rejects unknown/trailing or
over-sized input, and every invalid/expired/consumed code receives the same
generic denial.

### WebSocket authentication

After TLS upgrade, the client sends the exact 68-byte `SNA1` authentication
frame documented in `protocol/device-auth-frame-v1.md` as its first binary
message within five seconds. This avoids credentials in URLs while remaining
usable from Chrome MV3 and Android.

The frame contains workspace ID, device ID, and the 32-byte device credential.
The server hashes and matches all three against a non-revoked durable record,
clears its temporary token buffer, then binds the resulting identity to the
ciphertext Hub. Invalid credentials receive one generic close reason.

After authentication, only bounded Encrypted Envelope v1 frames are accepted.
The Hub verifies that clear sender workspace/device fields equal the
authenticated identity before routing an unchanged ciphertext copy. Browser
origins other than `chrome-extension://` are rejected; origin-less native
clients are allowed. Authentication attempts and concurrent unauthenticated
connections are bounded. Ping/Pong liveness closes dead sessions.

TLS (`wss://`) is mandatory outside loopback. This credential provides server
admission, not message confidentiality or sender authenticity; Auth HPKE and
local pinned peer keys remain mandatory.

## Alternatives considered

### Bearer credential in query parameters

Rejected because reverse proxies and access logs commonly retain complete URLs.

### HTTP Authorization header during upgrade

Rejected as the sole mechanism because the standard browser WebSocket API does
not permit Chrome extension code to set arbitrary upgrade headers.

### First-message asymmetric challenge/response

Deferred. It avoids replayable bearer credentials but adds an extra handshake,
cross-platform signing-key lifecycle, and challenge state. A 256-bit credential
inside TLS with hash-only persistence is simpler for the private MVP. Rotation
and revocation must still be added.

### Public account/password registration

Rejected. The product is a private self-hosted workspace and has no public
account system.

### PostgreSQL

Rejected for the personal MVP because it increases deployment and backup cost.
SQLite is sufficient when transactions, migrations, WAL, limits, and failure
handling are explicit.

## Remaining acceptance gates

- Android Keystore and Chrome protected storage for transport credentials;
- client registration and `SNA1` connection implementations;
- administrator-secret, backup, and recovery design;
- device list, revoke, credential rotation, and immediate active-session close;
- trusted-proxy and configurable connection/rate limits;
- offline queue/ACK integration and MV3 reconnect behavior;
- pairing code and authentication security review;
- proof that logs, diagnostics, SQLite files, and URLs contain no raw secrets or
  business plaintext.

Until these gates pass, only synthetic encrypted test payloads may use the
endpoint and this ADR remains Proposed.
