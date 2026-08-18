# ADR-004: Private instance admission and WebSocket transport authentication

- Status: **Proposed — persistence, authentication, immediate revocation, and recoverable three-process transport rotation validated; administrator lifecycle, lost-device recovery, and security review pending**
- Date: 2026-08-18
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
- SHA-256 hashes of pairing, rotation-authorization, and device authentication secrets;
- a positive credential version;
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

After authentication and successful Hub registration, the server sends the
fixed four-byte binary `SNO1` acknowledgement as its first data message. Clients
must validate `SNO1` before reporting an authenticated connection or sending
application frames. Failed authentication never receives this acknowledgement,
so a TCP/WebSocket open or successful local `SNA1` enqueue is not mistaken for
server acceptance.

After `SNO1`, only bounded Encrypted Envelope v1 frames are accepted. The Hub
verifies that clear sender workspace/device fields equal the
authenticated identity before routing an unchanged ciphertext copy. Browser
origins other than `chrome-extension://` are rejected; origin-less native
clients are allowed. Authentication attempts and concurrent unauthenticated
connections are bounded. Ping/Pong liveness closes dead sessions.

TLS (`wss://`) is mandatory outside loopback. This credential provides server
admission, not message confidentiality or sender authenticity; Auth HPKE and
local pinned peer keys remain mandatory.

### Immediate device revocation

The local CLI lists devices by a domain-separated 96-bit administrative
reference rather than printing complete device IDs, credentials, or E2EE keys.
Revocation sets `revoked_at_ms` durably and idempotently for one exact
workspace/device tuple. New authentication already excludes revoked rows.

Because the CLI and relay are separate processes, the running server revalidates
only its currently connected peers every 250 milliseconds. A revoked or
unverifiable peer is atomically removed from Hub routing and its active
WebSocket receives a fixed policy close. This bounds the post-commit active
session window without adding a network administration endpoint or trusting
signals/PID files. Lookup failure is fail-closed for the affected peer. Other
workspace peers remain online.

### Recoverable transport credential rotation

`protocol/transport-credential-rotation-v1.md` defines the server-side rotation
boundary. The administrator issues a 192-bit, short-lived, single-use code
bound to an exact active device through its redacted reference. There remains
no network administrator endpoint.

Before submitting over HTTPS, the client generates a new 32-byte credential and
durably stores it as pending alongside current. The strict JSON request proves
the exact workspace/device tuple, current credential, rotation code, and
pending credential. In one transaction the server verifies every binding,
consumes the code, replaces only the credential hash, and increments a positive
credential version. Same-token, wrong-device, expired, duplicate, revoked, and
concurrent requests fail closed. Raw codes and credentials are never persisted
or returned by the rotation response.

Each WebSocket session is bound to the credential version observed during
`SNA1`. The authorization monitor therefore closes an old-version active
session using the same atomic Hub removal as revocation. New authentication
accepts only the pending credential. Device ID, device metadata, E2EE public
key, and peer trust remain unchanged.

Client promotion intentionally depends on receiving `SNO1` with pending—not on
local HTTP send or HTTP 200. If a request or response is lost, the client still
owns pending and can distinguish committed rotation by attempting pending
transport authentication. Android and Chrome implement durable dual-slot stores and exact pending recovery.
The non-loopback real-process matrix validates pre-commit failure, committed
response loss, Android process and Chrome Worker reconstruction, current
fallback, exact pending `SNO1` promotion, post-promotion restart, and permanent
old-credential rejection without changing the device or E2EE identity tuple.

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

Completed implementation evidence now includes Android Keystore and Chrome
extension-origin credential storage, strict registration clients, `SNA1` first
message handling, and cross-platform `SNO1` acknowledgement validation.

Remaining gates:

- administrator-secret, backup, and recovery design;
- lost-device recovery and client-visible revocation UX;
- trusted-proxy and configurable connection/rate limits;
- general offline queue/cursor integration and multi-device convergence;
- pairing code and transport authentication security review;
- proof that logs, diagnostics, SQLite files, and URLs contain no raw secrets or
  business plaintext.

Until these gates pass, only synthetic encrypted test payloads may use the
endpoint and this ADR remains Proposed.
