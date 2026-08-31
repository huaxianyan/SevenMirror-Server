# Notification Mirroring Server

Private self-hosted relay for Notification Mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SevenMirror-Server>

> Status: the provisional synthetic-only system implements private admission, authenticated opaque ciphertext relay, authority-signed workspace membership, verified authority backup／restore and dual-signed rotation, recipient-specific durable delivery, cumulative cursors, and authority-certified snapshot recovery. Real mixed `2 Android × 2 Chrome` convergence has passed; production security review, third-party notification approval, and release compatibility policy remain incomplete. Real third-party notification content remains blocked.

## Current functionality

- `GET /healthz` and `GET /readyz`
- SQLite/WAL schema migration and durable private device registry with pending-proof, pending-approval, approved, and revoked membership states; schema v8 revokes historical `legacy_active` rows and prevents their recreation
- Local admin CLI for workspace initialization with a unique Ed25519 authority and 192-bit, short-lived, one-time pairing codes
- Authority-controlled ADR-005 `POST /v1/membership/register|prove|state` enrollment flow; the former `/v1/devices/register` route is not mounted and no open registration mode exists
- First-binary-frame WebSocket authentication at `GET /v1/relay`
- Bounded opaque ciphertext routing with workspace/device sender binding
- Bounded configurable membership, rotation and relay-authentication limits; slow-header/body/auth deadlines; Ping/Pong liveness; and graceful shutdown
- Canonical provisional notification and Workspace Membership v1 schemas with cross-client test vectors
- Recipient-specific durable ciphertext delivery, cumulative ACK, bounded history gaps, and explicit snapshot-required recovery
- Accepted protocol and Chrome recovery decisions in [`docs/adr/ADR-001-protocol-encoding-and-versioning.md`](docs/adr/ADR-001-protocol-encoding-and-versioning.md) and [`docs/adr/ADR-003-chrome-realtime-connection-and-recovery.md`](docs/adr/ADR-003-chrome-realtime-connection-and-recovery.md)
- P6 threat model, independent-review process, readiness findings, and evidence checklist in [`docs/security-review/`](docs/security-review/README.md)
- Aggregate-only support-summary boundary and operator terminal guidance in [`docs/deployment-artifact-boundary.md`](docs/deployment-artifact-boundary.md)
- Single-process reconnect and sustained relay regression baseline in [`docs/relay-capacity-baseline.md`](docs/relay-capacity-baseline.md)

The default bind address is `127.0.0.1:8080`; the service is not exposed publicly by default.

## Requirements

- Go 1.25.13 or newer; the patch floor is security-sensitive and is defined by `go.mod`
- Docker is optional

## Run

```sh
go run ./cmd/server
```

Configuration:

| Variable | Default | Description |
|---|---|---|
| `NM_ADDRESS` | `127.0.0.1:8080` | HTTP listen address |
| `NM_DATABASE_PATH` | `data/syncnotifications.db` | SQLite registry and migration database |
| `NM_AUTHORITY_KEY_DIR` | directory `authority-keys` beside the database | Owner-only directory for newly generated workspace authority PKCS#8 private keys; used by the admin CLI |
| `NM_SHUTDOWN_TIMEOUT_SECONDS` | `10` | Graceful shutdown timeout |
| `NM_READ_HEADER_TIMEOUT_SECONDS` | `5` | Maximum time to receive complete HTTP request headers |
| `NM_REQUEST_READ_TIMEOUT_SECONDS` | `10` | Maximum time to receive the complete HTTP request, including its bounded body |
| `NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE` | `10` | Membership register/prove/state attempts allowed per resolved client address |
| `NM_ROTATION_ATTEMPTS_PER_MINUTE` | `10` | Credential-rotation attempts allowed per resolved client address |
| `NM_RATE_LIMIT_MAX_CLIENT_BUCKETS` | `4096` | Maximum membership and rotation client-address buckets per limiter |
| `NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE` | `20` | Relay WebSocket upgrade/authentication attempts allowed per resolved client address |
| `NM_RELAY_AUTH_MAX_CLIENT_BUCKETS` | `4096` | Maximum relay-authentication client-address buckets |
| `NM_RELAY_AUTH_MAX_CONCURRENT` | `64` | Maximum concurrent upgraded connections waiting for authentication |
| `NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS` | `5` | Maximum time an upgraded WebSocket may wait for exact `SNA1` authentication |
| `NM_TLS_CERT_FILE` | unset | PEM certificate chain for optional native HTTPS/WSS |
| `NM_TLS_KEY_FILE` | unset | Matching PEM private key; must be configured with `NM_TLS_CERT_FILE` |
| `NM_TRUSTED_PROXY_CIDRS` | unset | Canonical comma-separated CIDR prefixes allowed to supply one canonical `X-Forwarded-For` client address; leave unset for direct/native TLS |

For direct non-loopback deployment without a TLS reverse proxy, configure both TLS files and bind explicitly:

```sh
NM_ADDRESS=0.0.0.0:8443 \
NM_TLS_CERT_FILE=/run/secrets/server-cert.pem \
NM_TLS_KEY_FILE=/run/secrets/server-key.pem \
go run ./cmd/server
```

The certificate must be valid for the hostname or IP entered by clients. The server never generates certificates, never redirects plaintext registration to HTTPS, and refuses a partial cert/key configuration. Keep the private key outside the repository with least-privilege filesystem permissions. For host-local proxy termination, keep the default loopback bind and use the production-shaped Caddy baseline in [`docs/caddy-reverse-proxy.md`](docs/caddy-reverse-proxy.md); only the exact configured proxy socket peer may supply a canonical single-value client address. The synthetic physical-device procedure and exact pass criteria are documented in [`docs/non-loopback-https-recovery.md`](docs/non-loopback-https-recovery.md).

Initialize a private workspace and issue one device-type-bound code from the local CLI:

```sh
go run ./cmd/admin init-workspace
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-pairing-code --workspace <base64url-id> --type android --name Pixel --ttl 10m
```

Workspace initialization stores only the authority public key in SQLite and writes the private key to an exclusive owner-only PKCS#8 file. The CLI prints its location and domain-separated public key ID, never private key material. Existing pre-schema-v3 workspaces are not silently assigned an authority.

Create and verify a workspace backup before approving real devices:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  backup-workspace --workspace <base64url-workspace-id> --output <new-directory>
go run ./cmd/admin verify-workspace-backup \
  --workspace <base64url-workspace-id> --backup <directory>
```

The command uses SQLite's online backup API rather than copying a live WAL database. The protected output binds one consistent registry snapshot to the exact authority PKCS#8 key selected from that snapshot. Verification checks the registry digest and integrity, exact schema, canonical manifests, workspace/public-key/key-ID binding, key derivation, file types, and permissions. SevenMirror deliberately does not encrypt this directory: move it into an access-controlled, encrypted off-host backup system. `restore-workspace-backup` restores only into a new registry path and never overwrites an existing registry or authority key. See the lifecycle document for the complete command and remaining operator obligations.

Prepare a new protected key, then rotate with that exact path:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin prepare-authority-rotation
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  rotate-authority --workspace <base64url-workspace-id> --new-key-file <prepared-path>
```

The old and new authorities jointly sign a canonical transition. Transition storage, active-certificate reissue, the activation roster, and the current authority pointer commit atomically. Retrying with the same prepared key verifies the committed result and returns `already-rotated`. Keep the old key and consistent backups until every supported client has accepted the transition. See [`docs/workspace-authority-key-lifecycle.md`](docs/workspace-authority-key-lifecycle.md) for the complete backup, restore, and rotation procedure.

The raw pairing code is printed once. SQLite stores only its SHA-256 hash. A successful registration returns a random 32-byte device credential once; only its SHA-256 hash is persisted.

The pending/proof/state API is documented in [`docs/membership-http-v1.md`](docs/membership-http-v1.md). It returns a real RFC 9180 Base-HPKE identity challenge and keeps pending credentials outside relay authorization. Current Android and Chrome enrollment entry points use this API and persist authority pins, roster epochs, and pending recovery journals. The former `/v1/devices/register` route has been removed; requests receive `404`, and schema v8 permanently revokes historical uncertified `legacy_active` rows.

List devices using redacted 96-bit administrative references, then revoke one exact device:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  revoke-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
```

The membership admin commands operate on pending records created only through `/v1/membership/register`:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-pending-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  approve-device --workspace <base64url-workspace-id> --device-ref <redacted-ref> \
  --roles receive,invoke
```

Approval loads the exact workspace authority key from `NM_AUTHORITY_KEY_DIR`, signs the device certificate, advances and signs the roster, and commits the certificate, device state, and roster in one SQLite transaction. It prints only the redacted device reference and roster epoch. `revoke-device` uses the same authority custody path for certified members: one SQLite transaction removes the exact certificate from the active set, appends its revocation, advances and signs the roster, and marks the device revoked. Historical uncertified devices are fail-closed and migrated directly to revoked state; they cannot re-enroll without a new pairing code and identity.

The list and revoke commands never print a full device ID, transport credential, or E2EE public key. Revocation is durable and idempotent. New authentication fails immediately; the running server revalidates active peers every 250 ms, atomically removes a revoked peer from ciphertext routing, and closes its WebSocket with a fixed policy response. Authorization lookup failures disconnect only the affected peer fail-closed.

Issue an exact-device-bound, short-lived rotation authorization from the same redacted list:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-rotation-code --workspace <base64url-workspace-id> \
  --device-ref <redacted-ref> --ttl 10m
```

`POST /v1/devices/rotate` follows [`protocol/transport-credential-rotation-v1.md`](protocol/transport-credential-rotation-v1.md). The client generates and durably retains a pending 32-byte credential before the request. One transaction consumes the code, replaces only the credential hash, and increments the credential version. A response can be lost without losing the pending secret. Old-version live sessions are then removed by the same 250 ms authorization monitor; the device tuple and E2EE public key are unchanged. The raw code is printed once, and neither raw credential nor raw code is persisted.

## Test

```sh
go test ./...
```

## Security status

`cmd/server` now mounts registration and relay endpoints only with an initialized admission store and authenticated relay handler. Knowing the host, workspace ID, or device ID is insufficient: registration requires an unexpired, unused admin-issued code, and every relay connection requires the independently issued device credential. Server-side pairing codes and transport credentials are absent from URLs and persisted only as hashes.

This is not yet a production release. Certified revocation, recoverable transport credential rotation, recipient-scoped durable delivery, cumulative cursors, and authority-certified snapshot recovery are implemented and have passed the documented mixed-device engineering acceptance. They have not received independent security approval. The P6 review baseline, threat model, initial findings, and reproducible evidence checklist are maintained in [`docs/security-review/`](docs/security-review/README.md).

Independent protocol/security review, release-baseline security scans, authority/signing backup operations, operator-specific proxy/certificate/log-retention validation, distributed-proxy and deployment-capacity abuse testing, release provenance, and two-real-Android OEM validation remain release blockers. Use `wss://` outside loopback; native TLS requires TLS 1.2 or newer. Until those gates pass and a reviewed release explicitly changes the product gate, submit only app-owned synthetic encrypted payloads—never third-party notification content.

The first-message authentication format is documented in [`protocol/device-auth-frame-v1.md`](protocol/device-auth-frame-v1.md).

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
