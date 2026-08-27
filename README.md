# Notification Mirroring Server

Private self-hosted relay for Notification Mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SevenMirror-Server>

> Status: provisional private admission and authenticated ciphertext relay are implemented for synthetic test devices. ADR-005 authority-key custody, verified authority-key backup/restore, strict three-client Workspace Membership v1 codecs/vectors, and the Server pending-proof/atomic approval persistence boundary are implemented. Dual-signed authority rotation and the Server half of recipient-specific durable ciphertext delivery are implemented; Android/Chrome cursor integration, snapshot-required recovery, and production security review remain incomplete. Real third-party notification content remains blocked.

## Current functionality

- `GET /healthz` and `GET /readyz`
- SQLite/WAL schema migration and durable private device registry with explicit `legacy_active`, pending-proof, pending-approval, approved, and revoked membership states
- Local admin CLI for workspace initialization with a unique Ed25519 authority and 192-bit, short-lived, one-time pairing codes
- Frozen code-gated `POST /v1/devices/register` plus isolated ADR-005 `/v1/membership/register|prove|state` replacement flow; no open registration mode
- First-binary-frame WebSocket authentication at `GET /v1/relay`
- Bounded opaque ciphertext routing with workspace/device sender binding
- Authentication/registration rate limits, five-second auth deadline, Ping/Pong liveness, and graceful shutdown
- Canonical provisional notification and Workspace Membership v1 schemas with cross-client test vectors

The default bind address is `127.0.0.1:8080`; the service is not exposed publicly by default.

## Requirements

- Go 1.24 or newer
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
| `NM_TLS_CERT_FILE` | unset | PEM certificate chain for optional native HTTPS/WSS |
| `NM_TLS_KEY_FILE` | unset | Matching PEM private key; must be configured with `NM_TLS_CERT_FILE` |

For direct non-loopback deployment without a TLS reverse proxy, configure both TLS files and bind explicitly:

```sh
NM_ADDRESS=0.0.0.0:8443 \
NM_TLS_CERT_FILE=/run/secrets/server-cert.pem \
NM_TLS_KEY_FILE=/run/secrets/server-key.pem \
go run ./cmd/server
```

The certificate must be valid for the hostname or IP entered by clients. The server never generates certificates, never redirects plaintext registration to HTTPS, and refuses a partial cert/key configuration. Keep the private key outside the repository with least-privilege filesystem permissions. A reverse proxy with a publicly trusted certificate remains supported; keep the default loopback bind when proxying locally. The synthetic physical-device procedure and exact pass criteria are documented in [`docs/non-loopback-https-recovery.md`](docs/non-loopback-https-recovery.md).

Initialize a private workspace and issue one device-type-bound code from the local CLI:

```sh
go run ./cmd/admin init-workspace
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-pairing-code --workspace <base64url-id> --type android --name Pixel --ttl 10m
```

Workspace initialization stores only the authority public key in SQLite and writes the private key to an exclusive owner-only PKCS#8 file. The CLI prints its location and domain-separated public key ID, never private key material. Existing pre-schema-v3 workspaces are not silently assigned an authority.

Create and verify an authority-key backup before approving real devices:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  backup-authority --workspace <base64url-workspace-id> --output <new-directory>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  verify-authority-backup --workspace <base64url-workspace-id> --backup <directory>
```

The protected backup directory contains the exact PKCS#8 file and a canonical manifest bound to the authority public key read from SQLite. SevenMirror does not encrypt this directory; store it in an encrypted backup system together with a consistent SQLite registry backup. After restoring the registry, `restore-authority` verifies every binding before exclusively creating the missing live key file. It never overwrites a file or changes SQLite.

Prepare a new protected key, then rotate with that exact path:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin prepare-authority-rotation
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  rotate-authority --workspace <base64url-workspace-id> --new-key-file <prepared-path>
```

The old and new authorities jointly sign a canonical transition. Transition storage, active-certificate reissue, the activation roster, and the current authority pointer commit atomically. Retrying with the same prepared key verifies the committed result and returns `already-rotated`. Keep the old key and consistent backups until every supported client has accepted the transition. See [`docs/workspace-authority-key-lifecycle.md`](docs/workspace-authority-key-lifecycle.md) for the complete backup, restore, and rotation procedure.

The raw pairing code is printed once. SQLite stores only its SHA-256 hash. A successful registration returns a random 32-byte device credential once; only its SHA-256 hash is persisted.

The replacement pending/proof/state API is documented in [`docs/membership-http-v1.md`](docs/membership-http-v1.md). It returns a real RFC 9180 Base-HPKE identity challenge and keeps pending credentials outside relay authorization. Current Android and Chrome enrollment entry points use this API and persist authority pins, roster epochs, and pending recovery journals. The legacy endpoint remains frozen for compatibility but is no longer used by those client entry points.

List devices using redacted 96-bit administrative references, then revoke one exact device:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  revoke-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
```

The membership admin commands operate on pending records created through `/v1/membership/register`; the frozen legacy `/v1/devices/register` endpoint continues to create only `legacy_active` records:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-pending-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  approve-device --workspace <base64url-workspace-id> --device-ref <redacted-ref> \
  --roles receive,invoke
```

Approval loads the exact workspace authority key from `NM_AUTHORITY_KEY_DIR`, signs the device certificate, advances and signs the roster, and commits the certificate, device state, and roster in one SQLite transaction. It prints only the redacted device reference and roster epoch. `revoke-device` uses the same authority custody path for certified members: one SQLite transaction removes the exact certificate from the active set, appends its revocation, advances and signs the roster, and marks the device revoked. Legacy devices remain revocable without creating a roster entry.

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

`cmd/server` now mounts registration and relay endpoints only with an initialized admission store and authenticated relay handler. Knowing the host, workspace ID, or device ID is insufficient: registration requires an unexpired, unused admin-issued code, and every relay connection requires the independently issued device credential. Secrets are absent from URLs and persisted only as hashes.

This is not yet a production release. Durable immediate device revocation, the server half of recoverable transport credential rotation, and the Server Relay Delivery v1 queue are implemented. Android/Chrome cursor integration, snapshot-required recovery, lost-device recovery, trusted-proxy policy, and an independent security review remain release blockers. Use `wss://` outside loopback; native TLS requires TLS 1.2 or newer. Until those gates pass, submit only synthetic encrypted test payloads—never real notification content.

The first-message authentication format is documented in [`protocol/device-auth-frame-v1.md`](protocol/device-auth-frame-v1.md).

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
