# Notification Mirroring Server

Private self-hosted relay for Notification Mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Server>

> Status: provisional private admission and authenticated ciphertext relay are implemented for synthetic test devices. ADR-005 now makes the server administrator the workspace membership authority; initial authority-key generation and separated private-key storage are implemented, while verified backup/restore, rotation, pending-device approval, authority-signed device certificates/rosters, offline delivery, and production security review are not complete yet. The existing bilateral client trust path is frozen and real third-party notification content remains blocked.

## Current functionality

- `GET /healthz` and `GET /readyz`
- SQLite/WAL schema migration and durable private device registry
- Local admin CLI for workspace initialization with a unique Ed25519 authority and 192-bit, short-lived, one-time pairing codes
- Code-gated `POST /v1/devices/register`; no open registration mode
- First-binary-frame WebSocket authentication at `GET /v1/relay`
- Bounded opaque ciphertext routing with workspace/device sender binding
- Authentication/registration rate limits, five-second auth deadline, Ping/Pong liveness, and graceful shutdown
- Canonical provisional protocol schema

The default bind address is `127.0.0.1:8080`; the service is not exposed publicly by default.

## Requirements

- Go 1.21 or newer
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

Workspace initialization stores only the authority public key in SQLite and writes the private key to an exclusive owner-only PKCS#8 file. The CLI prints its location and domain-separated public key ID, never private key material. Back up the database and exact key file separately; see [`docs/workspace-authority-key-lifecycle.md`](docs/workspace-authority-key-lifecycle.md). Existing pre-schema-v3 workspaces are not silently assigned an authority.

The raw pairing code is printed once. SQLite stores only its SHA-256 hash. A successful registration returns a random 32-byte device credential once; only its SHA-256 hash is persisted.

List devices using redacted 96-bit administrative references, then revoke one exact device:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  revoke-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
```

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

This is not yet a production release. Durable immediate device revocation and the server half of recoverable transport credential rotation are implemented. Android/Chrome dual-slot rotation and promotion, lost-device recovery, offline delivery, trusted-proxy policy, and an independent security review remain release blockers. Use `wss://` outside loopback; native TLS requires TLS 1.2 or newer. Until those gates pass, submit only synthetic encrypted test payloads—never real notification content.

The first-message authentication format is documented in [`protocol/device-auth-frame-v1.md`](protocol/device-auth-frame-v1.md).

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
