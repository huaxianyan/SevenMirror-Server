# Notification Mirroring Server

Private self-hosted relay for Notification Mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Server>

> Status: provisional private admission and authenticated ciphertext relay are implemented for test devices. Client pairing UX, E2EE trust approval, revocation/rotation, offline delivery, and production security review are still incomplete; real notification content remains blocked.

## Current functionality

- `GET /healthz` and `GET /readyz`
- SQLite/WAL schema migration and durable private device registry
- Local admin CLI for workspace initialization and 192-bit, short-lived, one-time pairing codes
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

The raw pairing code is printed once. SQLite stores only its SHA-256 hash. A successful registration returns a random 32-byte device credential once; only its SHA-256 hash is persisted.

List devices using redacted 96-bit administrative references, then revoke one exact device:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  revoke-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
```

The list and revoke commands never print a full device ID, transport credential, or E2EE public key. Revocation is durable and idempotent. New authentication fails immediately; the running server revalidates active peers every 250 ms, atomically removes a revoked peer from ciphertext routing, and closes its WebSocket with a fixed policy response. Authorization lookup failures disconnect only the affected peer fail-closed.

## Test

```sh
go test ./...
```

## Security status

`cmd/server` now mounts registration and relay endpoints only with an initialized admission store and authenticated relay handler. Knowing the host, workspace ID, or device ID is insufficient: registration requires an unexpired, unused admin-issued code, and every relay connection requires the independently issued device credential. Secrets are absent from URLs and persisted only as hashes.

This is not yet a production release. Durable immediate device revocation is implemented, while credential rotation, lost-device recovery, offline delivery, trusted-proxy policy, and an independent security review remain release blockers. Use `wss://` outside loopback; native TLS requires TLS 1.2 or newer. Until those gates pass, submit only synthetic encrypted test payloads—never real notification content.

The first-message authentication format is documented in [`protocol/device-auth-frame-v1.md`](protocol/device-auth-frame-v1.md).

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
