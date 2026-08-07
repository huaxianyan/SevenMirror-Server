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

Initialize a private workspace and issue one device-type-bound code from the local CLI:

```sh
go run ./cmd/admin init-workspace
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-pairing-code --workspace <base64url-id> --type android --name Pixel --ttl 10m
```

The raw pairing code is printed once. SQLite stores only its SHA-256 hash. A successful registration returns a random 32-byte device credential once; only its SHA-256 hash is persisted.

## Test

```sh
go test ./...
```

## Security status

`cmd/server` now mounts registration and relay endpoints only with an initialized admission store and authenticated relay handler. Knowing the host, workspace ID, or device ID is insufficient: registration requires an unexpired, unused admin-issued code, and every relay connection requires the independently issued device credential. Secrets are absent from URLs and persisted only as hashes.

This is not yet a production release. Device revocation/credential rotation, existing-device E2EE approval, client credential storage, offline delivery, trusted-proxy policy, and an independent security review remain release blockers. Use `wss://` outside loopback. Until those gates pass, submit only synthetic encrypted test payloads—never real notification content.

The first-message authentication format is documented in [`protocol/device-auth-frame-v1.md`](protocol/device-auth-frame-v1.md).

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

MIT
