# Notification Mirroring Server

Private self-hosted relay for Notification Mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Server>

> Status: foundation scaffold. Pairing, WebSocket relay, persistence and E2EE routing are not implemented yet.

## Current functionality

- Minimal Go HTTP process
- `GET /healthz`
- `GET /readyz`
- Graceful shutdown
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
| `NM_SHUTDOWN_TIMEOUT_SECONDS` | `10` | Graceful shutdown timeout |

## Test

```sh
go test ./...
```

## Security status

No endpoint accepts device registration or notification content yet. Public registration will remain disabled; real notification payloads will only be accepted after mandatory E2EE and device admission are implemented.

## Protocol ownership

`protocol/proto` is the canonical schema source. Android and Chrome repositories vendor a released, checksummed copy.

## License

MIT
