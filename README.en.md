<div align="center">
  <img src="docs/images/icon.png" width="120" alt="SevenMirror icon">

  # SevenMirror Server

[Project hub](https://github.com/huaxianyan/SevenMirror-Project) · Server · [Chrome extension](https://github.com/huaxianyan/SevenMirror-Extension) · [Android app](https://github.com/huaxianyan/SevenMirror-Android)

[English](README.en.md) | [简体中文](README.md)
</div>

The relay server for SevenMirror. It routes end-to-end encrypted notifications between your phone and your browsers on your own host, and holds the private-space authority that decides which devices may join.

> Status: usable today for everyday self-hosting. Ciphertext relay, authority-signed membership, durable delivery and snapshot recovery, the admin pages and the Docker assets are all implemented. A production-grade security review and a protocol compatibility policy are not.

## What it does

- **Forwards ciphertext only**: the server cannot read notification content. It sees ciphertext length and delivery timing, not titles, bodies, app names or replies.
- **Private space**: no public registration by default. Devices apply with a one-time join code and take effect only after the operator approves them.
- **Authoritative membership**: device identity, role and revocation come from one Ed25519 authority key that stays in your hands.
- **Durable delivery**: notifications for an offline recipient wait in the queue and advance by cumulative acknowledgement, so clients do not replay what was already confirmed.
- **Snapshot recovery**: when a gap appears in history, state converges on an authority-signed snapshot instead of skipping silently.
- **Admin pages**: an on-demand interface to inspect device status and to issue join codes, approve, reject, rename and remove devices.
- **One-command deployment**: the repository ships a Compose file and a first-run guide; the admin interface runs only when you need it.

## Deploying

You need a Linux host, Docker Engine and Compose v2. To let phones and browsers connect from the internet, you also need a domain with a valid TLS certificate.

The repository ships a Compose file that starts as-is. No `.env`, no directories to create first; persistent state sits next to the file.

```sh
cd deploy/compose
docker compose up -d
```

The first start creates the workspace and the authority key by itself; there is no manual initialisation. The one thing to change is the image reference at the top of the file:

```yaml
x-image: &sevenmirror-image ghcr.io/huaxianyan/sevenmirror-server:0.1.0
```

`latest` or a pinned digest also work. All three point at the same image; the difference is that a digest never moves.

Back the key file up offline; lose it and you can no longer approve devices. To find the workspace ID:

```sh
docker compose run --rm admin list-workspaces
```

Then issue a join code per device and approve it in the admin interface:

```sh
docker compose run --rm admin list-pending-devices --workspace <workspace ID>
docker compose run --rm admin approve-device --workspace <workspace ID> --device-ref <device ref>
docker compose up -d admin-web        # listens on 127.0.0.1:8081 only
docker compose stop admin-web         # stop it when done
```

Issue join codes with `issue-pairing-code`:

```sh
docker compose run --rm admin issue-pairing-code \
  --workspace <workspace ID> --type android --name Pixel
```

The join code is printed once; the database stores only its hash. The admin interface is not exposed publicly — reach it over an SSH tunnel. Full parameters are in [Configuration and operator commands](docs/operator-reference.md).

### Reverse proxy

The relay binds to the host loopback address only, does not terminate TLS and needs no published port. It uses the host network namespace directly, so there is no bridge address to look up after start.

A reverse proxy has to do two things. First, replace rather than append `X-Forwarded-For`, otherwise callers can choose their own rate-limit bucket. Second, forward the WebSocket upgrade headers, otherwise device connections get cut without a word.

Two usable starting points ship with the repository; pick the one matching your proxy:

| Proxy | Example file |
| --- | --- |
| Caddy | [`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile) |
| nginx | [`deploy/nginx/mirror.conf`](deploy/nginx/mirror.conf) |

With nginx, replace the domain in the example, install it under `sites-available` and issue a certificate:

```nginx
location / {
    proxy_pass http://127.0.0.1:18081;
    proxy_http_version 1.1;

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;

    proxy_read_timeout 3600s;
    proxy_buffering off;
}
```

`$connection_upgrade` needs a `map` definition first; the full file covers TLS, certificate paths and log policy.

### Verifying

```sh
docker compose ps
curl -fsS http://127.0.0.1:18081/healthz
curl -fsS http://127.0.0.1:18081/readyz
```

Both endpoints must answer `200`, and `ss -ltn` must show loopback addresses only — no `0.0.0.0` — before you call it ready.

The admin interface and the device API **do not share a public origin**; give them separate subdomains. Per-step detail and troubleshooting are in the [Docker deployment guide](docs/deployment.md).

## Requirements

- A Linux host with Docker Engine and Compose v2
- Go 1.27.3 or newer (only when building the binary yourself)
- A domain with a valid TLS certificate for serving over the internet

## Building and running from source

```sh
go run ./cmd/server
```

The admin interface is a separate process:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin-web
```

It listens on `http://127.0.0.1:8081` by default. Credentials live in the registry rather than in environment variables: until they are set, a built-in default account can reach the initialisation page and nothing else. Every start also prints a ten-minute emergency login code for when the authenticator is lost. The credential lifecycle is in [Admin interface](docs/admin-web.md).

## Releasing

Once the code is accepted and the required CI passes, pushing a tag like `v0.1.1` publishes automatically, with no manual approval.
Release tags use `vMAJOR.MINOR.PATCH`, independent of `protocol/PROTOCOL_VERSION`. While the protocol is unchanged, a patch release keeps the same protocol version.

The release page carries the binary artefacts only; container artefacts continue to ship through the registry. The release body comes from `docs/release-notes/<tag>.md` and the title is the tag alone. Full rules are in [Release provenance](docs/server-release-provenance.md).

## Documentation

Operational and development detail lives in separate documents rather than here.

| Topic | Document |
| --- | --- |
| Deployment steps and first run | [Docker deployment](docs/deployment.md) |
| Environment variables and commands | [Configuration and operator commands](docs/operator-reference.md) |
| Admin credentials and usage | [Admin interface](docs/admin-web.md) |
| Reverse proxy and TLS baseline | [Caddy reverse proxy](docs/caddy-reverse-proxy.md) |
| Authority key backup, restore and rotation | [Authority key lifecycle](docs/workspace-authority-key-lifecycle.md) |
| Membership HTTP interface | [Membership API](docs/membership-http-v1.md) |
| Session recovery and diagnostics | [Relay session recovery](docs/relay-session-recovery.md) |
| Relay capacity baseline | [Capacity baseline](docs/relay-capacity-baseline.md) |
| Binary artefacts and rollback | [Release provenance](docs/server-release-provenance.md) |
| Container artefacts, base images and registry boundary | [Container provenance](docs/server-container-provenance.md) |
| Image retention, deletion and emergency revocation | [Registry governance](docs/registry-release-governance.md) |
| Vulnerability evidence and exception policy | [Vulnerability management](docs/vulnerability-management.md) |
| Support bundles and terminal retention boundary | [Deployment artefact boundary](docs/deployment-artifact-boundary.md) |
| Independent review checklist and threat model | [Security review](docs/security-review/README.md) |
| Protocol assets, versions and verification | [Protocol assets](protocol/README.md) |

## License

This revision is licensed under [`GPL-3.0-only`](LICENSE). Commercial use is allowed, and distribution must follow GPLv3. Previously released MIT versions are unaffected retroactively; the exact MIT-to-GPL boundary is in [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md), and that boundary revision and its ancestors remain available under MIT.
