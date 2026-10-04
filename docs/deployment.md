# Docker deployment and first-run guide

> Status: production-shaped single-host deployment assets for a self-hosted relay
> and its on-demand management console. This guide describes the container path
> only; the binary path stays in the top-level README.

This guide takes a new Linux host from an empty directory to a relay that a phone
and a browser can join. It does not replace the operator-owned work listed under
[What this guide does not provide](#what-this-guide-does-not-provide).

## 1. What gets deployed

| Service | Role | Network | Mounts |
|---|---|---|---|
| `relay` | Persistent public relay, default entrypoint `/app/server` | Host network namespace; binds `NM_ADDRESS` directly, which is a host loopback address | `data` only |
| `admin` | One-shot workspace administration, entrypoint `/app/admin` | `network_mode: none` | `data`, `authority`, `backups` |
| `admin-web` | On-demand management console, entrypoint `/app/admin-web` | Host loopback namespace, no published port | `data`, `authority` |

`relay` and `admin-web` share the host network namespace. For the relay that is
deliberate: your reverse proxy connects over loopback, so the only peer allowed to
name a client address is a loopback address stated up front, and no Compose subnet
is pinned that could collide with networks already on the host. The relay still
binds loopback only, so it stays unreachable from outside the host; check it with
`ss -ltn` rather than `docker compose port`, because a host-network service has no
published port mapping.

`admin` and `admin-web` sit behind Compose profiles, so `up` alone never starts
them. The console refuses any non-loopback listen address, and the relay never
mounts the authority directory; approving, renaming, or removing a device is the
only operation that needs the workspace authority private key, and it runs in the
console container.

All three services run as `0:0` with a read-only root filesystem, every
capability dropped, and `no-new-privileges`. Writable state is limited to the bind
mounts and a `16 MiB` `noexec` tmpfs at `/tmp`.

Running as root is what removes the manual directory step. Docker creates a
missing bind-mount directory as `root`, and a non-root container cannot write
into it; matching the container user to that owner is simpler than requiring the
operator to run `install -d -o <uid> -g <gid>` first. It does not widen what the
process can do: `cap_drop: [ALL]` leaves no capability to use, the root
filesystem is read-only, and the image still declares `nonroot:nonroot` so any
other runtime keeps the least-privileged default.

### One image, three services

All three services use the same image reference, defined once at the top of
`compose.yaml`. The image ships
three static binaries (`/app/server`, `/app/admin`, `/app/admin-web`) and each
service selects one through its `entrypoint`; the image's own entrypoint is the
relay. Building or publishing a release therefore produces exactly one
multi-arch image per revision.

The privilege boundary between the relay and the console comes from the mount
list, not from the image contents: only `admin` and `admin-web` mount
`authority`, and the relay's only persistent mount is `data`. Splitting the image
per service would not widen that boundary, because the relay binary and the
console binary already live in one image while the relay still cannot read the
key.

Because all three share one reference, updating any one of them updates the
reference for all. A feature change that touches only the console still means the
next `docker compose up -d` replaces the relay container too, and the devices
reconnect a few seconds later. That is an accepted cost of the single-image
layout, not a failure.

### Pinning a revision

The image reference lives in `compose.yaml`, and the running containers are not
restarted when you change it, so the file may name a newer revision than the
containers are already serving. Read the `org.opencontainers.image.revision`
label on the running image to learn what is actually running:

```sh
docker inspect "$(docker compose ps -q relay)" \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

Before restarting a service to close that gap, check whether the revision range
touches the build inputs (`go.mod`, `go.sum`, `cmd/`, `internal/`). A release that
changes only documentation or the protocol text produces the same binaries, so
restarting buys no behavior change and costs a reconnect.

## 2. Prerequisites

- Linux host with Docker Engine and Compose v2.
- A hostname with a valid TLS certificate, if devices connect from outside the
  host. Devices use `wss://`; native TLS requires TLS 1.2 or newer.
- An immutable image reference. Use the exact multi-arch digest recorded in
  [`security/registry-release-ledger.json`](../security/registry-release-ledger.json)
  rather than a tag, and see
  [`docs/server-container-provenance.md`](server-container-provenance.md) for the
  rules on verifying a published image.

## 3. Choose the image

Nothing needs preparing. `compose.yaml` is the only file, and the directories are
created on first start with the ownership the containers need.

```sh
cd deploy/compose
```

The one value worth a decision is the image reference at the top of
`compose.yaml`. A tag build publishes `latest`, the `protocol/PROTOCOL_VERSION`
value and the 40-character commit, all pointing at the same verified image, so any
of these pulls:

```sh
docker pull ghcr.io/huaxianyan/sevenmirror-server:latest
docker pull ghcr.io/huaxianyan/sevenmirror-server:0.1.0
```

Pin a digest before exposing the relay to real traffic. The digest is the only
identity that cannot move, so it is the one that answers which revision is
running; a tag can be repointed. The release ledger in
[`security/registry-release-ledger.json`](../security/registry-release-ledger.json)
records the published digests, and the rules for trusting one are in
[`docs/server-container-provenance.md`](server-container-provenance.md).

### If you follow a moveable tag

An automated updater such as watchtower can follow `latest` so you do not upgrade
by hand. That is a deliberate choice with three costs, spelled out in
[`docs/registry-release-governance.md`](registry-release-governance.md): the
deployment file stops saying which revision runs, rollback stops being a one-value
change, and an update that advances the signed roster's rollback floor cannot be
undone by restarting an older image. Record a known-good digest before you let an
updater run unattended.

### What the directories hold

`data` holds the SQLite registry, `authority` holds the workspace authority
PKCS#8 private key, and `backups` receives consistent workspace backups. The
containers own all three. `authority` is tightened to `0700` the first time it is
used, and files inside it are written `0600`.

## 4. Initialize the workspace

```sh
docker compose run --rm admin init-workspace
```

The command prints the workspace ID, the authority key ID, and the authority
private key file path inside the container. Record the workspace ID; the key ID
and path are useful when verifying a backup. Initialization is idempotent only in
the sense that a second run creates a second workspace, so run it once.

`authority-keys/` inside `authority/` is the directory named by
`NM_AUTHORITY_KEY_DIR`. Its permissions and failure rules are in
[`docs/workspace-authority-key-lifecycle.md`](workspace-authority-key-lifecycle.md).

## 5. Start the relay

```sh
docker compose up -d relay
curl -fsS http://127.0.0.1:18081/healthz
curl -fsS http://127.0.0.1:18081/readyz
```

`healthz` proves the process is up; `readyz` proves it can serve from its
registry. Confirm the relay never mounts the authority directory, and that it
listens on loopback only. The relay uses the host network namespace, so check the
listening socket on the host rather than looking for a published port:

```sh
docker inspect "$(docker compose ps -q relay)" --format '{{json .Mounts}}'
ss -ltn '( sport = :18081 )'
```

The `ss` output must show `127.0.0.1:18081` and never `0.0.0.0:18081` or
`[::]:18081`. If it shows a wildcard address, stop the relay before exposing the
host to any network.

## 6. Publish through a reverse proxy

This stack terminates no TLS and issues no certificate. Point your own reverse
proxy at the published loopback address; only the relay needs to be exposed.

Two example proxy configurations are checked in:

- Caddy: [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile) is the
tested baseline. [`docs/caddy-reverse-proxy.md`](caddy-reverse-proxy.md)
explains the trusted-proxy resolution, the reduced access log and the `wss://`
upgrade path, and it expects `SEVENMIRROR_LISTEN_ADDRESS`,
`SEVENMIRROR_TLS_CERT_FILE`, `SEVENMIRROR_TLS_KEY_FILE`, `SEVENMIRROR_ACCESS_LOG`
and `SEVENMIRROR_UPSTREAM` in the proxy environment.
- nginx: [`deploy/nginx/mirror.conf`](../deploy/nginx/mirror.conf) is a starting
point for a host-installed nginx with certbot. It shows the WebSocket upgrade
headers and replaces rather than appends `X-Forwarded-For`.

Whichever you use, two rules decide whether the relay behaves correctly:

- The proxy must set `X-Forwarded-For` to the direct client address rather than
appending to it. Only the proxy may name the client address, otherwise a caller
picks its own rate-limit bucket.
- The proxy must pass the WebSocket upgrade through. The relay authenticates on the
first binary frame, so a proxy that strips `Upgrade` breaks device connectivity
instead of failing loudly.

The relay must not be reachable from any other interface. Do not add a second
published port and do not forward the container address from the proxy host.

## 7. Run the management console on demand

The console holds sessions in memory only and prints a single-use recovery code to
its own terminal. Run it in the foreground so that code is not retained by a
persistent log:

```sh
docker compose run --rm admin-web
```

Reach it with SSH forwarding from the operator machine:

```sh
ssh -L 8081:127.0.0.1:8081 user@host
```

Then open `http://127.0.0.1:8081`. A registry that has no console account yet
answers the built-in default account `admin` / `sevenmirror`, and that first
sign-in is forced into the credential setup: choose the account name and a new
password, then bind an authenticator entry with the secret the second step
displays. No other page is reachable until that finishes.

The password and the authenticator secret are then stored in the registry, so
later sign-ins use them and no restart is needed. Keep the printed recovery code
as the way back in after a lost authenticator device.

Stop the console with `Ctrl-C` when done; every in-memory session is discarded and
the container is removed. If you use a dedicated HTTPS management origin instead,
keep the proxy upstream on loopback and set `NM_ADMIN_ORIGIN` in `compose.yaml` to
the exact browser origin. Never put the console and the device API behind the same
public origin.

## 8. Enroll a device

Generate a one-time code in the console, or from the admin container:

```sh
docker compose run --rm admin issue-pairing-code \
  --workspace <workspace-id> --type android --name "My phone"
docker compose run --rm admin list-pending-devices --workspace <workspace-id>
docker compose run --rm admin approve-device \
  --workspace <workspace-id> --device-ref <ref>
```

The client submits the code, proves possession of its identity key, and waits for
approval. A pending request survives client restarts and never re-consumes the
code. Use `revoke-device` to remove access, and `issue-rotation-code` to rotate a
transport credential.

## 9. Back up the workspace

```sh
docker compose run --rm admin backup-workspace \
  --workspace <workspace-id> --output /backups/<name>
docker compose run --rm admin verify-workspace-backup \
  --workspace <workspace-id> --backup /backups/<name>
```

A backup packages a consistent SQLite snapshot together with the exact authority
key selected from that snapshot. It is written `0600` under an owner-only
directory and it is **not encrypted**. Moving it to access-controlled encrypted
off-host storage, and proving that you can retrieve it, is operator work.

Restoring is a separate destructive-recovery path with its own flags:

```sh
docker compose run --rm admin restore-workspace-backup \
  --workspace <workspace-id> --backup /backups/<name> \
  --database /data/restored.db --authority-key-directory /authority/restored
```

Restore refuses to overwrite an existing registry or a different key file.

## 10. Upgrade and roll back

1. Create and verify a workspace backup, and keep it outside `data`.
2. Change the image reference at the top of `compose.yaml` to the new immutable
   digest.
3. Check whether the new revision changes the build inputs. If it does not, the
   binaries are identical and there is nothing to upgrade; restarting only costs a
   device reconnect.
4. `docker compose up -d relay` and re-check `readyz`.
5. Confirm devices reconnect. Both clients keep a durable rollback floor for the
   signed roster, so a newer registry can reject an older client, but an older
   relay cannot silently downgrade a client that already advanced.

`docker compose up -d` without a service name also replaces the console with the
same image. That is harmless when the console is not running; the profile keeps it
stopped until you start it explicitly.

Keep the previous image reference and the consistent backup from step 1 as the
rollback pair. Follow
[`docs/registry-release-governance.md`](registry-release-governance.md) before
deleting any published digest, and
[`docs/server-release-provenance.md`](server-release-provenance.md) before
trusting a new artifact.

## What this guide does not provide

These remain operator-owned and are not implied by running this Compose file:

- host firewall rules, fail2ban, or any network access control beyond loopback
  publishing;
- certificate issuance and renewal;
- encrypted off-host backup storage, retention, deletion, and retrieval drills;
- container log drivers, shipping, and retention beyond the bounded `json-file`
  rotation set on the relay;
- monitoring, alerting, and capacity planning; the current regression floor is in
  [`docs/relay-capacity-baseline.md`](relay-capacity-baseline.md);
- proxy-topology distribution, distributed rate limiting, or multi-host routing;
- independent security review. See
  [`docs/security-review/README.md`](security-review/README.md) for the open
  findings and the current product gate.
