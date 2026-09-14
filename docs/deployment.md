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
| `relay` | Persistent public relay, default entrypoint `/app/server` | Publishes `${SEVENMIRROR_RELAY_BIND}`, which must be a host loopback address | `data` only |
| `admin` | One-shot workspace administration, entrypoint `/app/admin` | `network_mode: none` | `data`, `authority`, `backups` |
| `admin-web` | On-demand management console, entrypoint `/app/admin-web` | Host loopback namespace, no published port | `data`, `authority` |

`admin` and `admin-web` sit behind Compose profiles, so `up` alone never starts
them. The console refuses any non-loopback listen address, and the relay never
mounts the authority directory; approving, renaming, or removing a device is the
only operation that needs the workspace authority private key, and it runs in the
console container.

All three services run as `65532:65532` with a read-only root filesystem, every
capability dropped, and `no-new-privileges`. Writable state is limited to the bind
mounts and a `16 MiB` `noexec` tmpfs at `/tmp`.

## 2. Prerequisites

- Linux host with Docker Engine and Compose v2.
- A hostname with a valid TLS certificate, if devices connect from outside the
  host. Devices use `wss://`; native TLS requires TLS 1.2 or newer.
- An immutable image reference. Use the exact multi-arch digest recorded in
  [`security/registry-release-ledger.json`](../security/registry-release-ledger.json)
  rather than a tag, and see
  [`docs/server-container-provenance.md`](server-container-provenance.md) for the
  rules on verifying a published image.

## 3. Prepare the directory

From the repository root:

```sh
cd deploy/compose
install -d -m 0700 -o 65532 -g 65532 data authority backups
cp .env.example .env
```

Edit `.env` and set all five values. Two of them need local inspection:

- `SEVENMIRROR_TRUSTED_PROXY` must be the exact source address the relay sees for
  proxy traffic. Start once, run `docker network inspect` on the Compose network,
  and pin the single IPv4 gateway with `/32`. Never widen it to a subnet: every
  peer inside that range could otherwise spoof the forwarded client address.
- `SEVENMIRROR_IMAGE` must be the digest-pinned reference from the release ledger.

`data` holds the SQLite registry, `authority` holds the workspace authority
PKCS#8 private key, and `backups` receives consistent workspace backups. The
container user must own all three, and `authority` must stay `0700`.

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
registry. Confirm the relay never mounts the authority directory, and that the
published port is bound to loopback only:

```sh
docker compose config | grep -A3 published
docker inspect "$(docker compose ps -q relay)" --format '{{json .Mounts}}'
```

## 6. Publish through a reverse proxy

Choose either a host-installed proxy or the Compose-adjacent baseline:

- Host-installed Caddy: follow [`docs/caddy-reverse-proxy.md`](caddy-reverse-proxy.md),
  which fixes the trusted-proxy resolution, the reduced access log, and the
  `wss://` upgrade path.
- Container Caddy: the baseline file is
  [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile). It expects
  `SEVENMIRROR_LISTEN_ADDRESS`, `SEVENMIRROR_TLS_CERT_FILE`,
  `SEVENMIRROR_TLS_KEY_FILE`, `SEVENMIRROR_ACCESS_LOG`, and
  `SEVENMIRROR_UPSTREAM` in the proxy's environment.

The relay must not be reachable from any other interface. Do not add a second
published port and do not forward the container address from the proxy host.

## 7. Run the management console on demand

The console prints a single-use login code to its own terminal and holds sessions
in memory only. Run it in the foreground so the code is not retained by a
persistent log:

```sh
docker compose run --rm admin-web
```

Reach it with SSH forwarding from the operator machine:

```sh
ssh -L 8081:127.0.0.1:8081 user@host
```

Then open `http://127.0.0.1:8081`, paste the code, and finish the task. Stop it
with `Ctrl-C` when done; every in-memory session is discarded and the container is
removed. If you use a dedicated HTTPS management origin instead, keep the proxy
upstream on loopback and set `SEVENMIRROR_ADMIN_ORIGIN` to the exact browser
origin. Never put the console and the device API behind the same public origin.

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
2. Set `SEVENMIRROR_IMAGE` to the new immutable digest.
3. `docker compose up -d relay` and re-check `readyz`.
4. Confirm devices reconnect. Both clients keep a durable rollback floor for the
   signed roster, so a newer registry can reject an older client, but an older
   relay cannot silently downgrade a client that already advanced.

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
