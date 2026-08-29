# Caddy TLS reverse-proxy baseline

Status: production-shaped reference configuration with automated real-process evidence. Operators must still validate their exact hostname, certificate lifecycle, service manager, firewall, filesystem ownership and backup/log retention environment.

## Topology and trust boundary

The supported host-local topology is:

```text
Android / Chrome ── HTTPS/WSS ──> Caddy ── HTTP loopback ──> SevenMirror Server
```

Keep `NM_ADDRESS=127.0.0.1:8080`. Do not expose the plaintext Server listener on a LAN, container-published port or public interface. Caddy is the only intended network entry point.

Set:

```sh
NM_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

The Server then accepts a canonical single-IP `X-Forwarded-For` value only when the TCP socket peer is in that exact configured prefix. Requests from any other peer ignore forwarded-address headers and remain rate-limited by their socket address. Multiple values, comma-separated chains, non-canonical addresses and zoned IPv6 values from a trusted peer are rejected.

Trusting loopback means another local process able to connect to the Server port can supply a forwarded address. The deployment must therefore treat local code execution under another account as outside this network-only boundary, keep the host patched, avoid shared untrusted shell access and restrict the Server listener with host firewall or service isolation where available. Do not configure `0.0.0.0/0`, `::/0`, broad private ranges or a container network unless every possible peer in that range is an administratively controlled proxy that overwrites the header.

## Caddy configuration

The repository baseline is [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile). It requires:

| Variable | Purpose |
| --- | --- |
| `SEVENMIRROR_LISTEN_ADDRESS` | External HTTPS address, for example `https://mirror.example.com` |
| `SEVENMIRROR_TLS_CERT_FILE` | PEM certificate chain readable by Caddy |
| `SEVENMIRROR_TLS_KEY_FILE` | Matching least-privilege PEM private key |
| `SEVENMIRROR_ACCESS_LOG` | Owner-only access-log path |
| `SEVENMIRROR_UPSTREAM` | Loopback Server address, normally `127.0.0.1:8080` |

Example environment:

```sh
export SEVENMIRROR_LISTEN_ADDRESS=https://mirror.example.com
export SEVENMIRROR_TLS_CERT_FILE=/run/secrets/sevenmirror/fullchain.pem
export SEVENMIRROR_TLS_KEY_FILE=/run/secrets/sevenmirror/privkey.pem
export SEVENMIRROR_ACCESS_LOG=/var/log/sevenmirror/access.json
export SEVENMIRROR_UPSTREAM=127.0.0.1:8080
caddy run --config /etc/sevenmirror/Caddyfile --adapter caddyfile
```

The baseline deliberately:

- disables automatic plaintext-to-HTTPS redirects, so credentials are never submitted to or redirected from an HTTP endpoint
- terminates TLS at Caddy and preserves WebSocket upgrade semantics
- relies on Caddy's default anti-spoof behavior to replace incoming `X-Forwarded-For` with the direct client address
- removes `Forwarded`, `X-Real-IP` and `X-Forwarded-Host` before the upstream request
- sends the Server `X-Forwarded-Proto: https`
- logs only request method, query-free path and response status, plus Caddy's basic timestamp/logger metadata
- removes request/response headers, client addresses, TLS details, sizes and timing from the access record
- writes logs with mode `0600`, 10 MiB rotation, at most five retained files and a 30-day maximum age

The reduced access log trades per-client incident forensics for a smaller credential and endpoint-metadata disclosure surface. If an operator needs client-address or latency telemetry, that is a separate privacy and retention decision and is not covered by this baseline. Never enable Caddy's `log_credentials` option.

## Certificate and service operations

The checked-in configuration intentionally does not choose an ACME account, DNS provider or certificate deployment mechanism. Supply a certificate valid for the exact hostname configured in Android and Chrome. Keep the private key outside the repository, make it readable only by the Caddy service account and define renewal monitoring before exposure.

Run Caddy and Server as separate least-privilege service identities when the host supports it. The Caddy identity needs the certificate and access-log paths but does not need the SQLite registry or authority private keys. The Server identity needs its registry and runtime data but does not need the TLS private key or Caddy logs. The admin CLI and authority key directory should not be available to the Caddy identity.

## Automated evidence

CI downloads Caddy `v2.11.4` from the official GitHub release and verifies the Linux amd64 archive against the hard-coded official SHA-512:

```text
8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9
```

It then runs [`scripts/caddy_proxy_canary.py`](../scripts/caddy_proxy_canary.py) against the real Caddy and Server binaries. The canary verifies:

- TLS termination without an HTTP redirect path
- HTTP and WebSocket forwarding, including relay policy close `1008` after malformed binary authentication
- spoofed incoming `X-Forwarded-For` values do not escape the actual client bucket
- two loopback source addresses behind the same Caddy process receive independent registration rate-limit buckets
- access-log JSON contains only method, query-free path, status and basic logger metadata
- random query, header and request-body canaries do not enter the access log
- Caddy and Server processes terminate and the isolated certificate, key, database and logs are deleted

The canary uses a one-day self-signed certificate because public hostname issuance is an operator deployment concern. It does not prove public CA issuance, certificate renewal, firewall rules, service-manager sandboxing, a container ingress topology, external load balancers or the operator's actual log shipping and retention system.
