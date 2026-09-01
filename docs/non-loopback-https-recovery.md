# Non-loopback HTTPS/WSS recovery validation

This procedure is a **synthetic-only release-blocker test**. It does not authorize real notification transport.

## Security boundary

- Use a dedicated database and workspace. Never reuse production credentials.
- Prefer a publicly trusted certificate. A private development CA is acceptable only for a debuggable Android build and a browser profile whose host OS explicitly trusts that CA.
- The certificate SAN must match the exact hostname or IP entered by both clients.
- Never commit the CA private key, server private key, pairing codes, transport credentials, trust payloads, or test database.
- Remove a temporary private CA from every trust store after validation.
- Do not expose the Go plaintext listener on the LAN when TLS terminates at a local reverse proxy; retain the default loopback bind in that topology.

## Native TLS server

Native TLS is optional. Configure both files or startup fails:

```sh
NM_ADDRESS=0.0.0.0:8443 \
NM_DATABASE_PATH=data/nonloopback-recovery.db \
NM_TLS_CERT_FILE=/run/secrets/server-cert.pem \
NM_TLS_KEY_FILE=/run/secrets/server-key.pem \
go run ./cmd/server
```

TLS 1.2 or newer is required. The server does not generate certificates and does not redirect an HTTP registration request to HTTPS.

A TLS reverse proxy may be used instead. In that case keep the application listener on `127.0.0.1` and follow the Caddy WebSocket, access-log and exact trusted-peer baseline in [`caddy-reverse-proxy.md`](caddy-reverse-proxy.md). Do not trust broad private or container ranges.

## Client preparation

1. Confirm the Android device and browser host can reach the endpoint without `adb reverse`, USB tunnelling, or loopback aliases.
2. Verify `/healthz` and `/readyz` through the exact HTTPS origin.
3. Create a dedicated workspace and issue fresh one-time codes.
4. Register both clients against the same exact HTTPS origin. Credentials are origin-bound; do not edit or migrate an existing loopback credential.
5. Complete a new reciprocal E2EE trust transcript. Compare the full safety code on both devices and approve independently.
6. Use only the app-owned synthetic notification/action fixture.

For a private CA, install only the CA certificate—not its private key. Android's user-CA allowance is confined to `debug-overrides`; a non-debuggable release build must continue to reject that CA unless it is system-trusted.

## Blocking recovery matrix

Capture redacted state before and after each step:

1. Establish one authenticated Android and one authenticated Chrome connection.
2. Run one synthetic action/result/ACK baseline and record the redacted Android outbox and side-effect count.
3. Stop the relay for more than 70 seconds. Confirm Android and Chrome become offline without user reconnect controls.
4. Restore the same dedicated database, certificate, hostname/IP, and port.
5. Confirm both clients reconnect automatically and the server observes two authenticated connections.
6. Repeat with the relay available but the Android network disabled, then re-enable Wi-Fi or cellular. Confirm `ConnectivityManager.onAvailable()` causes recovery without tapping Retry.
7. Confirm the Android outbox, ACK tombstone aggregate, and synthetic side-effect count return exactly to the expected baseline. Heartbeat/socket recovery must not create a business delivery or side effect.

## Pass criteria

The test passes only when all of the following are observed independently:

- HTTPS and WSS use a non-loopback endpoint and valid certificate chain/name checks;
- no `adb reverse`, USB tunnel, manual reconnect, extension reload, or app restart is used;
- Android and Chrome recover automatically after relay restoration;
- Android recovers after a real network-availability transition;
- authenticated connection count returns to two;
- exact action/result/ACK state converges without a second side effect;
- no real notification, reply, credential, key, pairing payload, or full device identifier appears in evidence or logs.

Record automated output, server-side observations, Android redacted snapshots, and user-visible UI observations separately. A successful loopback test is not evidence for this matrix.
