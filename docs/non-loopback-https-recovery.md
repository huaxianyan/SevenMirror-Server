# Non-loopback HTTPS/WSS recovery validation

This procedure validates recovery using **controlled fixture notifications and actions only**. It does not authorize capturing or inspecting personal notifications. Record each completed scenario separately; a successful connection baseline does not establish network-switching or deep-Doze behavior.

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

A TLS reverse proxy may be used instead. Keep the host-local plaintext listener, or the Docker-published port when using a container, bound to `127.0.0.1`. A bridge-networked container can listen on its own container interface; this is not permission to publish plaintext on the host's public interfaces. Follow the Caddy WebSocket, access-log and exact trusted-peer baseline in [`caddy-reverse-proxy.md`](caddy-reverse-proxy.md). Trust only the exact proxy source address seen by the relay, which may be the Docker bridge gateway rather than loopback. Do not trust broad private or container ranges.

## Client preparation

1. Confirm the Android device and browser host can reach the endpoint without `adb reverse`, USB tunnelling, or loopback aliases.
2. Verify `/healthz` and `/readyz` through the exact HTTPS origin.
3. Create a dedicated workspace and issue a fresh, device-type-specific one-time code for each client. Keep the authority private key outside the running relay's mounts and permissions; use the separate management boundary described in the [administrator commands](../README.md#run).
4. Register both clients against the same exact HTTPS origin and complete their identity-possession proofs. Credentials are origin-bound; do not edit an existing loopback credential. If replacing an existing enrollment, obtain consent and use certified removal followed by the client's re-enrollment flow.
5. Inspect the pending device references, types, and names through the administrator's management interface, then explicitly approve each expected device. Confirm both clients accept the authority-signed certificates and current roster before testing business traffic. Registration alone does not authorize transport. There is no reciprocal safety-code approval step; use the trust model in [ADR-005](adr/ADR-005-centralized-workspace-membership-authority.md).
6. Grant the browser extension access to the exact HTTPS origin through its normal permission prompt. If preparing a headless test profile, complete any required visible authorization first, then verify the permission survives a normal restart. Do not edit browser profile preferences or disable certificate verification to bypass this step.
7. Use the independent [Android notification fixture](https://github.com/huaxianyan/SevenMirror-Android/tree/main/notification-fixture) through its ordinary controls. In SevenMirror, select and explicitly save that application, verify notification access, enable only the fixture operations needed by the action test, and enable background connection with its required status-notification permission. Do not substitute private preference edits for these user actions.
8. Record original application selection, operation permissions, background preference, and network settings. Obtain consent for network or power-state changes and restore the original settings after validation. Remove device-side temporary files and stop local test processes that are no longer needed; document any deliberately retained server deployment.

For a private CA, install only the CA certificate—not its private key. Android's user-CA allowance is confined to `debug-overrides`; a non-debuggable release build must continue to reject that CA unless it is system-trusted.

## Blocking recovery matrix

Capture redacted state before and after each step:

1. Establish one authenticated Android and one authenticated Chrome connection.
2. Run one synthetic action/result/ACK baseline and record the redacted Android outbox and side-effect count.
3. Stop the relay for more than 70 seconds. Confirm Android and Chrome become offline without user reconnect controls.
4. Restore the same dedicated database, certificate, hostname/IP, and port.
5. Confirm both clients reconnect automatically and the server observes two authenticated connections.
6. With the relay available, test an authorized real network transition and verify automatic recovery without tapping Retry. Record Wi-Fi association, the system default network, and any existing VPN transport changes: disabling Wi-Fi may switch to cellular rather than remove connectivity, and Wi-Fi association alone does not prove it has become the default route again. Treat complete network loss as a separate scenario. Do not attribute recovery to `ConnectivityManager.onAvailable()` unless callback evidence was actually collected.
7. Confirm the Android outbox, ACK tombstone aggregate, and synthetic side-effect count return exactly to the expected baseline. Heartbeat/socket recovery must not create a business delivery or side effect.

## Timing and background evidence

Record source notification execution times separately from browser observations. Distinguish network availability, socket failure detection, scheduled retry, authentication, and notification or snapshot application when diagnosing a delay. If those intermediate events were not recorded, report the observed interval without assigning it entirely to reconnect backoff. Do not claim precise cross-device latency without clock-offset evidence.

Ordinary screen-off and deep Doze are separate scenarios. Use the fixture's actual execution records (`interactive` and `deviceIdle`), not merely the time its alarm was scheduled. Keep the selected power state in effect until the observations are complete or the declared observation budget expires. Notifications received only after leaving Doze demonstrate recovery, not delivery during Doze. Restore any forced idle or battery simulation even if the test fails, and ask the user to unlock when needed rather than bypassing the lock screen.

## Pass criteria

The test passes only when all of the following are observed independently:

- HTTPS and WSS use a non-loopback endpoint and valid certificate chain/name checks;
- no `adb reverse`, USB tunnel, manual reconnect, extension reload, or app restart is used;
- Android and Chrome recover automatically after relay restoration;
- Android recovers after a real network-availability transition;
- both expected, authority-approved clients return to authenticated connections;
- exact action/result/ACK state converges without a second side effect;
- no real notification, reply, credential, key, pairing payload, or full device identifier appears in evidence or logs.

Record automated output, server-side observations, Android redacted snapshots, and user-visible UI observations separately. State the actual browser, Android version/device, network/VPN environment, and whether power-state testing was forced or naturally observed. Edge evidence is not Google Chrome evidence, a short forced-Doze test is not an overnight reliability test, and a successful loopback test is not evidence for this matrix.
