# Relay session recovery diagnostics

## Observed problem and scope

The controlled Android Wi-Fi recovery trace showed 66.775 seconds between the
application's network-capability change and the old socket failure, followed by
817 ms of backoff and a 671 ms new connection attempt. This supports investigating
stale-connection detection, not simply reducing backoff. A separate mobile-network
phase reached WebSocket open and sent authentication before failing. The cause
of those production failures has not been established.

The relay currently rejects a second connection for an already-connected device.
Previously the authenticated handler discarded the error returned by
`ServeAuthenticatedConnection`, making this case indistinguishable in server
logs from other post-authentication failures.

## Bounded session-end record

The existing process JSON logger now receives one `relay session ended` record
when `ServeAuthenticatedConnection` returns. It contains:

- `reason`: one of the categories below
- `duration_ms`: monotonic elapsed duration inside that call, including session
  registration and any active lifetime, but excluding HTTP upgrade and credential
  verification
- Standard logger time, level, and message fields

Categories:

| Reason | Meaning |
| --- | --- |
| `already_connected` | Credential verification succeeded, but another session still owns the device slot; this attempt did not receive SNO1 |
| `authorization_revoked` | The running session was disconnected through the Hub authorization path |
| `timeout` | A returned network-style error reports a timeout; this does not by itself identify a read, write, or underlying operation |
| `peer_closed` | EOF or a normal/going-away WebSocket close |
| `canceled` | The serving context was canceled |
| `transport_error` | Another post-credential-authentication failure; raw error text is deliberately omitted |
| `completed` | The serving function returned without an error |

No request URL, address, workspace/device identifier, credential version, token,
key, frame, notification data, close reason text, or raw exception is recorded.
No new telemetry endpoint or app-level persistence is introduced. The operator's
existing process-log collection/retention policy still applies. These records are
not ordinary-user UI and are not an independent privacy/security approval.

A real HTTP/WebSocket test authenticates one connection, attempts another with
the same credential, verifies the occupied-session classification, and verifies
that the original connection can still exchange a transport heartbeat. A module
test checks bounded classification, including wrapped errors and private canary
messages. No occupancy, authorization, retry, timeout, or wire-protocol behavior
is changed by this diagnostic slice.

## Why not replace the Hub entry immediately?

A correct future handover must establish all of these boundaries before it is
implemented:

1. Only an authenticated and still-authorized replacement may retire an existing
   session. Credential rotation must not let an older authenticated attempt
   displace a newer credential version.
2. Old read/write work must no longer route, resume, drain, or acknowledge on
   behalf of the new session. Current Hub methods identify callers by device,
   not by a distinct connection lease; replacing a map entry alone is insufficient.
3. A late authorization-monitor result or old cleanup must not disconnect or
   unregister the replacement. The monitor now carries the observed connection
   instance into `Disconnect`, which compares it with the current instance under
   the Hub lock. Reconnecting with the same credential version is also protected.
   The existing unregister closure likewise checks its exact session. This does
   not yet fence the old connection's routing, delivery reads, or ACK work.
4. Teardown and replacement admission must be bounded; a stuck old connection
   must not hold the slot indefinitely. Preserve durable delivery, cumulative
   ACK, recipient isolation, and one active connection per device.

The revocation race has a real HTTP/WebSocket regression test with a controlled
in-memory authorization lookup. It holds an old lookup while the original socket
exits and the same device reconnects, then returns the old lookup failure. The
replacement must still exchange SNH1/SNH2, while a subsequent current-session
revocation must still policy-close it. This failed on the peer-only disconnect
implementation. It tests session targeting, not database membership or a phone
network transition. No wire field, credential identity, or persisted state was
added for the in-process instance comparison.

On Android, network handling must distinguish an actual route/transport change
(including a VPN's underlying transport change) from repeated capabilities or
signal-quality notifications, and must honor Activity/foreground-Service
ownership. Changing every callback into an unconditional reconnect is not the
proposed fix.

Deployment and another controlled network experiment are separate steps. Until
server-side classification is observed during that experiment, do not label the
prior mobile failures as confirmed duplicate-session rejections. No historical
44-second observation is retrospectively assigned a unique cause by these logs.
