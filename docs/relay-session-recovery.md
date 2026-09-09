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
messages. The initial diagnostic slice did not change occupancy, authorization,
retry, timeout, or wire behavior. The subsequent operation isolation below adds
cancellation and a session-operation deadline.

## Why not replace the Hub entry immediately?

A correct future handover must establish all of these boundaries before it is
implemented:

1. Only an authenticated and still-authorized replacement may retire an existing
   session. Credential rotation must not let an older authenticated attempt
   displace a newer credential version.
2. Old read/write work must no longer route, resume, drain, or acknowledge on
   behalf of the new session. The former Hub methods identified callers by device,
   not by a distinct connection lease; replacing a map entry alone was insufficient.
   The operation boundary below now binds those calls to the registered instance.
3. A late authorization-monitor result or old cleanup must not disconnect or
   unregister the replacement. The monitor now carries the observed connection
   instance into `Disconnect`, which compares it with the current instance under
   the Hub lock. Reconnecting with the same credential version is also protected.
   Normal unregister and explicit disconnect now share the instance-bound
   retirement path described below.
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

## Session-bound delivery operations

`Register` now returns the actual connection handle used by both transport loops.
Online and durable routing, resume/read, cumulative ACK, activity recording, and
WebSocket data/ping writes enter one operation boundary using that handle. A device identity or credential
version alone cannot authorize old work against a reconnected slot. No peer-only
compatibility route is retained, and no wire or persistent identifier is added.

Retirement signals the transport and cancels the instance's operation context.
It then takes that instance's exclusive operation lock, waiting for admitted
operations to return before removing the exact map entry. Buffered batches cannot
bypass retirement at their subsequent socket writes. Normal unregister
uses the same path. The global Hub lock is not held during storage work or while
waiting for it. Storage and activity work get a five-second budget (or a shorter
caller deadline). Socket writes retain their existing ten-second budget, so this
change does not silently halve the time available for a large frame on a slow
link. Retirement cancels both immediately rather than waiting for their budgets
to expire. Canceled/expired socket writes close the transport to unblock IO,
and writer failures cancel the serving context as well. The old slot remains
reserved while cancellation cleanup runs.
An old operation may complete before retirement; it cannot complete a mutation
against a replacement because replacement admission occurs only after it returns.

Cancellation is cooperative, not a forced database-thread kill. The production
SQLite store uses context-aware transactions/queries. If a storage implementation
ignores cancellation or never returns, the slot stays reserved rather than
claiming safe retirement. Thus the five-second budget is not a guarantee that an
arbitrarily stuck driver will physically terminate in five seconds.

A real authenticated WebSocket test uses an explicitly controlled in-memory ACK
store: an ACK is held inside storage, retirement cancels it, admission remains
responsive but rejects reuse until cleanup returns, and the same device reconnects
and receives the retained ciphertext again. This is a storage-cancellation fixture,
not a SQLite outage or phone-network test. A module test confirms that old handles
cannot route, resume, read, or ACK after re-registration, while new handles can
receive and acknowledge their own delivery. The prior stale-authorization test
continues to cover legitimate current-session revocation.

Automatic takeover is still disabled. Transport-path changes and admission of an
authenticated replacement over an occupied slot remain separate work.

On Android, network handling must distinguish an actual route/transport change
(including a VPN's underlying transport change) from repeated capabilities or
signal-quality notifications, and must honor Activity/foreground-Service
ownership. Changing every callback into an unconditional reconnect is not the
proposed fix.

Deployment and another controlled network experiment are separate steps. Until
server-side classification is observed during that experiment, do not label the
prior mobile failures as confirmed duplicate-session rejections. No historical
44-second observation is retrospectively assigned a unique cause by these logs.
