# Relay session recovery diagnostics

## Observed problem and scope

The controlled Android Wi-Fi recovery trace showed 66.775 seconds between the
application's network-capability change and the old socket failure, followed by
817 ms of backoff and a 671 ms new connection attempt. This supports investigating
stale-connection detection, not simply reducing backoff. A separate mobile-network
phase reached WebSocket open and sent authentication before failing. The cause
of those production failures has not been established.

The relay used to reject a second connection for an already-connected device.
That rejection is what turned a client-side route change into a long outage: the
device had already authenticated successfully, but its slot stayed owned by a
socket the relay had not yet noticed was dead. A newer authenticated connection
for the same device now takes the slot over, under the boundaries described
below. Previously the authenticated handler discarded the error returned by
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
| `superseded` | A newer authenticated connection for the same device took this session's slot |
| `stale_credential` | Credential verification succeeded, but the connected session holds a newer credential version, so this attempt did not replace it |
| `handover_timeout` | This session was asked to release its slot for a replacement and did not do so within the bounded wait |
| `already_connected` | A replacement lost the slot race to another concurrent replacement; this attempt did not receive SNO1 |
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

A real HTTP/WebSocket test authenticates one connection, connects a replacement
with the same credential, verifies that the replacement holds the slot and can
exchange a transport heartbeat, and verifies that the retired connection is
closed with an ordinary close while the `superseded` category is logged. A
separate test verifies that ciphertext the superseded connection never
acknowledged is still delivered to the replacement. A module test checks bounded
classification, including wrapped errors and private canary messages. A handover
that cannot complete within the bounded wait keeps the slot reserved and reports
`ErrHandoverTimeout`. An older credential version is refused rather than
admitted. The subsequent operation isolation below adds cancellation and a
session-operation deadline.

## Bounded handover of an occupied slot

`Register` treats an occupied slot as a handover request rather than a rejection.
The caller has already proven possession of the device credential, so the
replacement retires the older instance and only takes the slot once that instance
has released it. The boundaries the earlier analysis required are all in place:

1. Only an authenticated replacement may retire an existing session, and a
   smaller credential version can never displace a newer one. An attempt that
   authenticates with an older credential version is refused with
   `ErrStaleCredential`, so credential rotation cannot be rolled backwards and a
   stale authenticated attempt cannot unseat a rotated session.
2. Old read/write work no longer routes, resume, drains, or acknowledges on
   behalf of the new session. The former Hub methods identified callers by device,
   not by a distinct connection lease; replacing a map entry alone was
   insufficient. The operation boundary below binds those calls to the
   registered instance.
3. A late authorization-monitor result or old cleanup must not disconnect or
   unregister the replacement. The monitor carries the observed connection
   instance into `Disconnect`, which compares it with the current instance under
   the Hub lock. Normal unregister and explicit disconnect share the same
   instance-bound retirement path.
4. Teardown and replacement admission are bounded. A retired instance signals
   `superseded` and cancels its operation context; the replacement then waits on
   that instance's `released` signal, outside the Hub lock, for at most
   `defaultSessionHandoverTimeout` (five seconds). Waiting on the release signal
   rather than on the operation lock keeps the admission bounded even when the
   retired session is stuck inside storage. If the wait expires the slot stays
   reserved and the replacement fails with `ErrHandoverTimeout`; a slot is never
   reported as free while the previous owner's admitted work is still running.
   At most one slot race is absorbed inside a single admission, so two concurrent
   replacements resolve by one of them retrying.

The two retirement signals stay distinct. `disconnected` closes for an
authorization revocation and produces a policy close (1008) that clients must
read as a membership change. `superseded` closes for a replacement and produces
an ordinary close (1000). Retiring is single-shot per instance, so a session can
only ever be ended for one of these reasons. `ServeAuthenticatedConnection`
reports whichever cause applies in preference to the socket or context error
that retiring the instance produced, which is what makes the operator categories
above reliable.

Durable delivery, cumulative ACK, recipient isolation, and one active connection
per device are all preserved. A handover does not delete or renumber anything:
the replacement resumes from the same durable history, so ciphertext the
superseded connection never acknowledged is still delivered. Canceled old
operations cannot commit against the replacement because admission of the
replacement happens only after the retired instance has released its slot.

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
store: an ACK is held inside storage, retirement cancels it, admission stays
responsive but refuses reuse while cleanup is still running, and the same device
reconnects and receives the retained ciphertext again. This is a
storage-cancellation fixture, not a SQLite outage or phone-network test. A module
test confirms that old handles cannot route, resume, read, or ACK after
re-registration, while new handles can receive and acknowledge their own
delivery. The prior stale-authorization test continues to cover legitimate
current-session revocation.

Server-side admission of an authenticated replacement over an occupied slot is
now implemented, with the boundaries above. Android-side transport handling is
still separate work.

On Android, network handling must distinguish an actual route/transport change
(including a VPN's underlying transport change) from repeated capabilities or
signal-quality notifications, and must honor Activity/foreground-Service
ownership. Changing every callback into an unconditional reconnect is not the
proposed fix.

Deployment and another controlled network experiment are separate steps. Until
server-side classification is observed during that experiment, do not label the
prior mobile failures as confirmed duplicate-session rejections. No historical
44-second observation is retrospectively assigned a unique cause by these logs.
