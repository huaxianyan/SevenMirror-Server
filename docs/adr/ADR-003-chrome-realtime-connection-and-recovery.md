# ADR-003: Chrome real-time connection and recovery

- Status: **Accepted for the provisional pre-v1 runtime — authenticated WebSocket, durable recipient cursor, Worker reconstruction, and authoritative snapshot recovery are implemented and validated**
- Date: 2026-08-28
- Owners: Server, Android, and Chrome projects

## Context

Chrome Manifest V3 uses an event-driven Service Worker that may be suspended at any time. A process-local WebSocket, timer, object graph, or decrypted message cannot be treated as durable state. At the same time, notification mirroring should normally be real-time, should not replay every old notification after a Worker restart, and must preserve one-shot operation semantics.

The relay cannot inspect encrypted business types. Some messages may be delayed safely, while replies and snapshot recovery traffic must not be delivered after their online context has expired. Chrome also cannot treat a WebSocket open, a successful local `send()`, or a relay delivery ACK as proof that Android executed an action or that the operating system visibly presented a notification.

A separate HTTP polling implementation would duplicate authentication, cursor, replay, authorization, and recovery semantics. The runtime therefore needs one transport model that tolerates Worker reconstruction without creating a second business path.

## Decision

### Authenticated WebSocket is the only business transport

Chrome opens a WebSocket to the configured private instance and sends the exact `SNA1` frame as its first binary message. It does not report `online`, send a relay cursor, or send business envelopes until it receives exact `SNO1` as the first server data message.

Outside loopback, `wss://` is mandatory. Credentials never enter a URL, query parameter, cookie, or redirect. Active sockets are bound to the authenticated workspace, device, credential version, and current authorization state.

There is no independent HTTP business pull fallback. Membership HTTP remains a separate bounded authority state API; notification, action, result, ACK, snapshot, and relay delivery traffic use the authenticated WebSocket path.

### The Worker is reconstructible, not durable

All correctness-relevant state lives in extension-origin persistence, not module globals:

- non-extractable WebCrypto identity;
- transport credential and exact identity-key binding;
- highest accepted authority transition and roster floors;
- replay ledger and per-recipient outbound sequence;
- notification state, removed revisions, media, and snapshot digest;
- pending action correlation, result ACK, and one-shot delivery mode;
- relay delivery cursor and snapshot-recovery session;
- programmatic notification-close markers and exact button bindings.

Worker startup reconstructs coordinators from these stores. In-memory sockets, timers, queues, and decrypted values are disposable working state. Persistent identity or credential corruption fails closed instead of silently generating a replacement.

### Reconnection and liveness

An explicit startup or user reconnect begins immediately. Failures use one bounded jittered exponential retry sequence. A `chrome.alarms` watchdog wakes retry work across Worker suspension; process-local timers are only short-lived scheduling helpers.

`SNH1`／`SNH2` heartbeat validates authenticated socket liveness and is independent from business delivery. A stale socket is closed and replaced by a new authenticated generation. Client-initiated WebSocket close codes remain `1000` or private `3000..4999`; encrypted-message security failure uses private fail-closed code `4008`.

Only the current connection generation may mutate online state or accept frames. Late callbacks from replaced sockets are ignored.

### Explicit online-only and durable delivery

Chrome and Android use Relay Delivery v1 without exposing encrypted business type:

- bare `SNE1` is online-only;
- `SNQ1 || SNE1` requests durable recipient delivery;
- one-shot reply remains online-only and is never drained by an alarm or explicit resend;
- snapshot recovery request and response remain online-only.

After `SNO1`, Chrome loads the cursor scoped to `(workspace_id, local_device_id)` and sends `SNC1`. It processes `SND1` in delivery-ID order. It advances the contiguous cursor and sends cumulative `SNC2` only after sender authorization, Auth HPKE, replay handling, business durable reconciliation, and required notification presentation have succeeded.

An ACK proves only that the recipient committed the encrypted business effect. It does not prove that a user saw a toast.

### Duplicate and history-gap behavior

A relay may redeliver an exact envelope when a cumulative ACK is lost. Chrome accepts this only when the replay tuple is already consumed and the same durable business binding can be proven; bare online replay remains rejected.

`SND2` is a consistency assertion and must match the committed cursor. `SNR1` is not permission to skip history. Chrome persists an exact recovery session containing:

- the reset high-water;
- one random recovery request ID;
- every expected authority-certified Android source device ID;
- each exact source identity key ID;
- completed source IDs.

Chrome retries only incomplete sources using fresh recipient-specific online-only Auth HPKE envelopes. A manifest completes a source only after exact request, device, key, and snapshot reconciliation succeed. Source revocation or key replacement fails closed rather than silently changing the fixed source set. Only after every fixed source completes does Chrome atomically accept the high-water, clear the recovery session, and send `SNC1` as explicit reset acceptance.

### Notification presentation and close semantics

The durable notification state is authoritative for Worker reconstruction. Chrome persists an exact close reason before programmatic `chrome.notifications.clear()` and serializes marker mutation. A user close requests remote dismiss only when `byUser === true` and no programmatic marker exists; ambiguous closes are ignored.

A programmatic close never fabricates Android `notification.removed`. The Chrome state becomes removed only through an authenticated Android event or authoritative snapshot reconciliation. Clicking a notification body opens the SevenMirror interaction page; actions re-read current durable revision before encryption.

### Development deployment is outside runtime recovery

For an unpacked extension, `chrome.runtime.reload()` or browser restart may restart an already registered same-version Worker without rereading a rebuilt `dist/` directory in Cent Browser. Acceptance after a rebuild must use the developer-mode **Reload** action at `chrome://extensions` and compare runtime Worker bytes with the disk build.

This is a development deployment requirement, not a production protocol fallback. The runtime must not attempt to support mixed chunks from one unpacked profile.

## Consequences

### Positive

- Real-time delivery remains the normal path without treating the Worker as a persistent process.
- One cursor and replay model covers online operation, relay restart, browser restart, and Worker suspension.
- One-shot replies cannot reappear after Android reconnects.
- History gaps require authority-certified source reconciliation rather than silent cursor jumps.
- Programmatic notification maintenance does not create remote-delete loops.

### Negative

- Durable IndexedDB state and reconstruction logic are required for every correctness-relevant workflow.
- A completely suspended Worker cannot promise uninterrupted socket presence; recovery begins on supported wake events and alarms.
- The relay retains bounded ciphertext metadata and delivery history for explicitly durable traffic.
- Snapshot recovery waits for every fixed active Android source or fails closed when its certified identity changes.

## Rejected alternatives

### Assume a permanent WebSocket keeps the Worker alive

Rejected because MV3 lifecycle does not provide that guarantee and correctness would depend on browser heuristics.

### Add a separate HTTP notification pull API

Rejected because it would duplicate credential, authorization, cursor, replay, E2EE, and snapshot semantics.

### Persist every encrypted message

Rejected because delayed delivery is unsafe for one-shot replies and recovery requests. The sender must explicitly select durable transport.

### Advance cursor immediately on `SNR1`

Rejected because missing removals or updates could be silently lost and old upserts could revive stale state.

### Reinterpret notification button indexes after settings change

Rejected because a stale native notification could invoke a different action. Button bindings remain tied to exact Chrome notification ID, notification revision, and action ID.

## Validation evidence

- MV3 lifecycle tests cover Worker reconstruction, stale socket generation, heartbeat timeout, bounded reconnect, and persistent close markers.
- Relay Delivery tests cover cursor isolation, commit-before-ACK, exact redelivery, caught-up checks, and history-gap persistence.
- Real `1 Android × 1 Chrome` history-gap acceptance kept cursor `2` while Android was unavailable, accepted reset `9` only after the fixed source response, then converged cursor and Server ACK to `11` after Server and Worker restart.
- Real mixed `2 Android × 2 Chrome` acceptance fixed two Android source identities, completed a two-source history-gap reset, demonstrated independent Chrome cursors, retained two offline deliveries for Chrome B, replayed and cumulatively ACKed them after browser restart, and ended with zero relay queue bytes.
- The same acceptance verified two-source notification isolation, action／reply／dismiss routing, Android process restart, Server restart, and both Chrome runtimes online.

## Release gates

Before a release candidate:

1. run compatibility checks on the supported Chrome and Chromium-derived browser versions;
2. complete accessibility and user-facing recovery UX for prolonged offline and revoked-source states;
3. include Worker lifecycle, cursor, and snapshot recovery in the independent security review;
4. define telemetry-free, plaintext-free diagnostics suitable for user support.
