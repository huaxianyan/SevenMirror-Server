# Workspace Preferences HTTP v1

Status: provisional workspace-scoped preference storage. Chrome uses it to share
notification shortcut rules across the browsers of one workspace. Android does
not read or write this API.

This endpoint pair stores opaque client-encrypted blobs. The server persists and
versions a preference value without ever parsing it, so it does not become a
second place where notification content or shortcut keywords are readable. It is
deliberately **not** part of `protocol/`: it is a device-facing HTTP API like the
membership API, not an E2EE wire message, and `NotificationShortcutPreferences`
remains a receiver-local concept.

All requests use `POST`, `Content-Type: application/json`, no redirects, no
credentials in URLs, a 512 KiB body limit, unknown-field rejection, and canonical
unpadded base64url binary values. Non-loopback use requires HTTPS.

## Scope and authorization

A preference is keyed by `(workspace_id, preference_key)`. Every approved device
of the workspace may read and write every key; the server has no per-device or
per-role preference authorization. A device authenticates with the same
`workspace_id`, `device_id`, and 32-byte transport credential tuple that the
membership API uses, so revocation and credential rotation apply unchanged.

Writes are bounded to 256 KiB of payload and keys are bounded to 64 visible ASCII
characters. A key is an opaque label, not a place to smuggle structured data.

## `POST /v1/workspace/preferences/read`

The request contains workspace/device IDs, the transport credential, and `key`.

The response contains `revision` as a canonical non-negative decimal string,
`payload` as canonical unpadded base64url, and `updated_at_ms` as a canonical
non-negative decimal string.

A key that was never written reports `revision` `0` with an empty `payload` and
`updated_at_ms` `0`. The zero revision is what lets a client distinguish "nothing
is stored yet" from "something is stored that I could not decrypt", which is the
state a device reaches when it holds the wrong synchronization passphrase.

## `POST /v1/workspace/preferences/write`

The request contains workspace/device IDs, the transport credential, `key`,
`payload`, and `expected_revision`.

- `expected_revision` `0` creates the key and reports revision `1`;
- a positive `expected_revision` replaces exactly that revision and reports the
  incremented revision;
- repeating a create for an existing key, or writing any revision the server did
  not store, is rejected with `409 Conflict` and leaves the stored value
  unchanged.

The revision guard exists so a device that fell behind cannot silently discard a
value another device already wrote. The client is responsible for resolving the
conflict: the server never merges, retries, or last-write-wins on its behalf.
Optimistic concurrency, not last-write-wins, is what keeps a stale tab from
erasing a newer rule set.

Rejected requests return `400` for a malformed revision, key, or base64 payload,
`403` for failed authentication, and `409` for a revision conflict. All four
responses are plain text bodies; no error response carries a stored value.

## What the server can still observe

Storing ciphertext does not make the endpoint metadata-free. The server sees, and
persists, the following for every workspace preference:

- the number of writes and their timing, via `revision` and `updated_at_ms`;
- the exact ciphertext length, which bounds the encoded rule count and total
  keyword length;
- which device performed each write, indirectly, through its own request logs.

A client that needs to hide rule count or keyword length must pad its plaintext
before encryption. v1 does not require padding and the current Chrome
implementation does not pad.

## Client obligations

The stored value is opaque to the server, so the client owns every guarantee that
makes it safe:

- derive the encryption key from a user-supplied passphrase, never from anything
  the server issued, or the server could decrypt the value it stores;
- bind the workspace ID and a fixed purpose string as authenticated additional
  data, so a ciphertext cannot be replayed under another workspace or another
  preference key;
- treat a decryption failure as "this device has the wrong passphrase", report
  it, and leave the local preference untouched rather than overwriting the
  local value with an unreadable one.
