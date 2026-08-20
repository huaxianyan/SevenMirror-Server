# Membership HTTP v1

Status: provisional ADR-005 replacement API. These endpoints coexist with the frozen legacy `/v1/devices/register` path until Android and Chrome persist authority pins and signed roster rollback state.

All requests use `POST`, `Content-Type: application/json`, no redirects, no credentials in URLs, an 8192-byte body limit, unknown-field rejection, and canonical unpadded base64url binary values. Non-loopback use requires HTTPS.

## `POST /v1/membership/register`

Request fields are `pairing_code`, `device_type`, `device_name`, and the 65-byte P-256 `e2ee_public_key`. The short-lived one-time code is consumed in the same transaction that creates a `pending_proof` device.

The response contains:

- workspace and device IDs;
- a one-time returned 32-byte transport credential;
- the workspace authority Ed25519 public key;
- Base-HPKE challenge encapsulated key and ciphertext.

The client pins the authority public key to this registration. Registration does not authorize relay traffic. The server stores only the challenge digest, secret SHA-256, and expiry; it does not persist the raw challenge plaintext or secret.

## `POST /v1/membership/prove`

The request contains workspace/device IDs, the transport credential, and canonical `PendingIdentityProof` bytes. The proof must exactly match the unexpired challenge binding and may advance `pending_proof` to `pending_approval` once.

A successful response reports only `pending_approval`. It does not imply administrator approval or permit relay traffic.

## `POST /v1/membership/state`

The request contains workspace/device IDs, the transport credential, and `after_roster_epoch` as a canonical non-negative decimal string. Secrets remain in the JSON body rather than the URL.

The response contains:

- current internal membership state;
- the pinned authority public key;
- the device's signed certificate when approved;
- up to 256 contiguous signed rosters after the requested epoch;
- the latest server roster epoch as a decimal string.

If more than 256 roster versions are missing, the client validates the returned chain, persists its last accepted epoch/digest, and requests the next page. A previously enrolled client must not skip epochs. A newly approved client applies the bootstrap rule from `protocol/workspace-membership-v1.md`.

The endpoint authenticates pending or approved membership credentials but does not make pending credentials valid for WebSocket relay authentication.

## Legacy isolation

`/v1/devices/register` remains unchanged and creates explicit `legacy_active` records. It never returns an authority key, certificate, or roster. New clients must not combine a legacy approved-peer pin with Membership HTTP v1 as parallel trust sources.
