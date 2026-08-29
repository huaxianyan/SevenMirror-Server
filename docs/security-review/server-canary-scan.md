# Server credential and plaintext canary scan

Status: **automated internal evidence; not an independent security approval**

## Security boundary

The Server may receive pairing and rotation codes in bounded HTTP bodies,
current/pending credentials in a rotation body, one transport credential in the
first binary WebSocket frame, and opaque encrypted business envelopes. It must
not place raw credentials or decrypted business content in routine logs, URLs,
HTTP errors, SQLite, WAL, SHM, backups, or support artifacts.

An explicit admin command is allowed to print a newly generated one-time pairing
or rotation code once to the operator's stdout. A successful registration
response is allowed to return the newly generated transport credential once.
These are narrow delivery channels, not routine diagnostic output.

## Automated entry point

CI builds the real Server and admin binaries, then runs:

```sh
python3 scripts/server_canary_scan.py --server ./server --admin ./admin
```

The script:

1. creates an isolated temporary authority directory and SQLite registry;
2. runs the real admin binary to initialize a workspace and issue one pairing
   code;
3. verifies that explicit admin stdout contains that code exactly once, then
   keeps the allowed output in memory rather than adding it to scanned
   artifacts;
4. starts the real Server binary on loopback with stdout and stderr captured;
5. starts a test-only loopback reverse proxy whose access log records only
   method, request path and response status;
6. verifies the removed `/v1/devices/register` route returns `404`, then
   registers through the real `/v1/membership/register` endpoint and retains
   the one-time pending credential response only in memory;
7. retries the consumed pairing code and submits an invalid membership
   registration body containing a unique synthetic business-text canary;
8. applies a test-only direct SQLite transition of that isolated row from
   `pending_proof` to `approved`, solely to reach credential-rotation and relay
   sensitive-state paths without adding a production test endpoint;
9. obtains the redacted `device_ref`, issues an exact-device rotation code with
   the real admin binary, and verifies that code appears once only in the
   allowed admin stdout;
10. generates a pending credential, rotates successfully through the proxy,
    then exercises consumed-code replay and malformed rotation errors;
11. probes the proxy's `/v1/relay` access-log target without forwarding the
    upgrade, and records the direct real WebSocket target separately;
12. connects to the real relay with exact binary `SNA1`: the old current token
    must receive generic policy close `1008`, while the pending token must
    receive exact binary `SNO1`;
13. refuses HTTP redirects, rejects query-bearing proxy targets, and records
    each effective HTTP/WebSocket target;
14. scans live and stopped artifacts for pairing/rotation code text and decoded
    bytes, current/pending credential text and decoded bytes, and the business
    canary;
15. deletes the isolated directory after success or failure.

Scanned artifacts include Server stdout/stderr, registration and rotation error
bodies, effective HTTP/WebSocket targets, the test proxy access log, SQLite,
WAL, SHM, authority directory, and every temporary file under the isolated run
directory. The expected result is zero matches. The script reports only the
canary class and artifact filename on failure; it does not print the matched
credential.

The access-log proxy is deliberately not a production reverse proxy and does
not forward WebSocket upgrades. It proves that the repository's recommended
method/path/status logging shape remains secret-free for legacy-route rejection,
membership registration, rotation and relay targets. The exact relay
authentication result is established through a separate direct connection to
the unmodified real Server binary.

The direct `pending_proof` → `approved` update is a canary fixture, not evidence
that possession proof or authority approval can be bypassed through a product
interface. The production HTTP API exposes no such transition. Membership
integration tests, canonical vectors and client tests remain the evidence for
challenge decryption, proof binding, administrator approval, certificate and
roster generation. This scanner uses the fixture only after a real pending
registration so it can inspect downstream credential placement with no test
command compiled into either production binary.

## Opaque relay storage evidence

`TestOfflineRecipientResumesDurableCiphertextAfterServerRestart` adds an
independent synthetic business canary. A test-only AES-GCM fixture transforms it
into ciphertext before constructing the structurally valid `SNE1` envelope. The
existing real WebSocket and durable relay path stores, restarts, resumes, and
acknowledges that exact envelope. The test scans SQLite, WAL, and SHM both while
the delivery is live and after clean shutdown.

The AES-GCM fixture is not a substitute for the Auth HPKE interoperability tests
and does not assert production encryption correctness. Its only purpose is to
prove that a known business canary entering the relay as opaque ciphertext does
not appear as plaintext in relay persistence.

## Explicit limitations

This slice does not yet close `SR-013`:

- this credential scanner's internal proxy still does not validate production
  forwarding; the separate pinned-Caddy gate in `scripts/caddy_proxy_canary.py`
  now covers the checked-in TLS, WebSocket, trusted-address and reduced-log
  baseline;
- `scripts/workspace_backup_restore_canary.py` separately proves a locally
  consistent registry/authority backup and isolated restore; encrypted off-host
  transport, retrieval, retention and deletion, plus container/runtime logs,
  observability exporters and operator support bundles, remain external evidence;
- WebSocket ciphertext persistence remains covered separately by the opaque
  relay restart test rather than duplicated here;
- Android privileged/system artifacts and full business-content paths, plus
  Chrome interaction DOM, crash/memory, sync/backup and OS artifacts, remain
  open in their endpoint reviews;
- release-candidate execution and independent review remain required.

Public protocol vectors and fixed test keys are not production secrets and are
outside this dynamic canary result. No broad path or keyword allowlist is used.
