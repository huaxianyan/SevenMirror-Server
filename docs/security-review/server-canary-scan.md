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
6. registers through the proxy-backed real HTTP endpoint, retaining the
   one-time current credential response only in memory;
7. retries the consumed pairing code and submits an invalid registration body
   containing a unique synthetic business-text canary;
8. obtains the redacted `device_ref`, issues an exact-device rotation code with
   the real admin binary, and verifies that code appears once only in the
   allowed admin stdout;
9. generates a pending credential, rotates successfully through the proxy, then
   exercises consumed-code replay and malformed rotation errors;
10. probes the proxy's `/v1/relay` access-log target without forwarding the
    upgrade, and records the direct real WebSocket target separately;
11. connects to the real relay with exact binary `SNA1`: the old current token
    must receive generic policy close `1008`, while the pending token must
    receive exact binary `SNO1`;
12. refuses HTTP redirects, rejects query-bearing proxy targets, and records
    each effective HTTP/WebSocket target;
13. scans live and stopped artifacts for pairing/rotation code text and decoded
    bytes, current/pending credential text and decoded bytes, and the business
    canary;
14. deletes the isolated directory after success or failure.

Scanned artifacts include Server stdout/stderr, registration and rotation error
bodies, effective HTTP/WebSocket targets, the test proxy access log, SQLite,
WAL, SHM, authority directory, and every temporary file under the isolated run
directory. The expected result is zero matches. The script reports only the
canary class and artifact filename on failure; it does not print the matched
credential.

The access-log proxy is deliberately not a production reverse proxy and does
not forward WebSocket upgrades. It proves that the repository's recommended
method/path/status logging shape remains secret-free for registration, rotation
and relay targets. The exact relay authentication result is established through
a separate direct connection to the unmodified real Server binary.

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

- the fixture does not validate a specific production Nginx/Caddy/Traefik
  configuration, TLS termination, forwarded-client-IP trust or full WebSocket
  upgrade forwarding;
- deployment backups, container/runtime logs, observability exporters and
  operator support bundles remain external evidence;
- WebSocket ciphertext persistence remains covered separately by the opaque
  relay restart test rather than duplicated here;
- Android privileged/system artifacts and full business-content paths, plus
  Chrome interaction DOM, crash/memory, sync/backup and OS artifacts, remain
  open in their endpoint reviews;
- release-candidate execution and independent review remain required.

Public protocol vectors and fixed test keys are not production secrets and are
outside this dynamic canary result. No broad path or keyword allowlist is used.
