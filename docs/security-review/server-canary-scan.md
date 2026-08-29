# Server credential and plaintext canary scan

Status: **automated internal evidence; not an independent security approval**

## Security boundary

The Server may receive a pairing code in a bounded registration body, a
transport credential in the first binary WebSocket frame, and opaque encrypted
business envelopes. It must not place raw credentials or decrypted business
content in routine logs, URLs, HTTP errors, SQLite, WAL, SHM, backups, or support
artifacts.

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
5. registers through the real HTTP endpoint with the code in the JSON body and
   retains the one-time credential response only in memory;
6. retries the consumed code and submits an invalid request containing a unique
   synthetic business-text canary to exercise fixed HTTP error handling;
7. refuses redirects and records each effective request target;
8. scans live and stopped artifacts for the pairing code text and decoded bytes,
   transport credential text and decoded bytes, and business canary;
9. deletes the isolated directory after success or failure.

Scanned artifacts include Server stdout/stderr, HTTP error bodies, effective
URLs, the SQLite database, WAL, SHM, authority directory, and any temporary file
created under the isolated run directory. The expected result is zero matches.
The script reports only the canary class and artifact filename on failure; it
does not print the matched credential.

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

- Android logcat, crash output, SharedPreferences, databases, backup behavior,
  and debug exports still need a canary inventory and runtime scan;
- Chrome console, errors, IndexedDB, storage, notifications, and profile exports
  still need classification of expected endpoint-local plaintext;
- rotation-code stdout and the credential-rotation HTTP path still require the
  same real-entry scan;
- external reverse-proxy access logs and operator backup/support pipelines are
  deployment evidence, not covered by the in-process repository CI;
- release-candidate execution and independent review remain required.

Public protocol vectors and fixed test keys are not production secrets and are
outside this dynamic canary result. No broad path or keyword allowlist is used.
