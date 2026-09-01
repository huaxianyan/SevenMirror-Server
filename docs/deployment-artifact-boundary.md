# Deployment artifact boundary

SevenMirror Server writes structured runtime events to stdout. The checked-in
runtime does not currently configure an observability exporter, log shipper,
crash collector or remote support service. Operators must not infer that an
external collector is safe merely because the Server's direct log passed a
local scan.

## Aggregate support summary

`scripts/build_support_bundle.py` creates a new local directory containing one
`summary.json`. It accepts the Server stdout/stderr files and the reduced Caddy
or canary access log:

```sh
python3 scripts/build_support_bundle.py \
  --server-stdout /var/log/sevenmirror/server.stdout.log \
  --server-stderr /var/log/sevenmirror/server.stderr.log \
  --access-log /var/log/sevenmirror/access.log \
  --output /tmp/sevenmirror-support
```

The summary contains only:

- runtime event counts grouped by `DEBUG`, `INFO`, `WARN` and `ERROR`;
- request counts grouped by HTTP method and status;
- fixed schema and boundary metadata.

It excludes timestamps, event messages, error details, network addresses, HTTP
paths, headers, bodies, raw logs and admin output. The destination must not
already exist. Input symlinks, malformed JSON events, non-canonical access-log
lines and non-empty Server stderr fail closed.

The resulting directory is still operational metadata. Apply access control,
retention and deletion appropriate to the deployment before sharing it. This
script does not upload, encrypt or delete the bundle and does not claim to be a
complete incident-response package.

## Admin stdout and terminal retention

`issue-pairing-code` and `issue-rotation-code` intentionally deliver one
short-lived secret exactly once on admin stdout. Successful membership
registration likewise delivers one credential in the HTTP response. These are
secret-delivery channels, not logs.

Do not include admin stdout, shell transcripts, terminal scrollback, CI command
output or successful registration bodies in support bundles or observability
pipelines. Run secret-issuing commands only from an access-controlled terminal
whose recording and scrollback policy is understood. Clear or expire retained
terminal sessions according to the operator's policy after the code has been
transferred.

The repository cannot enforce terminal emulator history, remote-session
recording, container runtime logging drivers, host journaling, third-party APM
agents or CI log retention. Each release deployment must verify those systems
separately.

## Automated evidence

`server_canary_scan.py` uses real Server and admin binaries, exercises pairing,
registration, rotation and WebSocket authentication, then builds the aggregate
support summary from the captured runtime and access logs. The final scan covers
the summary together with SQLite, WAL/SHM, authority files, HTTP errors, request
targets and direct logs.

The canary requires zero pairing-code, rotation-code, current/pending credential
or synthetic business-plaintext matches in every persisted artifact. Allowed
one-time secret delivery is validated in memory and is never passed to the
support-summary builder.

This is internal engineering evidence. It does not prove that a production
container log driver, exporter, support portal or operator terminal follows the
same boundary.
