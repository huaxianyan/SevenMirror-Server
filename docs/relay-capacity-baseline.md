# Relay capacity baseline

Status: **automated single-process engineering evidence; not production sizing**

`scripts/relay_capacity_canary.py` exercises the real Server and admin binaries.
It complements the low-threshold overload and slow-client checks in
`scripts/abuse_limit_canary.py`; it does not duplicate their `429`, `503` or
timeout assertions.

## Workload

The canary creates one isolated workspace and 32 approved test-only device rows.
The direct SQLite fixture exists only to create bounded relay identities without
adding a production enrollment bypass or issuing 32 authority certificates. The
real authentication query still requires each exact workspace, device, token
hash, approved state and non-revoked row.

The real Server then receives:

1. four reconnect waves of 32 concurrent authenticated WebSockets;
2. one final set of 32 concurrent authenticated WebSockets;
3. 2,000 structurally canonical online-only `SNE1` envelopes across 16
   sender／recipient pairs;
4. cursor-zero resume for four recipients, followed by 500 `SNQ1` durable
   submissions, exact `SND1` delivery IDs／ciphertext and `SND2` high-water;
5. four cumulative `SNC2` acknowledgements and SQLite queue convergence from an
   exact 500-row high-water to zero;
6. exact byte comparison for every online and durable ciphertext.

Every connection must receive exact `SNO1`; authentication success must be 100%.
The 2,000 online frames must sustain at least 100 frames per second. The 500
SQLite-backed durable frames must sustain at least 50 frames per second, and all
cumulative ACKs must clear the queue within 5 seconds.

The thresholds are regression floors for the small CI workload, not throughput
or latency promises. They do not predict performance for large envelopes, queue
eviction, WAL checkpoint pressure, WAN latency, TLS termination, multiple
workspaces or production hardware.

## Resource bounds

The canary records baseline, peak and post-cleanup resident memory plus open file
descriptors on Linux or process handles on Windows. It fails when:

- peak RSS grows by more than 128 MiB from the ready-state baseline;
- post-cleanup descriptors／handles remain more than 96 above baseline after a
  bounded 5-second cleanup window.

Windows handle counts include Go runtime and SQLite handles that remain pooled
after socket cleanup, so they are not numerically equivalent to Linux file
descriptors. The bound detects large regressions; it is not a claim that every
resource returns to its startup count.

## Remaining production evidence

This gate uses loopback HTTP, one Server process, small ciphertexts and a local
temporary SQLite filesystem. Production release still requires measurements
with the actual hostname, TLS／Caddy or load balancer, container limits, service
manager, filesystem, SQLite storage, log exporter and network path. Record CPU,
RSS, descriptors, commit／checkpoint latency, authentication success and overload
behavior under the intended reconnect population, durable-delivery mix,
envelope sizes, queue depth and test duration.

A single-process pass does not establish distributed rate-limit coordination,
autoscaling behavior, multi-instance routing, external load-balancer fairness or
host firewall capacity.
