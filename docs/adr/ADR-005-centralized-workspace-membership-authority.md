# ADR-005: Centralized workspace membership authority

- Status: **Accepted — enrollment, signed roster and revocation, business role enforcement, bilateral-source retirement, verified authority backup／restore, dual-signed authority rotation, and multi-device convergence are implemented**
- Date: 2026-08-19
- Owners: Server, Android, and Chrome projects

## Context

The provisional implementation separates server admission from E2EE trust. A
short-lived server pairing code creates transport credentials, while every
Android–Chrome communication edge requires a bilateral approved identity pin.
For `N` Android devices and `M` Chrome profiles this produces `N × M` manual
trust relationships. That does not scale to the intended multi-device product.

This is a private, self-hosted notification system rather than a hostile-server
messaging system. The operator already controls instance deployment, local
administrator commands, registration, revocation, upgrades, and backups. The
product therefore accepts the server administrator as the authority that
decides which devices are workspace members.

## Decision

### Trust boundary

The server administrator is the authoritative source of workspace membership,
device roles, and revocation. Once the administrator approves a device, clients
may accept its certified E2EE identity without comparing a separate safety code
with every existing communication peer.

This deliberately accepts the following risk:

> An administrator, or an attacker controlling the membership authority, can
> authorize an attacker-owned device. Other devices will then encrypt future
> authorized business payloads to that device.

The authority still does not possess device identity private keys and cannot
directly decrypt previously recorded ciphertext. Revocation cannot erase
plaintext already delivered to a device.

Product documentation and security claims must state this boundary explicitly.
The project must no longer claim protection against a malicious server adding a
future recipient.

### Registration and approval remain separate states

A short-lived, single-use registration code permits a device to prove possession
of its proposed identity key and create a pending server record. Registration
alone does not permit business traffic.

An administrator must explicitly approve the pending device. Approval causes the
workspace authority to issue a canonical signed device certificate. The exact
wire schema is a later protocol slice, but it must bind at least:

- protocol version and workspace ID;
- device ID, type, bounded display name, and roles;
- identity public key and its complete key ID;
- certificate ID, issue time, optional expiry, and membership epoch;
- the workspace authority signature over all preceding canonical fields.

The registration proof of possession, certificate signature algorithm, key
formats, and canonical encoding must be fixed by cross-client vectors before
clients consume certificates.

### Signed workspace roster

The authority publishes a canonical signed roster containing the current member
certificates and revocations. Roster versions use a strictly increasing epoch
and bind the previous accepted roster digest. Clients durably retain the highest
accepted epoch and reject rollback, same-epoch equivocation, invalid signatures,
unknown fields, and non-canonical encoding.

A client may send or accept a business envelope only when the relevant device,
identity key, and role are valid in its accepted roster. Clients continuously
refresh membership while online and refresh the durable authority／roster chain
before resuming business traffic. A certified revocation closes active relay
sessions within the authorization monitor's bounded 250-millisecond polling
window plus one local lookup; the system does not claim a zero-time window.

Device display names are workspace-wide authority facts, not client-local
aliases. Only the Server management boundary may change a name. For an approved
device, a rename replaces the active certificate through an authority-certified
transition in the next roster; clients accept it only when device identity,
type, roles, expiry, workspace, and device ID remain unchanged. Android and
Chrome display the accepted name read-only and do not maintain a second naming
model.

The relay may know administrative device metadata and authorization state. It
must still not parse, log, or persist notification titles, bodies, replies,
actions, operation results, snapshot contents, icons, or other encrypted
business payloads.

### Per-recipient E2EE remains mandatory

Centralized authorization does not introduce a shared workspace content key.
A sender still creates an independent Auth HPKE envelope for every authorized
recipient, with a fresh message ID and that recipient's durable sequence.
Compromise of one device identity key must not decrypt ciphertext addressed to
another device.

The roster determines eligible recipients; it does not prove delivery or visible
presentation and does not replace replay protection, notification revision,
snapshot reconciliation, delivery cursor, or operation idempotency.

### Roles and routing

The minimum authorization model must distinguish capabilities equivalent to:

- sending notifications;
- receiving notifications;
- invoking notification operations;
- managing workspace devices.

The server may enforce routing constraints visible from authenticated device
metadata, but a recipient must also enforce the authenticated sender's certified
role after opening the business payload. Relay enforcement alone is insufficient
because the relay does not inspect encrypted business message types.

### Revocation

Administrator revocation must atomically advance the signed roster epoch, mark
the exact certificate or device revoked, deny new transport authentication,
and close active sessions within the existing bounded authorization-monitor
window. Other clients stop creating new envelopes for the revoked recipient and
reject subsequent envelopes from its revoked identity.

Revocation applies prospectively. It cannot withdraw plaintext or private state
already delivered to the device.

### Existing pairwise trust implementation

The bilateral `sntrust1:` safety-code workflow, reciprocal approved-peer stores,
and per-peer identity-transition state are provisional spike artifacts and are
not the final multi-device trust model.

Authority replacement is now complete for notification, action invoke, action
result, and result ACK traffic. Android and Chrome product runtimes and temporary
acceptance UIs no longer expose or consult bilateral pairing or all-peer identity
transition. The obsolete client protocol codecs, stores, transition implementations, and
dedicated tests have been deleted. Only frozen canonical specifications, hashes,
vectors, and generated schema fields remain as protocol history; they are not a
fallback trust source and must not be reconnected to product runtime.

Identity rotation must be redesigned around authority-issued replacement
certificates and roster epochs. The existing all-approved-peer transition
protocol is not automatically carried forward.

## Consequences

### Positive

- One administrator approval enrolls a device for the workspace.
- Offline and newly added devices can converge through one signed roster.
- Roles and revocation have one authoritative definition.
- Notification payloads remain independently encrypted to each recipient.
- Multi-device UX no longer grows as `N × M` safety-code comparisons.

### Negative

- The membership authority can add a recipient that receives future data.
- Authority-key compromise becomes a workspace-wide security incident.
- Authority-key backup, restore, rotation, and disaster recovery become release
  blockers.
- Roster rollback and equivocation require durable client defenses.
- Existing pairing and identity-transition implementation must be simplified or
  removed rather than treated as sunk-cost architecture.

## Rejected alternatives

### Keep bilateral approval for every Android–Chrome edge

Rejected because manual trust grows as `N × M` and makes ordinary device
addition impractical.

### Let any approved device transitively add another device

Rejected as the default authority model because authorization policy and
recovery would be distributed across device-local state. A future high-assurance
co-signing option may be considered only after the centralized model is stable.

### Use one shared workspace content key

Rejected because one device compromise would expose traffic for every recipient
and make selective revocation significantly more expensive.

### Keep server certificates and pairwise pins as parallel production modes

Rejected because conflicting trust sources create ambiguous authorization,
rotation, and recovery behavior.

## Implementation status and remaining release gates

The authority model is implemented end to end:

1. [`../workspace-authority-key-lifecycle.md`](../workspace-authority-key-lifecycle.md)
   covers separated PKCS#8 custody, verified backup／restore, old/new-authority
   dual-signed transition, exact activation roster, and atomic current-authority
   replacement. Running Android and Chrome clients have accepted a real rotation
   and rejected an old-Server rollback after restart.
2. Android and Chrome independently verify the canonical pending proof, device
   certificate, signed roster, revocation, authority transition, and fixed
   vectors from [`../../protocol/workspace-membership-v1.md`](../../protocol/workspace-membership-v1.md).
3. Both clients implement bounded membership HTTP, authority pinning, contiguous
   roster and transition persistence, recoverable transport promotion, continuous
   refresh, role enforcement, and certified revocation.
4. Notification, snapshot, action invoke, action result, and result ACK recipient
   discovery and inbound authorization use only the signed roster. Obsolete
   bilateral pairing and per-peer identity-transition runtime paths have been
   removed; frozen protocol artifacts are not a fallback.
5. Real `1 Android × 2 Chrome` enrollment, fanout, operation, revocation, snapshot,
   and restart validation passed. Real mixed `2 Android × 2 Chrome` validation
   subsequently passed independent per-recipient encryption and cursor behavior,
   two-source snapshot recovery, action／reply／dismiss source routing, offline
   Chrome replay, and Server／Android／browser／Worker restart convergence.

Remaining release gates are operational rather than missing membership protocol
stages:

- independent review of authority compromise, backup custody, rotation, roster
  rollback, registration proof, and revocation boundaries;
- final administrator and client-facing enrollment／revocation UX;
- release documentation that states the accepted malicious-authority risk and
  requires an encrypted, consistent backup of both authority material and the
  SQLite registry.
