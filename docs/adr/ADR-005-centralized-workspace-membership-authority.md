# ADR-005: Centralized workspace membership authority

- Status: **Accepted — trust-model decision; certificate, roster, authority-key custody, and migration protocols pending**
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
identity key, and role are valid in its accepted roster. Offline recovery must
refresh authorization before resuming business traffic according to a bounded
staleness policy that remains to be specified.

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

They remain frozen only long enough to preserve the already validated 1 × 1
synthetic path while the authority replacement is implemented. They must not be
expanded into an `N × M` product workflow, and the project must not retain
server certificates and pairwise pins as two independent production trust
sources. The replacement slice must remove or directly migrate obsolete code
rather than add a compatibility shell.

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

## Required next slices

1. Define authority-key generation, protected storage, backup, restore, and
   rotation.
2. Define canonical pending registration proof, device certificate, signed
   roster, revocation, and fixed vectors.
3. Implement Server persistence and local administrator approval commands.
4. Implement client authority-key pinning, highest-roster-epoch storage, and
   role enforcement.
5. Replace pairwise recipient discovery in notification fanout.
6. Remove obsolete bilateral pairing and per-peer identity-transition product
   paths.
7. Execute 1 Android × 2 Chrome enrollment, fanout, revocation, snapshot, and
   restart validation before proceeding to 2 × 2.
