# GHCR retention, deletion, ownership and emergency revocation

Status: **internal enforceable baseline; independent approval and durable archive remain open**

Last reviewed: 2026-09-02

## Scope and authority

This policy applies only to `ghcr.io/huaxianyan/sevenmirror-server`. It governs
multi-architecture index digests published by the protected Server release
workflow. It does not govern Android packages, Chrome Web Store packages,
workspace backups or GitHub Actions artifacts.

`security/registry-release-ledger.json` is the durable source-controlled record
of every known published candidate and every approval, retirement or revocation
decision. `scripts/validate_registry_release_ledger.py` validates it in normal CI
and before every protected publication. Ledger history must never be rewritten or
compacted to remove an old digest.

The registry is a distribution location, not the authority for release status.
A tag, package page, successful workflow or available digest does not make an
image approved. A deployment is allowed only when the exact index digest has an
`approved` ledger entry and the deployment separately satisfies the provenance,
security review, protocol/storage compatibility and backup requirements.

There are currently no production-approved SevenMirror Server images.

## Immutable identities and tags

- The deployable identity is
  `ghcr.io/huaxianyan/sevenmirror-server@sha256:<index>`.
- A 40-character source-revision tag is only a retrieval aid. The protected
  workflow refuses to repoint an existing revision tag to different content.
- No `latest`, environment, release-name or rollback tag may be used in a service
  definition.
- Registry digest availability does not replace offline OCI graph verification,
  GitHub attestation verification or the ledger decision.

An owner can still mutate or remove tags through the GHCR UI or API. Digest-pinned
deployment prevents a changed tag from silently changing deployed bytes, but it
cannot prevent owner deletion. Until a second package owner and independently
controlled archive exist, this remains a release-governance limitation.

## Ledger states

Every entry has exactly one state:

- `candidate`: published and verified by the protected workflow, but not approved
  for production;
- `approved`: approved for a named production claim by at least two distinct
  decision actors, with a durable public-safe decision reference;
- `retired`: no longer supported or selected, after an independent retention
  decision;
- `revoked`: unsafe or untrusted for new or continued deployment, with an
  attributable incident decision.

`registry_availability` records whether the digest is expected to remain
pullable. It is not a health probe. A transition to `removed` must preserve an
`archive_reference`; removal without retained evidence is invalid. The ledger
validator requires two distinct actors for `approved` and `retired`. Emergency
`revoked` decisions may be recorded by one incident actor so response is not
blocked by reviewer availability, but must receive independent post-incident
review.

A newly published digest must be added as `candidate` by pull request promptly
after its protected evidence is verified. Publication and approval are separate
changes; a workflow must not create an `approved` entry automatically.

## Retention

### Approved images

An approved index and both platform manifests remain available for the complete
support lifetime of every release or deployment that references them, plus at
least 365 days. They must also remain available while any supported rollback plan
names them. Expiry of a mutable tag does not shorten this period.

Before an approved entry can become `retired`, verify that:

1. no supported deployment, installation guide or rollback plan references it;
2. a newer compatible approved digest exists, or the product/channel is formally
   withdrawn;
3. the exact OCI archives, manifests, attestations, SBOMs and vulnerability
   evidence are retrievable from independently durable off-registry storage;
4. a restore-and-verify drill has succeeded;
5. two distinct actors record the decision and reference.

### Candidates

Unapproved candidates remain available for at least 180 days after publication
and until every investigation, comparison and review that references them is
closed. They may be retired after that period only when the same off-registry
archive and two-actor decision requirements are met.

Current GitHub Actions artifacts expire after 30 days and do not satisfy the
durable archive requirement. Therefore **ordinary GHCR deletion is currently
prohibited**, even for superseded candidates.

### Ledger and incident records

Ledger entries, decision references and public-safe incident records are retained
indefinitely in Git history even after registry content is removed. Credentials,
private reports, exploit material under embargo and notification plaintext must
not enter the ledger.

## Normal deletion procedure

There is no scheduled or automatic deletion workflow. For a non-emergency
removal:

1. prove the applicable retention period has elapsed;
2. retrieve the independently stored OCI and evidence sets into a clean location;
3. run the checked-in offline verifiers and `gh attestation verify` for every
   subject;
4. change the ledger to `retired`, include two decision actors and a decision
   reference, and merge through protected `main`;
5. perform the registry removal using a short-lived least-privilege credential;
6. anonymously confirm the exact digest is no longer pullable;
7. change `registry_availability` to `removed`, add the durable archive reference,
   and merge the observation through protected `main`.

Do not log package tokens or place them in command history. Do not delete a whole
package when only one exact digest is in scope. Failure at any step stops the
procedure; it does not authorize broader cleanup.

## Emergency revocation

Deletion is not revocation. Clients and hosts may retain pulled content, mirrors
may cache it, and an attacker may already possess it. An incident response must
first change the trust and deployment decision, not merely hide registry bytes.

For a suspected signing, workflow, dependency or image compromise:

1. stop further release workflow dispatches and deployments;
2. identify exact affected index and platform digests—never only a tag;
3. add or update each ledger entry to `revoked`, with incident reference,
   decision actor, decision time and replacement digest when known;
4. publish operator guidance to stop or replace running instances and verify the
   deployed digest;
5. rotate affected credentials or authority only when the incident scope requires
   it; package deletion does not rotate application trust;
6. preserve OCI, provenance, SBOM, vulnerability and workflow evidence in an
   access-controlled location unless the artifact itself contains prohibited
   secret material;
7. remove revision tags or registry content only when doing so reduces further
   harm, then record `removed` and the preserved-evidence reference;
8. perform independent post-incident review and determine whether other
   repositories or client compatibility windows are affected.

If no safe replacement exists, the correct instruction is to stop the service,
not to roll back to an unverified mutable tag. A replacement is acceptable only
when its own ledger state is `approved`.

## Ownership or repository transfer

Before changing package ownership, repository linkage, visibility or inherited
permissions:

1. freeze publication and ordinary deletion;
2. record all ledger digests and anonymously pull each expected-available index;
3. verify package visibility, repository linkage, workflow permissions and the
   identities allowed to delete packages before and after the change;
4. verify each digest again after the change and compare the complete OCI graph;
5. rotate package credentials and remove obsolete owners;
6. record the change and independent approval in the release review.

A transfer is incomplete if digest retrieval works but delete authority is
broader or unknown. The current GitHub CLI credential lacks `read:packages`, so
REST package-owner inventory is not claimed as evidence; changing that global
credential is outside this repository and was not performed.

## Periodic verification

At least monthly while a release is supported, and before every production
rollout or rollback:

- compare the intended digest with the ledger;
- anonymously pull every approved or selected rollback digest;
- verify the complete graph, source revision, runtime identity and attestations;
- confirm no service definition uses a mutable tag;
- review GHCR owner/delete permissions and repository linkage;
- confirm durable archive retrieval and its retention period.

The protected release workflow already proves publication-time pull-back and
runtime scanning. It does not provide continuous availability monitoring or
prevent an owner from deleting content after the run.
