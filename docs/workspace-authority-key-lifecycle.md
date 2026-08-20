# Workspace authority key lifecycle

Status: provisional implementation contract for ADR-005.

## Scope

Each workspace has one Ed25519 membership authority. The authority signs device certificates, rosters, revocations, and future authority-key transitions. It is never used to encrypt notification content and is not a device Auth HPKE identity.

## Generation and storage

`notification-mirroring-admin init-workspace` generates a fresh authority before committing the workspace:

- the public key is stored with the workspace in SQLite;
- the private key is encoded as unencrypted PKCS#8 in a separate file;
- the key directory and file are created with owner-only `0700` and `0600` permissions where the operating system supports POSIX modes;
- the file name is derived from the domain-separated SHA-256 authority key ID;
- existing files are never overwritten;
- the CLI prints only the workspace ID, public key ID, and private-key file location.

The private key deliberately remains outside the relay database. The relay process does not need it for ciphertext forwarding. A host administrator or an attacker with equivalent filesystem access can still read it; encryption by a passphrase available to the same unattended process would not remove that trust boundary.

Existing workspaces created before schema version 3 retain a null authority public key. They are provisional legacy workspaces and are not silently assigned a new authority.

## Backup

Before approving any real device, the operator must back up both:

1. the SQLite registry; and
2. the exact authority PKCS#8 file named by the workspace authority key ID.

The private-key backup must be encrypted by the operator's backup system and stored separately from the live host. Copying only the database is insufficient. Backup tooling and a verification command remain release blockers; current development workspaces must contain only synthetic data.

## Restore

A restore is valid only if all of the following match:

- workspace ID;
- authority public key stored in SQLite;
- public key derived from the restored PKCS#8 private key;
- authority key ID.

Loading fails closed for malformed PKCS#8, a non-Ed25519 key, unsafe Unix permissions, or a public-key mismatch. Restore must never generate a replacement key for an existing workspace.

## Rotation

Normal rotation will require an old-authority-signed transition binding the exact old key, new key, workspace, transition epoch, and activation rules. Clients must accept the new key only through that protocol and retain rollback protection. This wire protocol is not implemented yet.

The private-key file must never be overwritten in place. A rotation creates a new file and retains the old key until every supported client has accepted the signed transition and the rollback window has closed.

## Loss and compromise

If the private key is lost without a verified backup, the workspace cannot issue trustworthy membership changes. The system must not silently generate a replacement. Recovery requires creating a new workspace and explicitly re-enrolling devices.

If compromise is suspected, an attacker may have authorized future recipients. Rotation alone cannot retract plaintext already delivered. The operator must stop enrollment, preserve evidence, rotate through the authenticated transition when safe, revoke malicious certificates, and re-enroll into a new workspace when the old authority can no longer be trusted.
