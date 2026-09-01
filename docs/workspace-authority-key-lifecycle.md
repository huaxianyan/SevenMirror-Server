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

Before approving any real device, the operator must create one bound backup containing:

1. a transactionally consistent SQLite registry snapshot; and
2. the exact authority PKCS#8 file named by the authority key recorded in that snapshot.

Copying a live SQLite main file is forbidden because committed state may still be in its WAL. `backup-workspace` instead uses SQLite's online backup API while the service database remains open:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  backup-workspace --workspace <id> --output <new-directory>
go run ./cmd/admin verify-workspace-backup \
  --workspace <id> --backup <directory>
```

The output path must not exist. It contains `registry.sqlite`, `manifest.txt`, and an `authority/` directory. The root canonical manifest binds the workspace ID, fixed registry filename, exact registry SHA-256, fixed authority directory, and authority key ID. The nested authority manifest binds the workspace ID, authority public key, domain-separated key ID, fixed private-key filename, and exact PKCS#8 digest.

Creation immediately re-verifies the completed backup. Verification checks the registry digest before opening it, runs SQLite integrity checking, requires the exact supported schema, reads the expected authority public key from the embedded registry rather than trusting backup metadata, and verifies the PKCS#8 encoding, Ed25519 type, derived public key, file types, exact directory entries, and permissions. On Unix, directories and files must remain owner-only `0700`／`0600`; symbolic links and non-regular files are rejected.

The directory contains an unencrypted authority private key and registry data. SevenMirror deliberately does not implement encryption with a key available to the relay process. The operator must transfer the completed directory into an access-controlled, encrypted backup system stored separately from the live host, apply retention and deletion policy, and periodically verify retrieval. The built-in command proves local consistency; it does not prove off-host durability or external encryption.

## Restore

A restore is valid only when the workspace ID, embedded registry, registry authority public key, PKCS#8-derived public key, and authority key ID all match. Restore must never generate a replacement authority for an existing workspace.

Restore into an offline, empty destination:

```sh
go run ./cmd/admin restore-workspace-backup \
  --workspace <id> \
  --backup <verified-backup-directory> \
  --database <new-restored-registry-file> \
  --authority-key-directory <restored-key-directory>
```

The command re-verifies the complete source before writing. It exclusive-creates the registry snapshot, verifies it again, and then restores the exact deterministic authority file with owner-only permissions. It refuses an existing registry file and never overwrites an existing authority file; an existing byte-identical authority is accepted, while a corrupt or different file fails closed. If authority restoration fails after creating the registry, the new registry file is removed.

Run the service only after the command succeeds. Then verify roster and authority epochs against independently retained operational records and reconnect supported clients. Client rollback floors reject older signed state, but that protection can turn a stale restore into an availability failure; it is not permission to restore an arbitrary old backup. The CI canary destroys the original local state, performs an isolated registry-plus-authority restore through the real admin binary, and creates and verifies another bound backup from the restored state. Operator-specific encrypted off-host retrieval and stale-backup recovery drills remain release requirements.

## Rotation

The canonical authority-transition wire message and Server transactional rotation core are implemented. A transition binds the exact workspace, old and new keys, monotonic transition epoch, previous transition digest, activation roster epoch, previous roster digest, and issue time. It is signed independently by both the old and new authorities. The same SQLite transaction stores the transition, reissues every active certificate, inserts the new-authority-signed activation roster, and advances the current authority pointer.

Android and Chrome durably apply each missing transition together with its activation roster before accepting the response authority pin. Operational rotation is therefore split into two explicit commands:

```text
notification-mirroring-admin prepare-authority-rotation
notification-mirroring-admin rotate-authority --workspace <id> --new-key-file <prepared-path>
```

Preparation exclusive-creates a protected PKCS#8 file without changing SQLite. Rotation loads that exact file, signs the transition with both authorities, and commits all durable membership changes atomically. Retrying `rotate-authority` with the same workspace and prepared file returns `result=already-rotated` only after re-reading and validating the committed transition and activation roster. A different new key is a new rotation intent. Direct unsigned replacement remains forbidden.

The private-key file must never be overwritten in place. A rotation creates a new file and retains the old key until every supported client has accepted the signed transition and the rollback window has closed.

## Loss and compromise

If the private key is lost without a verified backup, the workspace cannot issue trustworthy membership changes. The system must not silently generate a replacement. Recovery requires creating a new workspace and explicitly re-enrolling devices.

If compromise is suspected, an attacker may have authorized future recipients. Rotation alone cannot retract plaintext already delivered. The operator must stop enrollment, preserve evidence, rotate through the authenticated transition when safe, revoke malicious certificates, and re-enroll into a new workspace when the old authority can no longer be trusted.
