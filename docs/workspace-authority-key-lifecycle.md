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

The private-key backup must be encrypted by the operator's backup system and stored separately from the live host. Copying only the database is insufficient.

The admin CLI creates and verifies a protected authority-key backup directory:

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  backup-authority --workspace <id> --output <new-directory>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  verify-authority-backup --workspace <id> --backup <directory>
```

`backup-authority` refuses an existing output path. It copies the exact PKCS#8 bytes and writes a canonical manifest binding the workspace ID, authority public key, domain-separated key ID, fixed private-key file name, and SHA-256 file digest. Creation immediately re-verifies the completed backup. On Unix, the directory and both files must remain owner-only `0700`／`0600`; symbolic links and non-regular files are rejected. The directory is intentionally not encrypted by SevenMirror: the operator must place it inside an encrypted backup system together with a consistent SQLite registry backup.

`verify-authority-backup` looks up the workspace authority public key from the selected live or restored SQLite registry. It then checks the canonical manifest, exact workspace／public-key／key-ID binding, digest, PKCS#8 encoding, Ed25519 key type, derived public key, file types, and permissions. It does not trust metadata from the backup to select the expected authority.

## Restore

A restore is valid only if all of the following match:

- workspace ID;
- authority public key stored in SQLite;
- public key derived from the restored PKCS#8 private key;
- authority key ID.

Loading fails closed for malformed PKCS#8, a non-Ed25519 key, unsafe Unix permissions, or a public-key mismatch. Restore must never generate a replacement key for an existing workspace.

Restore the SQLite registry first, select it through `NM_DATABASE_PATH`, then run:

```sh
NM_DATABASE_PATH=<restored-registry> NM_AUTHORITY_KEY_DIR=<live-key-directory> \
  go run ./cmd/admin restore-authority \
  --workspace <id> --backup <verified-backup-directory>
```

`restore-authority` re-verifies the complete backup against the authority public key in the selected registry before writing anything. It creates only the deterministic missing PKCS#8 file with exclusive owner-only permissions and verifies the restored file again. It never updates SQLite and never overwrites an existing file. Repeating an exact completed restore returns `result=already-present`; an existing corrupt or different file fails closed and remains unchanged.

## Rotation

The canonical authority-transition wire message and Server transactional rotation core are implemented. A transition binds the exact workspace, old and new keys, monotonic transition epoch, previous transition digest, activation roster epoch, previous roster digest, and issue time. It is signed independently by both the old and new authorities. The same SQLite transaction stores the transition, reissues every active certificate, inserts the new-authority-signed activation roster, and advances the current authority pointer.

The operational admin command and client transition-chain reconciliation remain intentionally disabled until Android and Chrome can durably apply the transition and activation roster atomically. Therefore this implementation cannot yet rotate a production workspace through supported CLI paths; direct unsigned replacement remains forbidden.

The private-key file must never be overwritten in place. A rotation creates a new file and retains the old key until every supported client has accepted the signed transition and the rollback window has closed.

## Loss and compromise

If the private key is lost without a verified backup, the workspace cannot issue trustworthy membership changes. The system must not silently generate a replacement. Recovery requires creating a new workspace and explicitly re-enrolling devices.

If compromise is suspected, an attacker may have authorized future recipients. Rotation alone cannot retract plaintext already delivered. The operator must stop enrollment, preserve evidence, rotate through the authenticated transition when safe, revoke malicious certificates, and re-enroll into a new workspace when the old authority can no longer be trusted.
