package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

func TestPairingCodeRegistersExactlyOnePersistentDevice(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("database mode = %o, want 600", info.Mode().Perm())
		}
	}
	now := time.UnixMilli(1_800_000_000_000)
	workspace, err := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	storedAuthority, err := store.WorkspaceAuthorityPublicKey(ctx, workspace)
	if err != nil || storedAuthority != testAuthorityPublicKey() {
		t.Fatalf("stored authority=%x error=%v", storedAuthority, err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, DeviceAndroid, "Pixel", now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Pixel",
		E2EEPublicKey: testPublicKey(), Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.AuthToken) != authTokenBytes {
		t.Fatalf("auth token has %d bytes", len(registered.AuthToken))
	}
	pairingSecret, _ := base64.RawURLEncoding.DecodeString(code)
	for _, databaseFile := range []string{path, path + "-wal"} {
		contents, readErr := os.ReadFile(databaseFile)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, pairingSecret) || bytes.Contains(contents, registered.AuthToken) {
			t.Fatalf("raw credential persisted in %s", databaseFile)
		}
	}
	if _, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Pixel",
		E2EEPublicKey: testPublicKey(), Now: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("reused code error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path)
	identity, err := reopened.Authenticate(ctx, registered.WorkspaceID, registered.DeviceID,
		registered.AuthToken, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceType != DeviceAndroid || identity.DeviceName != "Pixel" || identity.CredentialVersion != 1 {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	wrongToken := append([]byte(nil), registered.AuthToken...)
	wrongToken[0] ^= 1
	if _, err := reopened.Authenticate(ctx, registered.WorkspaceID, registered.DeviceID,
		wrongToken, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestPairingCodeConstraintsDoNotLeakOrConsumeOnWrongType(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)

	_, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("wrong type error = %v", err)
	}
	if _, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	}); err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}

	expired, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "", now, time.Second)
	if _, err := store.Register(ctx, Registration{
		PairingCode: expired, DeviceType: DeviceChrome, DeviceName: "Late",
		E2EEPublicKey: testPublicKey(), Now: now.Add(time.Second),
	}); !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("expired code error = %v", err)
	}
}

func TestPendingRegistrationRequiresExactIdentityProofBeforeApproval(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	now := time.UnixMilli(1_800_000_000_000)
	authorityPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	defer clear(authorityPrivateKey)
	var authorityPublicKey membership.AuthorityPublicKey
	copy(authorityPublicKey[:], authorityPrivateKey.Public().(ed25519.PublicKey))
	workspace, err := store.CreateWorkspace(ctx, authorityPublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x41}, sha256.Size)
	secret := bytes.Repeat([]byte{0x42}, sha256.Size)
	device, err := store.RegisterPending(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome,
		DeviceName: "Browser", E2EEPublicKey: testPublicKey(), Now: now,
	}, func(challengeWorkspace WorkspaceID, challengeDevice DeviceID) (PendingChallenge, error) {
		if challengeWorkspace != workspace || challengeDevice == (DeviceID{}) {
			t.Fatal("challenge factory received the wrong device binding")
		}
		return PendingChallenge{Digest: digest, Secret: secret, ExpiresAt: now.Add(5 * time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, workspace, device.DeviceID, device.AuthToken, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pending relay authentication error=%v", err)
	}
	wrongSecret := append([]byte(nil), secret...)
	wrongSecret[0] ^= 1
	proof := PendingIdentityProof{WorkspaceID: workspace, DeviceID: device.DeviceID,
		AuthToken: device.AuthToken, ChallengeDigest: digest, ChallengeSecret: wrongSecret,
		Now: now.Add(time.Minute)}
	if err := store.CompletePendingIdentityProof(ctx, proof); !errors.Is(err, ErrInvalidMembershipProof) {
		t.Fatalf("wrong proof error=%v", err)
	}
	proof.ChallengeSecret = secret
	if err := store.CompletePendingIdentityProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePendingIdentityProof(ctx, proof); !errors.Is(err, ErrInvalidMembershipProof) {
		t.Fatalf("repeated proof error=%v", err)
	}
	var state string
	var storedSecret []byte
	if err := store.db.QueryRow(`SELECT membership_state, proof_secret_hash FROM devices
		WHERE workspace_id = ? AND id = ?`, workspace[:], device.DeviceID[:]).Scan(&state, &storedSecret); err != nil {
		t.Fatal(err)
	}
	if state != "pending_approval" || storedSecret != nil {
		t.Fatalf("membership state=%q secret hash retained=%t", state, storedSecret != nil)
	}
	approved, err := store.ApprovePendingMembership(ctx, ApprovePendingDevice{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID),
		Roles: []membershipv1.DeviceRole{
			membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS,
			membershipv1.DeviceRole_DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS,
		},
		AuthorityPrivateKey: authorityPrivateKey, Now: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.RosterEpoch != 1 || approved.CertificateID == ([sha256.Size]byte{}) ||
		approved.RosterDigest == ([sha256.Size]byte{}) {
		t.Fatalf("unexpected approval result: %+v", approved)
	}
	if _, err := store.Authenticate(ctx, workspace, device.DeviceID, device.AuthToken, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("approved relay authentication failed: %v", err)
	}

	secondCode, err := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Second Browser", now.Add(3*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RegisterPending(ctx, Registration{
		PairingCode: secondCode, DeviceType: DeviceChrome, DeviceName: "Second Browser",
		E2EEPublicKey: testPublicKey(), Now: now.Add(3 * time.Minute),
	}, func(WorkspaceID, DeviceID) (PendingChallenge, error) {
		return PendingChallenge{Digest: digest, Secret: secret, ExpiresAt: now.Add(8 * time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePendingIdentityProof(ctx, PendingIdentityProof{
		WorkspaceID: workspace, DeviceID: second.DeviceID, AuthToken: second.AuthToken,
		ChallengeDigest: digest, ChallengeSecret: secret, Now: now.Add(4 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApprovePendingMembership(ctx, ApprovePendingDevice{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, second.DeviceID),
		Roles:               []membershipv1.DeviceRole{membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS},
		AuthorityPrivateKey: authorityPrivateKey, Now: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	secondState, err := store.ReadMembershipState(ctx, workspace, second.DeviceID, second.AuthToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	if secondState.LatestRosterEpoch != 2 || len(secondState.Rosters) != 1 {
		t.Fatalf("second-device bootstrap latest=%d rosters=%d", secondState.LatestRosterEpoch, len(secondState.Rosters))
	}
	bootstrapRoster, err := membershipcodec.DecodeSignedWorkspaceRoster(
		secondState.Rosters[0], authorityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil || bootstrapRoster.GetRoster().GetRosterEpoch() != 2 {
		t.Fatalf("second-device bootstrap roster=%+v error=%v", bootstrapRoster, err)
	}

	var signedRoster []byte
	if err := store.db.QueryRow(`SELECT signed_roster FROM workspace_rosters
		WHERE workspace_id = ? AND epoch = 1`, workspace[:]).Scan(&signedRoster); err != nil {
		t.Fatal(err)
	}
	decodedRoster, err := membershipcodec.DecodeSignedWorkspaceRoster(
		signedRoster, authorityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil || len(decodedRoster.GetRoster().GetActiveCertificates()) != 1 {
		t.Fatalf("stored roster=%+v error=%v", decodedRoster, err)
	}
	if _, err := store.ApprovePendingMembership(ctx, ApprovePendingDevice{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID),
		Roles:               []membershipv1.DeviceRole{membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS},
		AuthorityPrivateKey: authorityPrivateKey, Now: now.Add(4 * time.Minute),
	}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("repeated approval error=%v", err)
	}
	if _, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID),
		Now: now.Add(6 * time.Minute),
	}); !errors.Is(err, ErrWorkspaceAuthorityUnavailable) {
		t.Fatalf("certified revocation without authority error=%v", err)
	}
	if authorized, err := store.IsDeviceAuthorized(ctx, workspace, device.DeviceID); err != nil || !authorized {
		t.Fatalf("failed revocation changed authorization=%v error=%v", authorized, err)
	}
	revoked, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID),
		AuthorityPrivateKey: authorityPrivateKey, Now: now.Add(6 * time.Minute),
	})
	if err != nil || !revoked.Changed || revoked.RosterEpoch != 3 ||
		revoked.RosterDigest == ([sha256.Size]byte{}) {
		t.Fatalf("certified revocation=%+v error=%v", revoked, err)
	}
	var revocationRosterBytes []byte
	if err := store.db.QueryRow(`SELECT signed_roster FROM workspace_rosters
		WHERE workspace_id = ? AND epoch = 3`, workspace[:]).Scan(&revocationRosterBytes); err != nil {
		t.Fatal(err)
	}
	revocationRoster, err := membershipcodec.DecodeSignedWorkspaceRoster(
		revocationRosterBytes, authorityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(revocationRoster.GetRoster().GetPreviousRosterDigest(), bootstrapRoster.GetRosterDigest()) ||
		len(revocationRoster.GetRoster().GetActiveCertificates()) != 1 ||
		!bytes.Equal(revocationRoster.GetRoster().GetActiveCertificates()[0].GetCertificate().GetDeviceId(), second.DeviceID[:]) ||
		len(revocationRoster.GetRoster().GetRevocations()) != 1 ||
		!bytes.Equal(revocationRoster.GetRoster().GetRevocations()[0].GetCertificateId(), approved.CertificateID[:]) ||
		!bytes.Equal(revocationRoster.GetRoster().GetRevocations()[0].GetDeviceId(), device.DeviceID[:]) {
		t.Fatalf("unexpected revocation roster: %+v", revocationRoster)
	}
	if authorized, err := store.IsSessionAuthorized(ctx, workspace, device.DeviceID, 1); err != nil || authorized {
		t.Fatalf("revoked certified session authorization=%v error=%v", authorized, err)
	}
	if authorized, err := store.IsSessionAuthorized(ctx, workspace, second.DeviceID, 1); err != nil || !authorized {
		t.Fatalf("remaining certified session authorization=%v error=%v", authorized, err)
	}
	remainingState, err := store.ReadMembershipState(
		ctx, workspace, second.DeviceID, second.AuthToken, 2)
	if err != nil || remainingState.LatestRosterEpoch != 3 || len(remainingState.Rosters) != 1 ||
		!bytes.Equal(remainingState.Rosters[0], revocationRosterBytes) {
		t.Fatalf("remaining member revocation page=%+v error=%v", remainingState, err)
	}
	revokedState, err := store.ReadMembershipState(
		ctx, workspace, device.DeviceID, device.AuthToken, 2)
	if err != nil || revokedState.State != "approved" || revokedState.LatestRosterEpoch != 3 ||
		len(revokedState.Rosters) != 1 ||
		!bytes.Equal(revokedState.Rosters[0], revocationRosterBytes) {
		t.Fatalf("revoked member terminal page=%+v error=%v", revokedState, err)
	}
	revokedTerminalState, err := store.ReadMembershipState(
		ctx, workspace, device.DeviceID, device.AuthToken, 3)
	if err != nil || revokedTerminalState.LatestRosterEpoch != 3 ||
		len(revokedTerminalState.Rosters) != 0 {
		t.Fatalf("revoked member state was not clamped=%+v error=%v", revokedTerminalState, err)
	}
	duplicate, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID),
		AuthorityPrivateKey: authorityPrivateKey, Now: now.Add(7 * time.Minute),
	})
	if err != nil || duplicate.Changed {
		t.Fatalf("duplicate certified revocation=%+v error=%v", duplicate, err)
	}

	// A schema-v4 installation may already contain certified revocations. The
	// v5 migration must recover the exact terminal epoch from signed rosters.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DROP TABLE workspace_authority_transitions`,
		`ALTER TABLE workspaces DROP COLUMN authority_transition_digest`,
		`ALTER TABLE workspaces DROP COLUMN authority_epoch`,
		`ALTER TABLE devices DROP COLUMN revoked_membership_epoch`,
		`DELETE FROM schema_migrations WHERE version IN (5, 6)`,
	} {
		if _, err := legacyDB.Exec(statement); err != nil {
			legacyDB.Close()
			t.Fatal(err)
		}
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	var migratedEpoch int64
	if err := migrated.db.QueryRow(`SELECT revoked_membership_epoch FROM devices
		WHERE workspace_id = ? AND id = ?`, workspace[:], device.DeviceID[:]).Scan(
		&migratedEpoch); err != nil || migratedEpoch != 3 {
		t.Fatalf("migrated revocation epoch=%d error=%v", migratedEpoch, err)
	}
	migratedState, err := migrated.ReadMembershipState(
		ctx, workspace, device.DeviceID, device.AuthToken, 2)
	if err != nil || migratedState.LatestRosterEpoch != 3 || len(migratedState.Rosters) != 1 {
		t.Fatalf("migrated revoked member page=%+v error=%v", migratedState, err)
	}
	for _, databaseFile := range []string{path, path + "-wal"} {
		contents, readErr := os.ReadFile(databaseFile)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, secret) {
			t.Fatalf("raw challenge secret persisted in %s", databaseFile)
		}
	}
}

func TestWorkspaceAuthorityRotationReissuesRosterAtomically(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	oldKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
	defer clear(oldKey)
	defer clear(newKey)
	var oldPublic membership.AuthorityPublicKey
	copy(oldPublic[:], oldKey.Public().(ed25519.PublicKey))
	workspace, err := store.CreateWorkspace(ctx, oldPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x31}, sha256.Size)
	secret := bytes.Repeat([]byte{0x32}, sha256.Size)
	device, err := store.RegisterPending(ctx, Registration{PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser", E2EEPublicKey: testPublicKey(), Now: now}, func(WorkspaceID, DeviceID) (PendingChallenge, error) {
		return PendingChallenge{Digest: digest, Secret: secret, ExpiresAt: now.Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePendingIdentityProof(ctx, PendingIdentityProof{WorkspaceID: workspace, DeviceID: device.DeviceID, AuthToken: device.AuthToken, ChallengeDigest: digest, ChallengeSecret: secret, Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	approved, err := store.ApprovePendingMembership(ctx, ApprovePendingDevice{WorkspaceID: workspace, DeviceReference: deviceReference(workspace, device.DeviceID), Roles: []membershipv1.DeviceRole{membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS}, AuthorityPrivateKey: oldKey, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := store.RotateWorkspaceAuthority(ctx, RotateWorkspaceAuthorityInput{WorkspaceID: workspace, PreviousAuthorityPrivateKey: oldKey, NewAuthorityPrivateKey: newKey, Now: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AuthorityEpoch != 2 || rotated.RosterEpoch != approved.RosterEpoch+1 || rotated.TransitionDigest == ([sha256.Size]byte{}) {
		t.Fatalf("unexpected rotation: %+v", rotated)
	}
	transition, err := membershipcodec.DecodeSignedAuthorityKeyTransition(rotated.SignedTransition)
	if err != nil || transition.GetTransition().GetActivationRosterEpoch() != uint64(rotated.RosterEpoch) || !bytes.Equal(transition.GetTransition().GetPreviousRosterDigest(), approved.RosterDigest[:]) {
		t.Fatalf("transition binding invalid: %v", err)
	}
	var newPublic membership.AuthorityPublicKey
	copy(newPublic[:], newKey.Public().(ed25519.PublicKey))
	completed, ok, err := store.CompletedWorkspaceAuthorityRotation(ctx, workspace, newPublic)
	if err != nil || !ok || completed.TransitionDigest != rotated.TransitionDigest || completed.RosterDigest != rotated.RosterDigest {
		t.Fatalf("completed rotation recovery=%+v ok=%t error=%v", completed, ok, err)
	}
	wrongPublic := membership.AuthorityPublicKey{1}
	if _, ok, err := store.CompletedWorkspaceAuthorityRotation(ctx, workspace, wrongPublic); err != nil || ok {
		t.Fatalf("wrong rotation recovery ok=%t error=%v", ok, err)
	}
	current, err := store.WorkspaceAuthorityPublicKey(ctx, workspace)
	if err != nil || !bytes.Equal(current[:], newKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("current authority mismatch: %v", err)
	}
	state, err := store.ReadMembershipState(ctx, workspace, device.DeviceID, device.AuthToken, 1)
	if err != nil || len(state.AuthorityTransitions) != 1 || len(state.Rosters) != 1 || state.LatestRosterEpoch != 2 {
		t.Fatalf("rotation roster state=%+v error=%v", state, err)
	}
	roster, err := membershipcodec.DecodeSignedWorkspaceRoster(state.Rosters[0], newKey.Public().(ed25519.PublicKey))
	if err != nil || !bytes.Equal(roster.GetRosterDigest(), rotated.RosterDigest[:]) {
		t.Fatalf("activation roster invalid: %v", err)
	}
	certificate, err := membershipcodec.DecodeSignedDeviceCertificate(state.SignedCertificate, newKey.Public().(ed25519.PublicKey))
	if err != nil || certificate.GetCertificate().GetMembershipEpoch() != 2 {
		t.Fatalf("replacement certificate invalid: %v", err)
	}
	if _, err := store.RotateWorkspaceAuthority(ctx, RotateWorkspaceAuthorityInput{WorkspaceID: workspace, PreviousAuthorityPrivateKey: oldKey, NewAuthorityPrivateKey: newKey, Now: now.Add(4 * time.Second)}); !errors.Is(err, ErrWorkspaceAuthorityUnavailable) {
		t.Fatalf("stale authority rotation error=%v", err)
	}
}

func TestConcurrentPairingCodeConsumptionAllowsOneRegistration(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceAndroid, "", now, time.Minute)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := store.Register(ctx, Registration{
				PairingCode: code, DeviceType: DeviceAndroid,
				DeviceName: fmt.Sprintf("phone-%d", index), E2EEPublicKey: testPublicKey(), Now: now,
			})
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrInvalidPairingCode) {
			rejected++
		} else {
			t.Fatalf("unexpected registration error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejected=%d", successes, rejected)
	}
}

func TestDeviceRevocationIsIdempotentPersistentAndWorkspaceBound(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	otherWorkspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	register := func(name string) RegisteredDevice {
		code, err := store.IssuePairingCode(ctx, workspace, DeviceChrome, name, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		device, err := store.Register(ctx, Registration{
			PairingCode: code, DeviceType: DeviceChrome, DeviceName: name,
			E2EEPublicKey: testPublicKey(), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return device
	}
	revokedDevice := register("revoked browser")
	activeDevice := register("active browser")
	devices, err := store.ListDevices(ctx, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 || devices[0].Reference == devices[1].Reference {
		t.Fatalf("unexpected device summaries: %+v", devices)
	}
	for _, device := range devices {
		if len(device.Reference) != 16 || device.Revoked {
			t.Fatalf("unexpected device summary: %+v", device)
		}
	}
	reference := deviceReference(workspace, revokedDevice.DeviceID)
	if reference == deviceReference(otherWorkspace, revokedDevice.DeviceID) {
		t.Fatal("device reference was not workspace-bound")
	}
	if _, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: "not-canonical", Now: now,
	}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("malformed reference error = %v", err)
	}
	unknownReference := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 12))
	if _, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: unknownReference, Now: now,
	}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("unknown reference error = %v", err)
	}
	if _, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: otherWorkspace, DeviceReference: reference, Now: now,
	}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("cross-workspace revocation error = %v", err)
	}
	if revoked, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: reference, Now: now.Add(time.Second),
	}); err != nil || !revoked.Changed {
		t.Fatalf("first revocation=%+v error=%v", revoked, err)
	}
	if revoked, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: reference, Now: now.Add(2 * time.Second),
	}); err != nil || revoked.Changed {
		t.Fatalf("duplicate revocation=%+v error=%v", revoked, err)
	}
	if _, err := store.Authenticate(ctx, workspace, revokedDevice.DeviceID,
		revokedDevice.AuthToken, now.Add(3*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked authentication error = %v", err)
	}
	if _, err := store.Authenticate(ctx, workspace, activeDevice.DeviceID,
		activeDevice.AuthToken, now.Add(3*time.Second)); err != nil {
		t.Fatalf("other device authentication failed: %v", err)
	}
	if authorized, err := store.IsDeviceAuthorized(ctx, workspace, revokedDevice.DeviceID); err != nil || authorized {
		t.Fatalf("revoked authorization=%v error=%v", authorized, err)
	}
	if authorized, err := store.IsDeviceAuthorized(ctx, workspace, activeDevice.DeviceID); err != nil || !authorized {
		t.Fatalf("active authorization=%v error=%v", authorized, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	if _, err := reopened.Authenticate(ctx, workspace, revokedDevice.DeviceID,
		revokedDevice.AuthToken, now.Add(4*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reopened revoked authentication error = %v", err)
	}
	listed, err := reopened.ListDevices(ctx, workspace)
	if err != nil {
		t.Fatal(err)
	}
	revokedCount := 0
	for _, device := range listed {
		if device.Reference == reference && device.Revoked {
			revokedCount++
		}
	}
	if revokedCount != 1 {
		t.Fatalf("revoked summaries = %d, want 1", revokedCount)
	}
}

func TestCredentialRotationIsAtomicPersistentAndRecoverable(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	reference := deviceReference(workspace, registered.DeviceID)
	rotationCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, reference, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pending := bytes.Repeat([]byte{0x71}, authTokenBytes)
	wrongCurrent := bytes.Repeat([]byte{0x72}, authTokenBytes)
	input := CredentialRotation{
		WorkspaceID: workspace, DeviceID: registered.DeviceID,
		CurrentAuthToken: wrongCurrent, RotationCode: rotationCode,
		PendingAuthToken: pending, Now: now.Add(time.Second),
	}
	if _, err := store.RotateCredential(ctx, input); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("wrong-current error = %v", err)
	}
	input.CurrentAuthToken = registered.AuthToken
	input.PendingAuthToken = registered.AuthToken
	if _, err := store.RotateCredential(ctx, input); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("same-token error = %v", err)
	}
	input.PendingAuthToken = pending
	version, err := store.RotateCredential(ctx, input)
	if err != nil || version != 2 {
		t.Fatalf("rotation version=%d error=%v", version, err)
	}
	if _, err := store.RotateCredential(ctx, input); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("duplicate rotation error = %v", err)
	}
	if _, err := store.Authenticate(ctx, workspace, registered.DeviceID,
		registered.AuthToken, now.Add(2*time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old credential error = %v", err)
	}
	identity, err := store.Authenticate(ctx, workspace, registered.DeviceID,
		pending, now.Add(2*time.Second))
	if err != nil || identity.CredentialVersion != 2 {
		t.Fatalf("pending authentication identity=%+v error=%v", identity, err)
	}
	if authorized, err := store.IsSessionAuthorized(ctx, workspace, registered.DeviceID, 1); err != nil || authorized {
		t.Fatalf("old session authorization=%v error=%v", authorized, err)
	}
	if authorized, err := store.IsSessionAuthorized(ctx, workspace, registered.DeviceID, 2); err != nil || !authorized {
		t.Fatalf("new session authorization=%v error=%v", authorized, err)
	}
	var storedPublicKey []byte
	if err := store.db.QueryRow(`SELECT e2ee_public_key FROM devices WHERE workspace_id = ? AND id = ?`,
		workspace[:], registered.DeviceID[:]).Scan(&storedPublicKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedPublicKey, testPublicKey()) {
		t.Fatal("credential rotation changed E2EE identity")
	}
	rotationSecret, _ := base64.RawURLEncoding.DecodeString(rotationCode)
	for _, databaseFile := range []string{path, path + "-wal"} {
		contents, readErr := os.ReadFile(databaseFile)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, rotationSecret) || bytes.Contains(contents, registered.AuthToken) ||
			bytes.Contains(contents, pending) {
			t.Fatalf("raw rotation secret persisted in %s", databaseFile)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	identity, err = reopened.Authenticate(ctx, workspace, registered.DeviceID,
		pending, now.Add(3*time.Second))
	if err != nil || identity.CredentialVersion != 2 {
		t.Fatalf("reopened authentication identity=%+v error=%v", identity, err)
	}
}

func TestConcurrentCredentialRotationAllowsOneCommit(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	pairingCode, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	device, err := store.Register(ctx, Registration{
		PairingCode: pairingCode, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, deviceReference(workspace, device.DeviceID), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			_, err := store.RotateCredential(ctx, CredentialRotation{
				WorkspaceID: workspace, DeviceID: device.DeviceID,
				CurrentAuthToken: device.AuthToken, RotationCode: rotationCode,
				PendingAuthToken: bytes.Repeat([]byte{value}, authTokenBytes), Now: now,
			})
			results <- err
		}(byte(0x40 + index))
	}
	wait.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidRotation):
			rejected++
		default:
			t.Fatalf("unexpected rotation error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejected=%d", successes, rejected)
	}
}

func TestCredentialRotationCodeIsExactDeviceBoundAndExpires(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	otherWorkspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	register := func(name string) RegisteredDevice {
		code, _ := store.IssuePairingCode(ctx, workspace, DeviceAndroid, name, now, time.Minute)
		device, err := store.Register(ctx, Registration{
			PairingCode: code, DeviceType: DeviceAndroid, DeviceName: name,
			E2EEPublicKey: testPublicKey(), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return device
	}
	device := register("Phone A")
	otherDevice := register("Phone B")
	rotationCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, deviceReference(workspace, device.DeviceID), now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := CredentialRotation{
		WorkspaceID: workspace, DeviceID: device.DeviceID,
		CurrentAuthToken: device.AuthToken, RotationCode: rotationCode,
		PendingAuthToken: bytes.Repeat([]byte{0x61}, authTokenBytes), Now: now,
	}
	wrongDevice := base
	wrongDevice.DeviceID = otherDevice.DeviceID
	wrongDevice.CurrentAuthToken = otherDevice.AuthToken
	if _, err := store.RotateCredential(ctx, wrongDevice); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("wrong-device error = %v", err)
	}
	wrongWorkspace := base
	wrongWorkspace.WorkspaceID = otherWorkspace
	if _, err := store.RotateCredential(ctx, wrongWorkspace); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("wrong-workspace error = %v", err)
	}
	base.Now = now.Add(500 * time.Millisecond)
	if version, err := store.RotateCredential(ctx, base); err != nil || version != 2 {
		t.Fatalf("valid retry version=%d error=%v", version, err)
	}
	expiredCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, deviceReference(workspace, device.DeviceID), now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	expired := base
	expired.CurrentAuthToken = base.PendingAuthToken
	expired.PendingAuthToken = bytes.Repeat([]byte{0x62}, authTokenBytes)
	expired.RotationCode = expiredCode
	expired.Now = now.Add(time.Second)
	if _, err := store.RotateCredential(ctx, expired); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("expired error = %v", err)
	}
	if _, err := store.IssueCredentialRotationCode(
		ctx, otherWorkspace, deviceReference(workspace, device.DeviceID), now, time.Minute,
	); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("cross-workspace issue error = %v", err)
	}
	revokedCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, deviceReference(workspace, otherDevice.DeviceID), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, otherDevice.DeviceID),
		Now: now,
	}); err != nil || !revoked.Changed {
		t.Fatalf("revoke before rotation=%+v error=%v", revoked, err)
	}
	if _, err := store.RotateCredential(ctx, CredentialRotation{
		WorkspaceID: workspace, DeviceID: otherDevice.DeviceID,
		CurrentAuthToken: otherDevice.AuthToken, RotationCode: revokedCode,
		PendingAuthToken: bytes.Repeat([]byte{0x63}, authTokenBytes), Now: now,
	}); !errors.Is(err, ErrInvalidRotation) {
		t.Fatalf("revoked-device rotation error = %v", err)
	}
}

func TestOpenMigratesSchemaVersionOneWithoutChangingCredential(t *testing.T) {
	path := tempDatabasePath(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL)`,
		`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (1, 0)`,
		`CREATE TABLE workspaces (id BLOB PRIMARY KEY, created_at_ms INTEGER NOT NULL)`,
		`CREATE TABLE devices (
			workspace_id BLOB NOT NULL, id BLOB NOT NULL, device_type TEXT NOT NULL,
			device_name TEXT NOT NULL, auth_token_hash BLOB NOT NULL,
			e2ee_public_key BLOB NOT NULL, registered_at_ms INTEGER NOT NULL,
			last_online_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER,
			PRIMARY KEY(workspace_id, id))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	workspace := bytes.Repeat([]byte{1}, 16)
	device := bytes.Repeat([]byte{2}, 16)
	token := bytes.Repeat([]byte{3}, authTokenBytes)
	hash := sha256.Sum256(token)
	if _, err := db.Exec(`INSERT INTO workspaces(id, created_at_ms) VALUES (?, 0)`, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO devices(
		workspace_id, id, device_type, device_name, auth_token_hash, e2ee_public_key,
		registered_at_ms, last_online_at_ms) VALUES (?, ?, 'chrome', 'Browser', ?, ?, 0, 0)`,
		workspace, device, hash[:], testPublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, path)
	var workspaceID WorkspaceID
	var deviceID DeviceID
	copy(workspaceID[:], workspace)
	copy(deviceID[:], device)
	identity, err := store.Authenticate(context.Background(), workspaceID, deviceID, token, time.Now())
	if err != nil || identity.CredentialVersion != 1 {
		t.Fatalf("migrated authentication identity=%+v error=%v", identity, err)
	}
	var version int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 6 {
		t.Fatalf("schema version=%d error=%v", version, err)
	}
	if _, err := store.WorkspaceAuthorityPublicKey(context.Background(), workspaceID); !errors.Is(err, ErrWorkspaceAuthorityUnavailable) {
		t.Fatalf("legacy workspace authority error=%v", err)
	}
}

func TestOpenRejectsNewerSchemaVersion(t *testing.T) {
	path := tempDatabasePath(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (7, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), path); err == nil {
		store.Close()
		t.Fatal("newer schema version unexpectedly accepted")
	}
}

func TestCreateWorkspaceRejectsZeroAuthorityPublicKey(t *testing.T) {
	store := openTestStore(t, tempDatabasePath(t))
	if _, err := store.CreateWorkspace(context.Background(), membership.AuthorityPublicKey{}, time.Now()); err == nil {
		t.Fatal("zero workspace authority public key unexpectedly accepted")
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func tempDatabasePath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/admission.db"
}

func testAuthorityPublicKey() membership.AuthorityPublicKey {
	var key membership.AuthorityPublicKey
	for index := range key {
		key[index] = byte(index + 1)
	}
	return key
}

func testPublicKey() []byte {
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	return elliptic.Marshal(elliptic.P256(), x, y)
}
