package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"filippo.io/hpke"
	hpkeecdh "filippo.io/hpke/crypto/ecdh"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

func TestMembershipHTTPRegistersProofsAndRetrievesApprovedRoster(t *testing.T) {
	ctx := context.Background()
	store, err := admission.Open(ctx, t.TempDir()+"/membership.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.UnixMilli(1_800_000_000_000)
	authorityPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	defer clear(authorityPrivate)
	var authorityPublic membership.AuthorityPublicKey
	copy(authorityPublic[:], authorityPrivate.Public().(ed25519.PublicKey))
	workspace, err := store.CreateWorkspace(ctx, authorityPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, admission.DeviceChrome, "Browser", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	privateScalar := make([]byte, 32)
	privateScalar[31] = 2
	x, y := elliptic.P256().ScalarBaseMult(privateScalar)
	identityPublic := elliptic.Marshal(elliptic.P256(), x, y)
	handler := newMembershipHandler(store)
	handler.now = func() time.Time { return now }

	register := httptest.NewRecorder()
	handler.register(register, membershipRequest(t, map[string]string{
		"pairing_code": code, "device_type": "chrome", "device_name": "Browser",
		"e2ee_public_key": base64.RawURLEncoding.EncodeToString(identityPublic),
	}))
	if register.Code != http.StatusCreated {
		t.Fatalf("registration status=%d body=%s", register.Code, register.Body.String())
	}
	var registration membershipRegistrationResponse
	if err := json.Unmarshal(register.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	workspaceBytes, _ := base64.RawURLEncoding.DecodeString(registration.WorkspaceID)
	deviceBytes, _ := base64.RawURLEncoding.DecodeString(registration.DeviceID)
	identityKeyID := membershipIdentityKeyID(identityPublic)
	info, err := membershipcodec.PossessionHPKEInfo(workspaceBytes, deviceBytes, identityKeyID)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := hpke.DHKEM(hpkeecdh.P256()).NewPrivateKey(privateScalar)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := base64.RawURLEncoding.DecodeString(registration.ChallengeEnc)
	ciphertext, _ := base64.RawURLEncoding.DecodeString(registration.ChallengeCiphertext)
	recipient, err := hpke.NewRecipient(enc, privateKey, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	challenge, err := membershipcodec.DecodeIdentityPossessionChallenge(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := membershipcodec.ChallengeDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, err := membershipcodec.EncodePendingIdentityProof(&membershipv1.PendingIdentityProof{
		ProtocolVersion: membershipcodec.ProtocolVersion, WorkspaceId: workspaceBytes,
		DeviceId: deviceBytes, IdentityKeyId: identityKeyID,
		ChallengeDigest: digest[:], ChallengeSecret: challenge.GetChallengeSecret(),
	})
	if err != nil {
		t.Fatal(err)
	}
	prove := httptest.NewRecorder()
	handler.prove(prove, membershipRequest(t, map[string]string{
		"workspace_id": registration.WorkspaceID, "device_id": registration.DeviceID,
		"auth_token": registration.AuthToken,
		"proof":      base64.RawURLEncoding.EncodeToString(proofBytes),
	}))
	if prove.Code != http.StatusOK {
		t.Fatalf("proof status=%d body=%s", prove.Code, prove.Body.String())
	}

	var workspaceID admission.WorkspaceID
	copy(workspaceID[:], workspaceBytes)
	pending, err := store.ListPendingDevices(ctx, workspaceID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending devices=%+v error=%v", pending, err)
	}
	approved, err := store.ApprovePendingMembership(ctx, admission.ApprovePendingDevice{
		WorkspaceID: workspaceID, DeviceReference: pending[0].Reference,
		Roles:               []membershipv1.DeviceRole{membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS},
		AuthorityPrivateKey: authorityPrivate, Now: now.Add(time.Minute),
	})
	if err != nil || approved.RosterEpoch != 1 {
		t.Fatalf("approval=%+v error=%v", approved, err)
	}
	state := httptest.NewRecorder()
	handler.state(state, membershipRequest(t, map[string]string{
		"workspace_id": registration.WorkspaceID, "device_id": registration.DeviceID,
		"auth_token": registration.AuthToken, "after_roster_epoch": "0",
	}))
	if state.Code != http.StatusOK {
		t.Fatalf("state status=%d body=%s", state.Code, state.Body.String())
	}
	var response membershipStateResponse
	if err := json.Unmarshal(state.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.State != "approved" || response.LatestRosterEpoch != "1" ||
		response.SignedCertificate == "" || len(response.Rosters) != 1 {
		t.Fatalf("unexpected membership state: %+v", response)
	}
	certificateBytes, _ := base64.RawURLEncoding.DecodeString(response.SignedCertificate)
	rosterBytes, _ := base64.RawURLEncoding.DecodeString(response.Rosters[0])
	if _, err := membershipcodec.DecodeSignedDeviceCertificate(certificateBytes, authorityPublic[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := membershipcodec.DecodeSignedWorkspaceRoster(rosterBytes, authorityPublic[:]); err != nil {
		t.Fatal(err)
	}
}

func membershipRequest(t *testing.T, value any) *http.Request {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.test/v1/membership", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func membershipIdentityKeyID(publicKey []byte) []byte {
	digest := sha256.Sum256(publicKey)
	return digest[:]
}
