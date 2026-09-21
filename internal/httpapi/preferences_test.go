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

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
)

func TestWorkspacePreferenceHTTPStoresOpaquePayloadWithRevisionGuard(t *testing.T) {
	ctx := context.Background()
	store, err := admission.Open(ctx, t.TempDir()+"/preferences.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.UnixMilli(1_800_000_000_000)
	workspace, device := approvedPreferenceDevice(t, ctx, store, now)
	handler := newPreferenceHandler(store)
	handler.now = func() time.Time { return now }

	credentials := map[string]string{
		"workspace_id": base64.RawURLEncoding.EncodeToString(workspace[:]),
		"device_id":    base64.RawURLEncoding.EncodeToString(device.DeviceID[:]),
		"auth_token":   base64.RawURLEncoding.EncodeToString(device.AuthToken),
		"key":          "notification-shortcuts",
	}
	read := func() preferenceReadResponse {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.read(recorder, membershipRequest(t, credentials))
		if recorder.Code != http.StatusOK {
			t.Fatalf("read status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var response preferenceReadResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	write := func(expectedRevision string, payload []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := make(map[string]string, len(credentials)+2)
		for name, value := range credentials {
			request[name] = value
		}
		request["expected_revision"] = expectedRevision
		request["payload"] = base64.RawURLEncoding.EncodeToString(payload)
		recorder := httptest.NewRecorder()
		handler.write(recorder, membershipRequest(t, request))
		return recorder
	}

	// A key that was never written reports revision zero and no payload.
	if response := read(); response.Revision != "0" || response.Payload != "" {
		t.Fatalf("unread key reported %+v", response)
	}

	// The server stores opaque bytes, including ones that are not valid UTF-8.
	payload := []byte{0x00, 0xff, 0x10, 0x7f}
	created := write("0", payload)
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var createdResponse preferenceWriteResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdResponse); err != nil {
		t.Fatal(err)
	}
	if createdResponse.Revision != "1" {
		t.Fatalf("create revision=%s", createdResponse.Revision)
	}

	// Repeating the create cannot replace the value that already exists.
	if duplicate := write("0", []byte{0x09}); duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate create status=%d", duplicate.Code)
	}
	// A revision the server never stored cannot discard another device's write.
	if stale := write("7", []byte{0x09}); stale.Code != http.StatusConflict {
		t.Fatalf("stale update status=%d", stale.Code)
	}
	if response := read(); response.Revision != "1" ||
		response.Payload != base64.RawURLEncoding.EncodeToString(payload) {
		t.Fatalf("value changed after rejected writes: %+v", response)
	}

	replacement := []byte{0x01, 0x02}
	replaced := write("1", replacement)
	if replaced.Code != http.StatusOK {
		t.Fatalf("replace status=%d body=%s", replaced.Code, replaced.Body.String())
	}
	if response := read(); response.Revision != "2" ||
		response.Payload != base64.RawURLEncoding.EncodeToString(replacement) {
		t.Fatalf("replaced value=%+v", response)
	}

	// An unauthenticated credential reaches nothing, even with the right key.
	denied := make(map[string]string, len(credentials))
	for name, value := range credentials {
		denied[name] = value
	}
	denied["auth_token"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	recorder := httptest.NewRecorder()
	handler.read(recorder, membershipRequest(t, denied))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated read status=%d", recorder.Code)
	}
}

func TestWorkspacePreferenceRejectsMalformedRevisionsAndKeys(t *testing.T) {
	ctx := context.Background()
	store, err := admission.Open(ctx, t.TempDir()+"/preferences.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.UnixMilli(1_800_000_000_000)
	workspace, device := approvedPreferenceDevice(t, ctx, store, now)
	handler := newPreferenceHandler(store)
	handler.now = func() time.Time { return now }

	body := func(key string, expectedRevision string) map[string]string {
		return map[string]string{
			"workspace_id":      base64.RawURLEncoding.EncodeToString(workspace[:]),
			"device_id":         base64.RawURLEncoding.EncodeToString(device.DeviceID[:]),
			"auth_token":        base64.RawURLEncoding.EncodeToString(device.AuthToken),
			"key":               key,
			"payload":           base64.RawURLEncoding.EncodeToString([]byte{0x2a}),
			"expected_revision": expectedRevision,
		}
	}
	for _, expectedRevision := range []string{"", "01", " 1", "-1", "1.0", "9223372036854775808"} {
		recorder := httptest.NewRecorder()
		handler.write(recorder, membershipRequest(t, body("notification-shortcuts", expectedRevision)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("revision %q status=%d", expectedRevision, recorder.Code)
		}
	}
	for _, key := range []string{"", "notification shortcuts", "短"} {
		recorder := httptest.NewRecorder()
		handler.write(recorder, membershipRequest(t, body(key, "0")))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("key %q status=%d", key, recorder.Code)
		}
	}
}

// approvedPreferenceDevice drives one Chrome device through pending
// registration, identity proof, and administrator approval so the preference
// endpoints can be exercised with a real workspace credential.
func approvedPreferenceDevice(
	t *testing.T,
	ctx context.Context,
	store *admission.Store,
	now time.Time,
) (admission.WorkspaceID, admission.RegisteredDevice) {
	t.Helper()
	authorityPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	t.Cleanup(func() { clear(authorityPrivate) })
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
	digest := bytes.Repeat([]byte{0x91}, sha256.Size)
	secret := bytes.Repeat([]byte{0x92}, sha256.Size)
	device, err := store.RegisterPending(ctx, admission.Registration{
		PairingCode: code, DeviceType: admission.DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: preferenceTestPublicKey(), Now: now,
	}, func(admission.WorkspaceID, admission.DeviceID) (admission.PendingChallenge, error) {
		return admission.PendingChallenge{
			Digest: digest, Secret: secret, ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePendingIdentityProof(ctx, admission.PendingIdentityProof{
		WorkspaceID: device.WorkspaceID, DeviceID: device.DeviceID, AuthToken: device.AuthToken,
		ChallengeDigest: digest, ChallengeSecret: secret, Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ListPendingDevices(ctx, workspace)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending devices=%+v error=%v", pending, err)
	}
	if _, err := store.ApprovePendingMembership(ctx, admission.ApprovePendingDevice{
		WorkspaceID: workspace, DeviceReference: pending[0].Reference,
		Roles:               []membershipv1.DeviceRole{membershipv1.DeviceRole_DEVICE_ROLE_RECEIVE_NOTIFICATIONS},
		AuthorityPrivateKey: authorityPrivate, Now: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	return workspace, device
}

func preferenceTestPublicKey() []byte {
	privateScalar := make([]byte, 32)
	privateScalar[31] = 3
	x, y := elliptic.P256().ScalarBaseMult(privateScalar)
	return elliptic.Marshal(elliptic.P256(), x, y)
}
