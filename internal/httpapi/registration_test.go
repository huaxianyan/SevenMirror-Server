package httpapi

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

func TestPrivateRegistrationConsumesAdminIssuedCode(t *testing.T) {
	ctx := context.Background()
	store, err := admission.Open(ctx, t.TempDir()+"/registration.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.UnixMilli(1_800_000_000_000)
	workspace, err := store.CreateWorkspace(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, admission.DeviceChrome, "Browser", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler := &registrationHandler{registrar: store, now: func() time.Time { return now }}
	body := registrationJSON(t, code)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newJSONRequest(body))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var response registrationResponse
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	workspaceBytes, _ := base64.RawURLEncoding.DecodeString(response.WorkspaceID)
	deviceBytes, _ := base64.RawURLEncoding.DecodeString(response.DeviceID)
	token, _ := base64.RawURLEncoding.DecodeString(response.AuthToken)
	var registeredWorkspace admission.WorkspaceID
	var registeredDevice admission.DeviceID
	copy(registeredWorkspace[:], workspaceBytes)
	copy(registeredDevice[:], deviceBytes)
	if _, err := store.Authenticate(ctx, registeredWorkspace, registeredDevice, token, now); err != nil {
		t.Fatalf("issued credential does not authenticate: %v", err)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, newJSONRequest(body))
	if second.Code != http.StatusForbidden || second.Body.String() != "registration denied\n" {
		t.Fatalf("replay status=%d body=%q", second.Code, second.Body.String())
	}
}

func TestRegistrationRejectsUnknownFieldsAndOversizedBodies(t *testing.T) {
	store, err := admission.Open(context.Background(), t.TempDir()+"/registration.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := newRegistrationHandler(store)

	for name, body := range map[string][]byte{
		"unknown":   []byte(`{"pairing_code":"x","unexpected":true}`),
		"oversized": bytes.Repeat([]byte{'x'}, maxRegistrationBody+1),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newJSONRequest(body))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func newJSONRequest(body []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func registrationJSON(t *testing.T, code string) []byte {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	publicKey := elliptic.Marshal(elliptic.P256(), x, y)
	encoded, err := json.Marshal(registrationRequest{
		PairingCode: code, DeviceType: "chrome", DeviceName: "Browser",
		E2EEPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
