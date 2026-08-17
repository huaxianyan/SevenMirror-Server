package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

type credentialRotatorFunc func(context.Context, admission.CredentialRotation) (int64, error)

func (f credentialRotatorFunc) RotateCredential(
	ctx context.Context,
	input admission.CredentialRotation,
) (int64, error) {
	return f(ctx, input)
}

func TestCredentialRotationHandlerAcceptsOnlyExactCanonicalRequest(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	workspace := bytes.Repeat([]byte{1}, 16)
	device := bytes.Repeat([]byte{2}, 16)
	current := bytes.Repeat([]byte{3}, 32)
	pending := bytes.Repeat([]byte{4}, 32)
	rotationCode := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 24))
	called := 0
	handler := &credentialRotationHandler{
		rotator: credentialRotatorFunc(func(_ context.Context, input admission.CredentialRotation) (int64, error) {
			called++
			if !bytes.Equal(input.WorkspaceID[:], workspace) || !bytes.Equal(input.DeviceID[:], device) ||
				!bytes.Equal(input.CurrentAuthToken, current) || !bytes.Equal(input.PendingAuthToken, pending) ||
				input.RotationCode != rotationCode || !input.Now.Equal(now) {
				t.Fatalf("unexpected rotation input")
			}
			return 2, nil
		}),
		now: func() time.Time { return now },
	}
	body := rotationJSON(workspace, device, current, rotationCode, pending)
	request := httptest.NewRequest(http.MethodPost, "/v1/devices/rotate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"status\":\"rotated\"}\n" || called != 1 {
		t.Fatalf("status=%d body=%q called=%d", response.Code, response.Body.String(), called)
	}

	for name, invalidBody := range map[string]string{
		"unknown field": strings.TrimSuffix(body, "}") + `,"extra":true}`,
		"trailing JSON": body + `{}`,
		"padded ID":     strings.Replace(body, encodeID(workspace), encodeID(workspace)+"=", 1),
		"short token":   strings.Replace(body, encodeID(current), encodeID(current[:31]), 1),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/devices/rotate", strings.NewReader(invalidBody))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestCredentialRotationHandlerCollapsesProofAndInternalErrors(t *testing.T) {
	validBody := rotationJSON(
		bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 32),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 24)), bytes.Repeat([]byte{5}, 32))
	for name, testCase := range map[string]struct {
		err  error
		want int
	}{
		"proof":    {admission.ErrInvalidRotation, http.StatusForbidden},
		"internal": {errors.New("database unavailable"), http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			handler := &credentialRotationHandler{
				rotator: credentialRotatorFunc(func(context.Context, admission.CredentialRotation) (int64, error) {
					return 0, testCase.err
				}),
				now: time.Now,
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/devices/rotate", strings.NewReader(validBody))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if name == "internal" && strings.Contains(response.Body.String(), testCase.err.Error()) {
				t.Fatal("internal rotation error leaked")
			}
		})
	}
}

func TestCredentialRotationHandlerRejectsMethodAndNonExactContentType(t *testing.T) {
	handler := &credentialRotationHandler{
		rotator: credentialRotatorFunc(func(context.Context, admission.CredentialRotation) (int64, error) {
			t.Fatal("rotator called")
			return 0, nil
		}),
		now: time.Now,
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/devices/rotate", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/devices/rotate", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content-type status=%d", response.Code)
	}
}

func rotationJSON(workspace, device, current []byte, code string, pending []byte) string {
	return `{"workspace_id":"` + encodeID(workspace) +
		`","device_id":"` + encodeID(device) +
		`","current_auth_token":"` + encodeID(current) +
		`","rotation_code":"` + code +
		`","pending_auth_token":"` + encodeID(pending) + `"}`
}
