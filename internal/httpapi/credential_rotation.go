package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

const maxCredentialRotationBody = 2048

type credentialRotator interface {
	RotateCredential(context.Context, admission.CredentialRotation) (int64, error)
}

type credentialRotationHandler struct {
	rotator credentialRotator
	now     func() time.Time
	limiter *clientRateLimiter
}

type credentialRotationRequest struct {
	WorkspaceID      string `json:"workspace_id"`
	DeviceID         string `json:"device_id"`
	CurrentAuthToken string `json:"current_auth_token"`
	RotationCode     string `json:"rotation_code"`
	PendingAuthToken string `json:"pending_auth_token"`
}

func newCredentialRotationHandler(
	store *admission.Store,
	limiter *clientRateLimiter,
) http.Handler {
	return &credentialRotationHandler{rotator: store, now: time.Now, limiter: limiter}
}

func (h *credentialRotationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	now := h.now()
	if h.limiter != nil {
		allowed, err := h.limiter.allow(r, now)
		if err != nil {
			http.Error(w, "invalid client address", http.StatusBadRequest)
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many credential rotation attempts", http.StatusTooManyRequests)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCredentialRotationBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request credentialRotationRequest
	if err := decoder.Decode(&request); err != nil || ensureJSONEnd(decoder) != nil {
		http.Error(w, "invalid credential rotation request", http.StatusBadRequest)
		return
	}
	workspaceBytes, ok := decodeCanonicalBase64URL(request.WorkspaceID, len(admission.WorkspaceID{}))
	if !ok {
		http.Error(w, "invalid credential rotation request", http.StatusBadRequest)
		return
	}
	deviceBytes, ok := decodeCanonicalBase64URL(request.DeviceID, len(admission.DeviceID{}))
	if !ok {
		http.Error(w, "invalid credential rotation request", http.StatusBadRequest)
		return
	}
	currentToken, ok := decodeCanonicalBase64URL(request.CurrentAuthToken, 32)
	if !ok {
		http.Error(w, "invalid credential rotation request", http.StatusBadRequest)
		return
	}
	defer clear(currentToken)
	pendingToken, ok := decodeCanonicalBase64URL(request.PendingAuthToken, 32)
	if !ok {
		http.Error(w, "invalid credential rotation request", http.StatusBadRequest)
		return
	}
	defer clear(pendingToken)
	var workspaceID admission.WorkspaceID
	var deviceID admission.DeviceID
	copy(workspaceID[:], workspaceBytes)
	copy(deviceID[:], deviceBytes)
	_, err := h.rotator.RotateCredential(r.Context(), admission.CredentialRotation{
		WorkspaceID: workspaceID, DeviceID: deviceID,
		CurrentAuthToken: currentToken, RotationCode: request.RotationCode,
		PendingAuthToken: pendingToken, Now: now,
	})
	if err != nil {
		if errors.Is(err, admission.ErrInvalidRotation) {
			http.Error(w, "credential rotation denied", http.StatusForbidden)
			return
		}
		http.Error(w, "credential rotation unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statusResponse{Status: "rotated"})
}

func decodeCanonicalBase64URL(value string, size int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}
