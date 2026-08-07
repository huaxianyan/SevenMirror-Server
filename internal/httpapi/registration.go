package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

const maxRegistrationBody = 4096

type deviceRegistrar interface {
	Register(context.Context, admission.Registration) (admission.RegisteredDevice, error)
}

type registrationHandler struct {
	registrar deviceRegistrar
	now       func() time.Time
	limiter   *registrationRateLimiter
}

type registrationRequest struct {
	PairingCode   string `json:"pairing_code"`
	DeviceType    string `json:"device_type"`
	DeviceName    string `json:"device_name"`
	E2EEPublicKey string `json:"e2ee_public_key"`
}

type registrationResponse struct {
	WorkspaceID string `json:"workspace_id"`
	DeviceID    string `json:"device_id"`
	AuthToken   string `json:"auth_token"`
}

func newRegistrationHandler(store *admission.Store) http.Handler {
	return &registrationHandler{
		registrar: store,
		now:       time.Now,
		limiter:   newRegistrationRateLimiter(),
	}
}

func (h *registrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	now := h.now()
	if h.limiter != nil && !h.limiter.allow(r, now) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many registration attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRegistrationBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request registrationRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(request.E2EEPublicKey)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	registered, err := h.registrar.Register(r.Context(), admission.Registration{
		PairingCode: request.PairingCode, DeviceType: admission.DeviceType(request.DeviceType),
		DeviceName: request.DeviceName, E2EEPublicKey: publicKey, Now: now,
	})
	if err != nil {
		if errors.Is(err, admission.ErrInvalidRegistration) {
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}
		if errors.Is(err, admission.ErrInvalidPairingCode) {
			http.Error(w, "registration denied", http.StatusForbidden)
			return
		}
		// Validation details are safe but intentionally collapsed so pairing attempts
		// cannot distinguish existing workspaces or code constraints.
		http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registrationResponse{
		WorkspaceID: encodeID(registered.WorkspaceID[:]),
		DeviceID:    encodeID(registered.DeviceID[:]),
		AuthToken:   base64.RawURLEncoding.EncodeToString(registered.AuthToken),
	})
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func encodeID(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
