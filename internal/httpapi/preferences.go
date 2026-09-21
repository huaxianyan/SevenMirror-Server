package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

// A request carries one preference payload as canonical unpadded base64url, so
// the encoded envelope needs roughly four thirds of the raw payload bound plus
// the identifier fields and JSON syntax.
const maxPreferenceBody = 512 * 1024

type preferenceReadRequest struct {
	WorkspaceID string `json:"workspace_id"`
	DeviceID    string `json:"device_id"`
	AuthToken   string `json:"auth_token"`
	Key         string `json:"key"`
}

type preferenceWriteRequest struct {
	WorkspaceID      string `json:"workspace_id"`
	DeviceID         string `json:"device_id"`
	AuthToken        string `json:"auth_token"`
	Key              string `json:"key"`
	ExpectedRevision string `json:"expected_revision"`
	Payload          string `json:"payload"`
}

// preferenceReadResponse reports revision zero with an absent payload when the
// key has never been written, so a client can tell "nothing stored yet" from a
// stored value it failed to decrypt.
type preferenceReadResponse struct {
	Revision    string `json:"revision"`
	Payload     string `json:"payload"`
	UpdatedAtMS string `json:"updated_at_ms"`
}

type preferenceWriteResponse struct {
	Revision string `json:"revision"`
}

type preferenceHandler struct {
	store *admission.Store
	now   func() time.Time
}

func newPreferenceHandler(store *admission.Store) *preferenceHandler {
	return &preferenceHandler{store: store, now: time.Now}
}

func (h *preferenceHandler) read(w http.ResponseWriter, r *http.Request) {
	if !beginPreferenceJSON(w, r) {
		return
	}
	var request preferenceReadRequest
	if !decodePreferenceJSON(w, r, &request) {
		return
	}
	workspaceID, ok := h.authenticate(w, r, request.WorkspaceID, request.DeviceID, request.AuthToken)
	if !ok {
		return
	}
	record, found, err := h.store.ReadWorkspacePreference(r.Context(), workspaceID, request.Key)
	if err != nil {
		if errors.Is(err, admission.ErrPreferenceKeyInvalid) {
			http.Error(w, "invalid preference key", http.StatusBadRequest)
			return
		}
		http.Error(w, "preference read unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		writePreferenceJSON(w, http.StatusOK, preferenceReadResponse{Revision: "0"})
		return
	}
	writePreferenceJSON(w, http.StatusOK, preferenceReadResponse{
		Revision:    strconv.FormatInt(record.Revision, 10),
		Payload:     base64.RawURLEncoding.EncodeToString(record.Payload),
		UpdatedAtMS: strconv.FormatInt(record.UpdatedAtMS, 10),
	})
}

func (h *preferenceHandler) write(w http.ResponseWriter, r *http.Request) {
	if !beginPreferenceJSON(w, r) {
		return
	}
	var request preferenceWriteRequest
	if !decodePreferenceJSON(w, r, &request) {
		return
	}
	workspaceID, ok := h.authenticate(w, r, request.WorkspaceID, request.DeviceID, request.AuthToken)
	if !ok {
		return
	}
	expectedRevision, okRevision := decodeCanonicalRevision(request.ExpectedRevision)
	if !okRevision {
		http.Error(w, "invalid preference revision", http.StatusBadRequest)
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(request.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != request.Payload {
		http.Error(w, "invalid preference payload", http.StatusBadRequest)
		return
	}
	defer clear(payload)
	revision, err := h.store.WriteWorkspacePreference(
		r.Context(), workspaceID, request.Key, expectedRevision, payload, h.now())
	switch {
	case err == nil:
		writePreferenceJSON(w, http.StatusOK, preferenceWriteResponse{
			Revision: strconv.FormatInt(revision, 10),
		})
	case errors.Is(err, admission.ErrPreferenceRevisionConflict):
		http.Error(w, "preference revision conflict", http.StatusConflict)
	case errors.Is(err, admission.ErrPreferenceKeyInvalid):
		http.Error(w, "invalid preference key", http.StatusBadRequest)
	case errors.Is(err, admission.ErrPreferencePayloadInvalid):
		http.Error(w, "invalid preference payload", http.StatusBadRequest)
	default:
		http.Error(w, "preference write unavailable", http.StatusServiceUnavailable)
	}
}

// authenticate resolves the workspace from the request credentials. Preferences
// are workspace-scoped, so any approved device of the workspace may read and
// write them; the server never inspects the stored value itself.
func (h *preferenceHandler) authenticate(
	w http.ResponseWriter,
	r *http.Request,
	workspaceValue string,
	deviceValue string,
	tokenValue string,
) (admission.WorkspaceID, bool) {
	workspaceBytes, okWorkspace := decodeCanonicalBase64URL(workspaceValue, 16)
	deviceBytes, okDevice := decodeCanonicalBase64URL(deviceValue, 16)
	token, okToken := decodeCanonicalBase64URL(tokenValue, 32)
	if !okWorkspace || !okDevice || !okToken {
		http.Error(w, "preference access denied", http.StatusForbidden)
		return admission.WorkspaceID{}, false
	}
	defer clear(token)
	var workspaceID admission.WorkspaceID
	var deviceID admission.DeviceID
	copy(workspaceID[:], workspaceBytes)
	copy(deviceID[:], deviceBytes)
	if _, err := h.store.Authenticate(r.Context(), workspaceID, deviceID, token, h.now()); err != nil {
		http.Error(w, "preference access denied", http.StatusForbidden)
		return admission.WorkspaceID{}, false
	}
	return workspaceID, true
}

func beginPreferenceJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

func decodePreferenceJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPreferenceBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureJSONEnd(decoder) != nil {
		http.Error(w, "invalid preference request", http.StatusBadRequest)
		return false
	}
	return true
}

func writePreferenceJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// decodeCanonicalRevision accepts a non-negative decimal revision without a
// sign, leading zero, or surrounding whitespace, so two encodings of the same
// number cannot reach the store.
func decodeCanonicalRevision(value string) (int64, bool) {
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 0 || strconv.FormatInt(revision, 10) != value {
		return 0, false
	}
	return revision, true
}
