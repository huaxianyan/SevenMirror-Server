package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

const maxMembershipBody = 8192

type membershipHandler struct {
	store   *admission.Store
	now     func() time.Time
	limiter *registrationRateLimiter
}

type membershipRegistrationResponse struct {
	WorkspaceID         string `json:"workspace_id"`
	DeviceID            string `json:"device_id"`
	AuthToken           string `json:"auth_token"`
	AuthorityPublicKey  string `json:"authority_public_key"`
	ChallengeEnc        string `json:"challenge_enc"`
	ChallengeCiphertext string `json:"challenge_ciphertext"`
}

type membershipProofRequest struct {
	WorkspaceID string `json:"workspace_id"`
	DeviceID    string `json:"device_id"`
	AuthToken   string `json:"auth_token"`
	Proof       string `json:"proof"`
}

type membershipStateRequest struct {
	WorkspaceID      string `json:"workspace_id"`
	DeviceID         string `json:"device_id"`
	AuthToken        string `json:"auth_token"`
	AfterRosterEpoch string `json:"after_roster_epoch"`
}

type membershipStateResponse struct {
	State                string   `json:"state"`
	AuthorityPublicKey   string   `json:"authority_public_key"`
	SignedCertificate    string   `json:"signed_certificate,omitempty"`
	AuthorityTransitions []string `json:"authority_transitions"`
	Rosters              []string `json:"rosters"`
	LatestRosterEpoch    string   `json:"latest_roster_epoch"`
}

func newMembershipHandler(store *admission.Store) *membershipHandler {
	return &membershipHandler{store: store, now: time.Now, limiter: newRegistrationRateLimiter()}
}

func (h *membershipHandler) register(w http.ResponseWriter, r *http.Request) {
	if !h.beginJSON(w, r, true) {
		return
	}
	var request registrationRequest
	if !decodeMembershipJSON(w, r, &request) {
		return
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(request.E2EEPublicKey)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	now := h.now()
	var challenge membership.IdentityChallenge
	registered, err := h.store.RegisterPending(r.Context(), admission.Registration{
		PairingCode: request.PairingCode, DeviceType: admission.DeviceType(request.DeviceType),
		DeviceName: request.DeviceName, E2EEPublicKey: publicKey, Now: now,
	}, func(workspaceID admission.WorkspaceID, deviceID admission.DeviceID) (admission.PendingChallenge, error) {
		created, createErr := membership.CreateIdentityChallenge(
			workspaceID[:], deviceID[:], publicKey, now)
		if createErr != nil {
			return admission.PendingChallenge{}, createErr
		}
		challenge = created
		return admission.PendingChallenge{Digest: created.Digest[:], Secret: created.Secret[:], ExpiresAt: created.ExpiresAt}, nil
	})
	defer clear(challenge.Secret[:])
	defer clear(challenge.CanonicalPlaintext)
	if err != nil {
		if errors.Is(err, admission.ErrInvalidRegistration) {
			http.Error(w, "invalid registration request", http.StatusBadRequest)
		} else if errors.Is(err, admission.ErrInvalidPairingCode) {
			http.Error(w, "registration denied", http.StatusForbidden)
		} else {
			http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	defer clear(registered.AuthToken)
	authorityPublicKey, err := h.store.WorkspaceAuthorityPublicKey(r.Context(), registered.WorkspaceID)
	if err != nil {
		http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
		return
	}
	writeMembershipJSON(w, http.StatusCreated, membershipRegistrationResponse{
		WorkspaceID: encodeID(registered.WorkspaceID[:]), DeviceID: encodeID(registered.DeviceID[:]),
		AuthToken:           base64.RawURLEncoding.EncodeToString(registered.AuthToken),
		AuthorityPublicKey:  base64.RawURLEncoding.EncodeToString(authorityPublicKey[:]),
		ChallengeEnc:        base64.RawURLEncoding.EncodeToString(challenge.EncapsulatedKey),
		ChallengeCiphertext: base64.RawURLEncoding.EncodeToString(challenge.Ciphertext),
	})
}

func (h *membershipHandler) prove(w http.ResponseWriter, r *http.Request) {
	if !h.beginJSON(w, r, false) {
		return
	}
	var request membershipProofRequest
	if !decodeMembershipJSON(w, r, &request) {
		return
	}
	workspaceBytes, okWorkspace := decodeCanonicalBase64URL(request.WorkspaceID, 16)
	deviceBytes, okDevice := decodeCanonicalBase64URL(request.DeviceID, 16)
	token, okToken := decodeCanonicalBase64URL(request.AuthToken, 32)
	proofBytes, err := base64.RawURLEncoding.DecodeString(request.Proof)
	if !okWorkspace || !okDevice || !okToken || err != nil ||
		base64.RawURLEncoding.EncodeToString(proofBytes) != request.Proof {
		http.Error(w, "membership proof denied", http.StatusForbidden)
		return
	}
	defer clear(token)
	defer clear(proofBytes)
	proof, err := membershipcodec.DecodePendingIdentityProof(proofBytes)
	if err != nil || !bytes.Equal(proof.GetWorkspaceId(), workspaceBytes) || !bytes.Equal(proof.GetDeviceId(), deviceBytes) {
		http.Error(w, "membership proof denied", http.StatusForbidden)
		return
	}
	var workspaceID admission.WorkspaceID
	var deviceID admission.DeviceID
	copy(workspaceID[:], workspaceBytes)
	copy(deviceID[:], deviceBytes)
	if err := h.store.CompletePendingIdentityProof(r.Context(), admission.PendingIdentityProof{
		WorkspaceID: workspaceID, DeviceID: deviceID, AuthToken: token,
		ChallengeDigest: proof.GetChallengeDigest(), ChallengeSecret: proof.GetChallengeSecret(), Now: h.now(),
	}); err != nil {
		http.Error(w, "membership proof denied", http.StatusForbidden)
		return
	}
	writeMembershipJSON(w, http.StatusOK, map[string]string{"state": "pending_approval"})
}

func (h *membershipHandler) state(w http.ResponseWriter, r *http.Request) {
	if !h.beginJSON(w, r, false) {
		return
	}
	var request membershipStateRequest
	if !decodeMembershipJSON(w, r, &request) {
		return
	}
	workspaceBytes, okWorkspace := decodeCanonicalBase64URL(request.WorkspaceID, 16)
	deviceBytes, okDevice := decodeCanonicalBase64URL(request.DeviceID, 16)
	token, okToken := decodeCanonicalBase64URL(request.AuthToken, 32)
	afterEpoch, err := strconv.ParseInt(request.AfterRosterEpoch, 10, 64)
	if !okWorkspace || !okDevice || !okToken || err != nil || afterEpoch < 0 ||
		strconv.FormatInt(afterEpoch, 10) != request.AfterRosterEpoch {
		http.Error(w, "membership state denied", http.StatusForbidden)
		return
	}
	defer clear(token)
	var workspaceID admission.WorkspaceID
	var deviceID admission.DeviceID
	copy(workspaceID[:], workspaceBytes)
	copy(deviceID[:], deviceBytes)
	view, err := h.store.ReadMembershipState(r.Context(), workspaceID, deviceID, token, afterEpoch)
	if err != nil {
		http.Error(w, "membership state denied", http.StatusForbidden)
		return
	}
	response := membershipStateResponse{State: view.State,
		AuthorityPublicKey:   base64.RawURLEncoding.EncodeToString(view.AuthorityPublicKey[:]),
		LatestRosterEpoch:    strconv.FormatInt(view.LatestRosterEpoch, 10),
		AuthorityTransitions: make([]string, len(view.AuthorityTransitions)),
		Rosters:              make([]string, len(view.Rosters))}
	if len(view.SignedCertificate) != 0 {
		response.SignedCertificate = base64.RawURLEncoding.EncodeToString(view.SignedCertificate)
	}
	for index, transition := range view.AuthorityTransitions {
		response.AuthorityTransitions[index] = base64.RawURLEncoding.EncodeToString(transition)
	}
	for index, roster := range view.Rosters {
		response.Rosters[index] = base64.RawURLEncoding.EncodeToString(roster)
	}
	writeMembershipJSON(w, http.StatusOK, response)
}

func (h *membershipHandler) beginJSON(w http.ResponseWriter, r *http.Request, rateLimited bool) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if rateLimited && h.limiter != nil && !h.limiter.allow(r, h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many registration attempts", http.StatusTooManyRequests)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

func decodeMembershipJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxMembershipBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureJSONEnd(decoder) != nil {
		http.Error(w, "invalid membership request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeMembershipJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
