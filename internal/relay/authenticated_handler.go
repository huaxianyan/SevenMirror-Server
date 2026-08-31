package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

const authFrameSize = 68

var authMagic = [4]byte{'S', 'N', 'A', '1'}

type ConnectionAuthenticator interface {
	AuthenticateConnection(context.Context, PeerIdentity, []byte, time.Time) (int64, error)
}

type ConnectionActivityRecorder interface {
	RecordConnectionActivity(context.Context, PeerIdentity, time.Time) error
}

type ConnectionAuthenticatorFunc func(context.Context, PeerIdentity, []byte, time.Time) (int64, error)

func (f ConnectionAuthenticatorFunc) AuthenticateConnection(
	ctx context.Context,
	peer PeerIdentity,
	token []byte,
	now time.Time,
) (int64, error) {
	return f(ctx, peer, token, now)
}

type AuthenticatedWebSocketHandler struct {
	hub              *Hub
	authenticator    ConnectionAuthenticator
	activityRecorder ConnectionActivityRecorder
	now              func() time.Time
	attempts         *authAttemptLimiter
	authSlots        chan struct{}
	authTimeout      time.Duration
	upgrader         websocket.Upgrader
}

func NewAuthenticatedWebSocketHandler(
	hub *Hub,
	authenticator ConnectionAuthenticator,
	clientAddresses clientaddress.Resolver,
	configuredLimits ...AuthenticationLimits,
) (*AuthenticatedWebSocketHandler, error) {
	if hub == nil || authenticator == nil {
		return nil, errors.New("hub and authenticator are required")
	}
	limits := DefaultAuthenticationLimits()
	if len(configuredLimits) > 1 {
		return nil, errors.New("at most one relay authentication limit set is allowed")
	}
	if len(configuredLimits) == 1 {
		limits = configuredLimits[0]
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	activityRecorder, _ := authenticator.(ConnectionActivityRecorder)
	return &AuthenticatedWebSocketHandler{
		hub:              hub,
		authenticator:    authenticator,
		activityRecorder: activityRecorder,
		now:              time.Now,
		attempts:         newAuthAttemptLimiter(clientAddresses, limits),
		authSlots:        make(chan struct{}, limits.MaxConcurrent),
		authTimeout:      limits.FrameTimeout,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     permittedWebSocketOrigin,
		},
	}, nil
}

func (h *AuthenticatedWebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	allowed, err := h.attempts.allow(r, h.now())
	if err != nil {
		http.Error(w, "invalid client address", http.StatusBadRequest)
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many connection attempts", http.StatusTooManyRequests)
		return
	}
	authSlotHeld := false
	select {
	case h.authSlots <- struct{}{}:
		authSlotHeld = true
		defer func() {
			if authSlotHeld {
				<-h.authSlots
			}
		}()
	default:
		http.Error(w, "authentication capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	connection, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()

	peer, token, err := readAuthenticationFrame(connection, h.authTimeout)
	if err != nil {
		writeGenericClose(connection)
		return
	}
	defer clear(token)
	credentialVersion, err := h.authenticator.AuthenticateConnection(r.Context(), peer, token, h.now())
	if err != nil || credentialVersion < 1 {
		writeGenericClose(connection)
		return
	}
	<-h.authSlots
	authSlotHeld = false
	_ = connection.SetReadDeadline(time.Time{})
	_ = ServeAuthenticatedConnection(
		r.Context(), connection, peer, credentialVersion, h.hub, h.activityRecorder)
}

func EncodeAuthenticationFrame(peer PeerIdentity, token []byte) ([]byte, error) {
	if len(token) != 32 {
		return nil, errors.New("authentication token must be 32 bytes")
	}
	frame := make([]byte, authFrameSize)
	copy(frame[0:4], authMagic[:])
	copy(frame[4:20], peer.WorkspaceID[:])
	copy(frame[20:36], peer.DeviceID[:])
	copy(frame[36:68], token)
	return frame, nil
}

func readAuthenticationFrame(
	connection *websocket.Conn,
	timeout time.Duration,
) (PeerIdentity, []byte, error) {
	connection.SetReadLimit(authFrameSize)
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return PeerIdentity{}, nil, err
	}
	messageType, reader, err := connection.NextReader()
	if err != nil {
		return PeerIdentity{}, nil, err
	}
	if messageType != websocket.BinaryMessage {
		return PeerIdentity{}, nil, errors.New("authentication frame must be binary")
	}
	frame, err := io.ReadAll(io.LimitReader(reader, authFrameSize+1))
	if err != nil || len(frame) != authFrameSize {
		return PeerIdentity{}, nil, errors.New("invalid authentication frame")
	}
	if string(frame[0:4]) != string(authMagic[:]) {
		return PeerIdentity{}, nil, errors.New("invalid authentication frame")
	}
	var peer PeerIdentity
	copy(peer.WorkspaceID[:], frame[4:20])
	copy(peer.DeviceID[:], frame[20:36])
	if peer.WorkspaceID == (WorkspaceID{}) || peer.DeviceID == (DeviceID{}) {
		return PeerIdentity{}, nil, errors.New("invalid authentication frame")
	}
	// Return the frame-backed slice so the caller's clear(token) also wipes the
	// only application buffer containing the raw credential.
	return peer, frame[36:68], nil
}

func permittedWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Native Android and non-browser test clients.
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "chrome-extension" && parsed.Host != ""
}

func writeGenericClose(connection *websocket.Conn) {
	_ = connection.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authentication failed"),
		time.Now().Add(time.Second),
	)
}
