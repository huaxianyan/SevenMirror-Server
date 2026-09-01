package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

func TestAuthenticationFrameMatchesCanonicalVector(t *testing.T) {
	content, err := os.ReadFile("../../protocol/test-vectors/device-auth-frame-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		WorkspaceID string `json:"workspaceId"`
		DeviceID    string `json:"deviceId"`
		AuthToken   string `json:"authToken"`
		FrameHex    string `json:"frameHex"`
		SuccessAck  string `json:"successAckHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	workspace, _ := hex.DecodeString(vector.WorkspaceID)
	device, _ := hex.DecodeString(vector.DeviceID)
	token, _ := hex.DecodeString(vector.AuthToken)
	var peer PeerIdentity
	copy(peer.WorkspaceID[:], workspace)
	copy(peer.DeviceID[:], device)
	frame, err := EncodeAuthenticationFrame(peer, token)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(frame) != vector.FrameHex {
		t.Fatal("authentication frame does not match canonical vector")
	}
	if hex.EncodeToString(authenticationSuccessAck[:]) != vector.SuccessAck {
		t.Fatal("authentication success acknowledgement does not match canonical vector")
	}
}

func TestAuthenticatedHandlerRoutesOnlyAfterBinaryCredentialFrame(t *testing.T) {
	frame := canonicalFrame(t)
	senderPeer := peerFromFrame(t, frame, 24)
	recipientPeer := peerFromFrame(t, frame, 40)
	senderToken := bytes.Repeat([]byte{0x51}, 32)
	recipientToken := bytes.Repeat([]byte{0x52}, 32)
	tokens := map[PeerIdentity][]byte{senderPeer: senderToken, recipientPeer: recipientToken}
	authenticator := ConnectionAuthenticatorFunc(func(
		_ context.Context, peer PeerIdentity, token []byte, _ time.Time,
	) (int64, error) {
		expected, ok := tokens[peer]
		if !ok || !bytes.Equal(expected, token) {
			return 0, errors.New("unauthorized")
		}
		return 1, nil
	})
	hub := newTestHub(t)
	handler, err := NewAuthenticatedWebSocketHandler(
		hub, authenticator, clientaddress.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	recipient := dialAndAuthenticateDevice(t, server.URL, recipientPeer, recipientToken)
	defer recipient.Close()
	waitUntilConnected(t, hub, recipientPeer)
	sender := dialAndAuthenticateDevice(t, server.URL, senderPeer, senderToken)
	defer sender.Close()
	waitUntilConnected(t, hub, senderPeer)

	if err := sender.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	if err := recipient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, received, err := recipient.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage || !bytes.Equal(received, frame) {
		t.Fatal("authenticated relay did not preserve ciphertext")
	}
}

func TestAuthenticatedHandlerClosesActiveRevokedSession(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	token := bytes.Repeat([]byte{3}, 32)
	hub := newTestHub(t)
	handler, err := NewAuthenticatedWebSocketHandler(hub, ConnectionAuthenticatorFunc(func(
		_ context.Context, candidate PeerIdentity, received []byte, _ time.Time,
	) (int64, error) {
		if candidate != peer || !bytes.Equal(received, token) {
			return 0, errors.New("unauthorized")
		}
		return 1, nil
	}), clientaddress.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	connection := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer connection.Close()
	waitUntilConnected(t, hub, peer)
	if !hub.Disconnect(peer) {
		t.Fatal("active peer was not disconnected")
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = connection.ReadMessage()
	var closeError *websocket.CloseError
	if !errors.As(err, &closeError) || closeError.Code != websocket.ClosePolicyViolation {
		t.Fatalf("revoked connection error = %v", err)
	}
	if hub.IsConnected(peer) {
		t.Fatal("revoked peer remained registered")
	}
}

func TestAuthenticatedHandlerRejectsWrongTokenAndWebOrigin(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	hub := newTestHub(t)
	handler, err := NewAuthenticatedWebSocketHandler(hub, ConnectionAuthenticatorFunc(func(
		context.Context, PeerIdentity, []byte, time.Time,
	) (int64, error) {
		return 0, errors.New("unauthorized")
	}), clientaddress.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	connection := dialAuthenticatedDevice(t, server.URL, peer, bytes.Repeat([]byte{3}, 32))
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("unauthorized connection remained open")
	}
	if hub.IsConnected(peer) {
		t.Fatal("unauthorized peer registered with hub")
	}

	headers := http.Header{"Origin": []string{"https://attacker.example"}}
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	if rejected, response, err := websocket.DefaultDialer.Dial(url, headers); err == nil {
		rejected.Close()
		t.Fatal("web origin unexpectedly accepted")
	} else if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("web origin status = %v, error = %v", response, err)
	}
}

func TestAuthenticationAttemptLimiterUsesForwardedAddressOnlyForTrustedProxy(t *testing.T) {
	limits := DefaultAuthenticationLimits()
	limiter := newAuthAttemptLimiter(clientaddress.New(nil), limits)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < limits.AttemptsPerMinute; i++ {
		request := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
		request.RemoteAddr = "192.0.2.20:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		if allowed, err := limiter.allow(request, now); err != nil || !allowed {
			t.Fatalf("attempt %d allowed=%v error=%v", i+1, allowed, err)
		}
	}
	blocked := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
	blocked.RemoteAddr = "192.0.2.20:9999"
	if allowed, err := limiter.allow(blocked, now); err != nil || allowed {
		t.Fatalf("excess authentication attempt allowed=%v error=%v", allowed, err)
	}
	if allowed, err := limiter.allow(blocked, now.Add(time.Minute)); err != nil || !allowed {
		t.Fatalf("reset authentication attempt allowed=%v error=%v", allowed, err)
	}

	trusted := newAuthAttemptLimiter(clientaddress.New([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.20/32"),
	}), limits)
	for i := 0; i < limits.AttemptsPerMinute; i++ {
		request := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
		request.RemoteAddr = "192.0.2.20:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		if allowed, err := trusted.allow(request, now); err != nil || !allowed {
			t.Fatalf("trusted attempt %d allowed=%v error=%v", i+1, allowed, err)
		}
	}
	otherClient := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
	otherClient.RemoteAddr = "192.0.2.20:1234"
	otherClient.Header.Set("X-Forwarded-For", "198.51.100.2")
	if allowed, err := trusted.allow(otherClient, now); err != nil || !allowed {
		t.Fatalf("separate forwarded client allowed=%v error=%v", allowed, err)
	}
}

func dialAuthenticatedDevice(
	t *testing.T,
	serverURL string,
	peer PeerIdentity,
	token []byte,
) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(serverURL, "http")
	connection, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	authFrame, err := EncodeAuthenticationFrame(peer, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.WriteMessage(websocket.BinaryMessage, authFrame); err != nil {
		t.Fatal(err)
	}
	return connection
}

func dialAndAuthenticateDevice(
	t *testing.T,
	serverURL string,
	peer PeerIdentity,
	token []byte,
) *websocket.Conn {
	t.Helper()
	connection := dialAuthenticatedDevice(t, serverURL, peer, token)
	readAuthenticationSuccessAck(t, connection)
	return connection
}
