package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
	) error {
		expected, ok := tokens[peer]
		if !ok || !bytes.Equal(expected, token) {
			return errors.New("unauthorized")
		}
		return nil
	})
	hub := NewHub()
	handler, err := NewAuthenticatedWebSocketHandler(hub, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	recipient := dialAuthenticatedDevice(t, server.URL, recipientPeer, recipientToken)
	defer recipient.Close()
	waitUntilConnected(t, hub, recipientPeer)
	sender := dialAuthenticatedDevice(t, server.URL, senderPeer, senderToken)
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

func TestAuthenticatedHandlerRejectsWrongTokenAndWebOrigin(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	hub := NewHub()
	handler, err := NewAuthenticatedWebSocketHandler(hub, ConnectionAuthenticatorFunc(func(
		context.Context, PeerIdentity, []byte, time.Time,
	) error {
		return errors.New("unauthorized")
	}))
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

func TestAuthenticationAttemptLimiterIgnoresForwardedAddresses(t *testing.T) {
	limiter := newAuthAttemptLimiter()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < authAttemptsPerMinute; i++ {
		request := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
		request.RemoteAddr = "192.0.2.20:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		if !limiter.allow(request, now) {
			t.Fatalf("attempt %d unexpectedly rejected", i+1)
		}
	}
	blocked := httptest.NewRequest(http.MethodGet, "/v1/relay", nil)
	blocked.RemoteAddr = "192.0.2.20:9999"
	if limiter.allow(blocked, now) {
		t.Fatal("excess authentication attempt accepted")
	}
	if !limiter.allow(blocked, now.Add(time.Minute)) {
		t.Fatal("authentication attempt window did not reset")
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
