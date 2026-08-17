package relay

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
)

func TestWebSocketRelaysCanonicalChromeFrameUnchanged(t *testing.T) {
	hub, server := newTestWebSocketServer(t)
	defer server.Close()
	frame := canonicalFrame(t)
	senderPeer := peerFromFrame(t, frame, 24)
	recipientPeer := peerFromFrame(t, frame, 40)
	recipient := dialTestDevice(t, server.URL, recipientPeer)
	defer recipient.Close()
	waitUntilConnected(t, hub, recipientPeer)
	sender := dialTestDevice(t, server.URL, senderPeer)
	defer sender.Close()
	waitUntilConnected(t, hub, senderPeer)

	if err := sender.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	if err := recipient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, routed, err := recipient.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("message type = %d", messageType)
	}
	if hex.EncodeToString(routed) != hex.EncodeToString(frame) {
		t.Fatal("WebSocket relay changed encrypted frame")
	}
}

func TestWebSocketHeartbeatIsAnsweredWithoutRelayRouting(t *testing.T) {
	hub, server := newTestWebSocketServer(t)
	defer server.Close()
	frame := canonicalFrame(t)
	peer := peerFromFrame(t, frame, 24)
	connection := dialTestDevice(t, server.URL, peer)
	defer connection.Close()
	waitUntilConnected(t, hub, peer)

	if err := connection.WriteMessage(websocket.BinaryMessage, heartbeatRequest[:]); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, response, err := connection.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage || string(response) != string(heartbeatResponse[:]) {
		t.Fatal("connection did not receive canonical SNH2 heartbeat response")
	}
}

func TestWebSocketRejectsOversizedMessageBeforeRouting(t *testing.T) {
	hub, server := newTestWebSocketServer(t)
	defer server.Close()
	frame := canonicalFrame(t)
	senderPeer := peerFromFrame(t, frame, 24)
	recipientPeer := peerFromFrame(t, frame, 40)
	recipient := dialTestDevice(t, server.URL, recipientPeer)
	defer recipient.Close()
	waitUntilConnected(t, hub, recipientPeer)
	sender := dialTestDevice(t, server.URL, senderPeer)
	defer sender.Close()
	waitUntilConnected(t, hub, senderPeer)

	oversized := make([]byte, envelopeframe.MaxFrameSize+1)
	if err := sender.WriteMessage(websocket.BinaryMessage, oversized); err != nil {
		t.Fatal(err)
	}
	if err := recipient.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := recipient.ReadMessage(); err == nil {
		t.Fatal("recipient unexpectedly received oversized message")
	}
}

func newTestWebSocketServer(t *testing.T) (*Hub, *httptest.Server) {
	t.Helper()
	hub := NewHub()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceBytes, deviceErr := hex.DecodeString(r.URL.Query().Get("test_device_id"))
		workspaceBytes, workspaceErr := hex.DecodeString(r.URL.Query().Get("test_workspace_id"))
		if deviceErr != nil || workspaceErr != nil || len(deviceBytes) != 16 || len(workspaceBytes) != 16 {
			http.Error(w, "invalid test peer", http.StatusBadRequest)
			return
		}
		var peer PeerIdentity
		copy(peer.DeviceID[:], deviceBytes)
		copy(peer.WorkspaceID[:], workspaceBytes)
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		_ = ServeAuthenticatedConnection(ctx, connection, peer, 1, hub)
	})
	return hub, httptest.NewServer(handler)
}

func dialTestDevice(t *testing.T, serverURL string, peer PeerIdentity) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(serverURL, "http") +
		"/?test_device_id=" + hex.EncodeToString(peer.DeviceID[:]) +
		"&test_workspace_id=" + hex.EncodeToString(peer.WorkspaceID[:])
	connection, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	readAuthenticationSuccessAck(t, connection)
	return connection
}

func readAuthenticationSuccessAck(t *testing.T, connection *websocket.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := connection.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage || string(message) != string(authenticationSuccessAck[:]) {
		t.Fatal("connection did not receive canonical SNO1 authentication acknowledgement")
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func waitUntilConnected(t *testing.T, hub *Hub, peer PeerIdentity) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !hub.IsConnected(peer) {
		if time.Now().After(deadline) {
			t.Fatal("device did not register with relay")
		}
		time.Sleep(time.Millisecond)
	}
}
