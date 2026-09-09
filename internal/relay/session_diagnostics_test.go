package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

func TestReconnectReportsOccupiedSessionWhileOriginalConnectionStillWorks(t *testing.T) {
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
	var log bytes.Buffer
	handler.Logger = slog.New(slog.NewJSONHandler(&log, nil))
	server := httptest.NewServer(handler)
	defer server.Close()
	original := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer original.Close()

	replacement := dialAuthenticatedDevice(t, server.URL, peer, token)
	defer replacement.Close()
	if err := replacement.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := replacement.ReadMessage(); err == nil {
		t.Fatal("second connection unexpectedly received authentication success")
	}
	// The handler writes the diagnostic before closing this rejected socket.
	var record map[string]any
	if err := json.Unmarshal(log.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["reason"] != "already_connected" {
		t.Fatalf("session outcome = %v", record["reason"])
	}
	// This allowlist is the diagnostic privacy boundary, not a log-text assertion.
	for key := range record {
		switch key {
		case "time", "level", "msg", "reason", "duration_ms":
		default:
			t.Fatalf("unexpected diagnostic field %q", key)
		}
	}
	if duration, ok := record["duration_ms"].(float64); !ok || duration < 0 {
		t.Fatal("missing session duration")
	}

	if err := original.WriteMessage(websocket.BinaryMessage, []byte{'S', 'N', 'H', '1'}); err != nil {
		t.Fatal(err)
	}
	if err := original.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	kind, response, err := original.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(response, []byte{'S', 'N', 'H', '2'}) {
		t.Fatalf("original connection heartbeat failed: %v", err)
	}
}

func TestSessionErrorsProduceOnlyBoundedOperatorCategories(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "completed"},
		{fmt.Errorf("wrapped: %w", ErrAlreadyConnected), "already_connected"},
		{ErrDeviceDisconnected, "authorization_revoked"},
		{context.Canceled, "canceled"},
		{&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, "timeout"},
		{io.EOF, "peer_closed"},
		{&websocket.CloseError{Code: 1000, Text: "private-diagnostic-canary"}, "peer_closed"},
		{errors.New("private-diagnostic-canary"), "transport_error"},
	}
	for _, test := range cases {
		if got := relaySessionEndReason(test.err); got != test.want {
			t.Errorf("category = %q, want %q", got, test.want)
		}
	}
}
