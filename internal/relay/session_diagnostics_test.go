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

type sessionLogRecords chan []byte

func (records sessionLogRecords) Write(encoded []byte) (int, error) {
	records <- bytes.Clone(encoded)
	return len(encoded), nil
}

func TestAuthenticatedReplacementTakesOverTheSlotAndRetiresTheOriginal(t *testing.T) {
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
	logs := make(sessionLogRecords, 2)
	handler.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	server := httptest.NewServer(handler)
	defer server.Close()
	original := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer original.Close()

	// The replacement proves the same credential, so it must not stay locked out
	// behind a stale socket that the relay has not noticed yet.
	replacement := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer replacement.Close()

	// The retired connection learns it was replaced through an ordinary close.
	// A policy close would tell the client its membership changed.
	if err := original.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = original.ReadMessage()
	var closeError *websocket.CloseError
	if !errors.As(err, &closeError) || closeError.Code != websocket.CloseNormalClosure {
		t.Fatalf("retired connection error = %v", err)
	}
	if !hub.IsConnected(peer) {
		t.Fatal("replacement did not register")
	}
	if err := replacement.WriteMessage(websocket.BinaryMessage, []byte{'S', 'N', 'H', '1'}); err != nil {
		t.Fatal(err)
	}
	if err := replacement.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	kind, response, err := replacement.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(response, []byte{'S', 'N', 'H', '2'}) {
		t.Fatalf("replacement heartbeat failed: %v", err)
	}
	// Synchronize with the logger explicitly; a socket close is not a Go memory barrier.
	var record map[string]any
	select {
	case encoded := <-logs:
		if err := json.Unmarshal(encoded, &record); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retirement diagnostic was not received")
	}
	if record["reason"] != "superseded" {
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
}

func TestSessionErrorsProduceOnlyBoundedOperatorCategories(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "completed"},
		{fmt.Errorf("wrapped: %w", ErrAlreadyConnected), "already_connected"},
		{fmt.Errorf("wrapped: %w", ErrStaleCredential), "stale_credential"},
		{fmt.Errorf("wrapped: %w", ErrHandoverTimeout), "handover_timeout"},
		{fmt.Errorf("wrapped: %w", ErrSessionSuperseded), "superseded"},
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
