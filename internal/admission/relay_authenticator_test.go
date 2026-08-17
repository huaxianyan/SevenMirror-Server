package admission

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

func TestRegisteredCredentialAuthenticatesProductionRelayBoundary(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewRelayAuthenticator(store)
	if err != nil {
		t.Fatal(err)
	}
	hub := relay.NewHub()
	handler, err := relay.NewAuthenticatedWebSocketHandler(hub, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	peer := relay.PeerIdentity{}
	copy(peer.WorkspaceID[:], registered.WorkspaceID[:])
	copy(peer.DeviceID[:], registered.DeviceID[:])
	connection, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	authFrame, err := relay.EncodeAuthenticationFrame(peer, registered.AuthToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.WriteMessage(websocket.BinaryMessage, authFrame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !hub.IsConnected(peer) {
		if time.Now().After(deadline) {
			t.Fatal("registered credential did not establish relay identity")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDurableRevocationClosesActiveRelayAndRejectsReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewRelayAuthenticator(store)
	if err != nil {
		t.Fatal(err)
	}
	hub := relay.NewHub()
	handler, err := relay.NewAuthenticatedWebSocketHandler(hub, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	peer := relay.PeerIdentity{}
	copy(peer.WorkspaceID[:], registered.WorkspaceID[:])
	copy(peer.DeviceID[:], registered.DeviceID[:])
	monitorFinished := make(chan error, 1)
	go func() {
		monitorFinished <- relay.RunAuthorizationMonitor(ctx, hub, time.Millisecond, func(
			checkContext context.Context, candidate relay.PeerIdentity,
		) (bool, error) {
			var candidateWorkspace WorkspaceID
			var candidateDevice DeviceID
			copy(candidateWorkspace[:], candidate.WorkspaceID[:])
			copy(candidateDevice[:], candidate.DeviceID[:])
			return store.IsDeviceAuthorized(checkContext, candidateWorkspace, candidateDevice)
		})
	}()

	connection := dialRegisteredDevice(t, server.URL, peer, registered.AuthToken)
	defer connection.Close()
	if _, message, err := connection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("authentication acknowledgement = %q, error = %v", message, err)
	}
	if changed, err := store.RevokeDevice(ctx, workspace,
		deviceReference(workspace, registered.DeviceID), now.Add(time.Second)); err != nil || !changed {
		t.Fatalf("revocation changed=%v error=%v", changed, err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = connection.ReadMessage()
	var closeError *websocket.CloseError
	if !errors.As(err, &closeError) || closeError.Code != websocket.ClosePolicyViolation {
		t.Fatalf("active revoked connection error = %v", err)
	}
	if hub.IsConnected(peer) {
		t.Fatal("revoked device remained connected")
	}

	reconnect := dialRegisteredDevice(t, server.URL, peer, registered.AuthToken)
	defer reconnect.Close()
	if err := reconnect.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, message, err := reconnect.ReadMessage(); err == nil || string(message) == "SNO1" {
		t.Fatalf("revoked reconnect acknowledgement = %q, error = %v", message, err)
	}
	cancel()
	if err := <-monitorFinished; !errors.Is(err, context.Canceled) {
		t.Fatalf("monitor error = %v", err)
	}
}

func dialRegisteredDevice(
	t *testing.T,
	serverURL string,
	peer relay.PeerIdentity,
	token []byte,
) *websocket.Conn {
	t.Helper()
	connection, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(serverURL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	authFrame, err := relay.EncodeAuthenticationFrame(peer, token)
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if err := connection.WriteMessage(websocket.BinaryMessage, authFrame); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}
