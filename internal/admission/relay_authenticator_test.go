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
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := registerApprovedTestDevice(ctx, store, Registration{
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
	hub, err := relay.NewHub(store, store)
	if err != nil {
		t.Fatal(err)
	}
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
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := registerApprovedTestDevice(ctx, store, Registration{
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
	hub, err := relay.NewHub(store, store)
	if err != nil {
		t.Fatal(err)
	}
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
			checkContext context.Context, session relay.ConnectedSession,
		) (bool, error) {
			var candidateWorkspace WorkspaceID
			var candidateDevice DeviceID
			copy(candidateWorkspace[:], session.Peer.WorkspaceID[:])
			copy(candidateDevice[:], session.Peer.DeviceID[:])
			return store.IsSessionAuthorized(
				checkContext, candidateWorkspace, candidateDevice, session.CredentialVersion)
		})
	}()

	connection := dialRegisteredDevice(t, server.URL, peer, registered.AuthToken)
	defer connection.Close()
	if _, message, err := connection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("authentication acknowledgement = %q, error = %v", message, err)
	}
	if revoked, err := store.RevokeDevice(ctx, RevokeDeviceInput{
		WorkspaceID: workspace, DeviceReference: deviceReference(workspace, registered.DeviceID),
		AuthorityPrivateKey: testAuthorityPrivateKey(), Now: now.Add(time.Second),
	}); err != nil || !revoked.Changed {
		t.Fatalf("revocation=%+v error=%v", revoked, err)
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

func TestCredentialRotationClosesOldSessionAndAuthenticatesPendingCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)
	registered, err := registerApprovedTestDevice(ctx, store, Registration{
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
	hub, err := relay.NewHub(store, store)
	if err != nil {
		t.Fatal(err)
	}
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
			checkContext context.Context, session relay.ConnectedSession,
		) (bool, error) {
			var candidateWorkspace WorkspaceID
			var candidateDevice DeviceID
			copy(candidateWorkspace[:], session.Peer.WorkspaceID[:])
			copy(candidateDevice[:], session.Peer.DeviceID[:])
			return store.IsSessionAuthorized(
				checkContext, candidateWorkspace, candidateDevice, session.CredentialVersion)
		})
	}()

	oldConnection := dialRegisteredDevice(t, server.URL, peer, registered.AuthToken)
	defer oldConnection.Close()
	if _, message, err := oldConnection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("old authentication acknowledgement = %q, error = %v", message, err)
	}
	rotationCode, err := store.IssueCredentialRotationCode(
		ctx, workspace, deviceReference(workspace, registered.DeviceID), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pendingToken := make([]byte, authTokenBytes)
	for index := range pendingToken {
		pendingToken[index] = 0x6a
	}
	if version, err := store.RotateCredential(ctx, CredentialRotation{
		WorkspaceID: workspace, DeviceID: registered.DeviceID,
		CurrentAuthToken: registered.AuthToken, RotationCode: rotationCode,
		PendingAuthToken: pendingToken, Now: now.Add(time.Second),
	}); err != nil || version != 2 {
		t.Fatalf("rotation version=%d error=%v", version, err)
	}
	if err := oldConnection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = oldConnection.ReadMessage()
	var closeError *websocket.CloseError
	if !errors.As(err, &closeError) || closeError.Code != websocket.ClosePolicyViolation {
		t.Fatalf("old-version connection error = %v", err)
	}
	oldReconnect := dialRegisteredDevice(t, server.URL, peer, registered.AuthToken)
	defer oldReconnect.Close()
	if err := oldReconnect.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, message, err := oldReconnect.ReadMessage(); err == nil || string(message) == "SNO1" {
		t.Fatalf("old credential reconnect acknowledgement = %q, error = %v", message, err)
	}
	pendingConnection := dialRegisteredDevice(t, server.URL, peer, pendingToken)
	defer pendingConnection.Close()
	if _, message, err := pendingConnection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("pending authentication acknowledgement = %q, error = %v", message, err)
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
