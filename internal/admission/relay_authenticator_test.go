package admission

import (
	"context"
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
