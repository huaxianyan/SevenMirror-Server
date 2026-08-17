package relay

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthorizationMonitorDisconnectsRevokedAndLookupFailureOnly(t *testing.T) {
	hub := NewHub()
	revoked := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{1}}
	active := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	lookupFailure := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{3}}
	_, revokedSignal, revokedUnregister, err := hub.Register(revoked, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer revokedUnregister()
	_, _, activeUnregister, err := hub.Register(active, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer activeUnregister()
	_, failureSignal, failureUnregister, err := hub.Register(lookupFailure, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer failureUnregister()

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		finished <- RunAuthorizationMonitor(ctx, hub, time.Millisecond, func(
			_ context.Context, session ConnectedSession,
		) (bool, error) {
			switch session.Peer {
			case revoked:
				return false, nil
			case lookupFailure:
				return false, errors.New("database unavailable")
			default:
				return true, nil
			}
		})
	}()

	waitForDisconnect(t, revokedSignal)
	waitForDisconnect(t, failureSignal)
	if !hub.IsConnected(active) {
		t.Fatal("authorized peer was disconnected")
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("monitor error = %v", err)
	}
}

func waitForDisconnect(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("device was not disconnected")
	}
}
