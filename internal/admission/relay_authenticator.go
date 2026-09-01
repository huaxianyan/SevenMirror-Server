package admission

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

type RelayAuthenticator struct {
	store *Store

	activityMu   sync.Mutex
	nextActivity map[relay.PeerIdentity]time.Time
}

func NewRelayAuthenticator(store *Store) (*RelayAuthenticator, error) {
	if store == nil {
		return nil, errors.New("admission store is required")
	}
	return &RelayAuthenticator{
		store: store, nextActivity: make(map[relay.PeerIdentity]time.Time),
	}, nil
}

func (a *RelayAuthenticator) AuthenticateConnection(
	ctx context.Context,
	peer relay.PeerIdentity,
	token []byte,
	now time.Time,
) (int64, error) {
	workspaceID, deviceID := admissionIDs(peer)
	identity, err := a.store.Authenticate(ctx, workspaceID, deviceID, token, now)
	if err == nil {
		a.activityMu.Lock()
		a.nextActivity[peer] = now.Add(time.Minute)
		a.activityMu.Unlock()
	}
	return identity.CredentialVersion, err
}

func (a *RelayAuthenticator) RecordConnectionActivity(
	ctx context.Context,
	peer relay.PeerIdentity,
	now time.Time,
) error {
	a.activityMu.Lock()
	if next, exists := a.nextActivity[peer]; exists && now.Before(next) {
		a.activityMu.Unlock()
		return nil
	}
	a.nextActivity[peer] = now.Add(time.Minute)
	a.activityMu.Unlock()

	workspaceID, deviceID := admissionIDs(peer)
	if err := a.store.RecordDeviceActivity(ctx, workspaceID, deviceID, now); err != nil {
		a.activityMu.Lock()
		delete(a.nextActivity, peer)
		a.activityMu.Unlock()
		return err
	}
	return nil
}

func admissionIDs(peer relay.PeerIdentity) (WorkspaceID, DeviceID) {
	var workspaceID WorkspaceID
	var deviceID DeviceID
	copy(workspaceID[:], peer.WorkspaceID[:])
	copy(deviceID[:], peer.DeviceID[:])
	return workspaceID, deviceID
}
