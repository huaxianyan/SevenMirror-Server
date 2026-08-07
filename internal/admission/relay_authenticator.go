package admission

import (
	"context"
	"errors"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

type RelayAuthenticator struct {
	store *Store
}

func NewRelayAuthenticator(store *Store) (*RelayAuthenticator, error) {
	if store == nil {
		return nil, errors.New("admission store is required")
	}
	return &RelayAuthenticator{store: store}, nil
}

func (a *RelayAuthenticator) AuthenticateConnection(
	ctx context.Context,
	peer relay.PeerIdentity,
	token []byte,
	now time.Time,
) error {
	var workspaceID WorkspaceID
	var deviceID DeviceID
	copy(workspaceID[:], peer.WorkspaceID[:])
	copy(deviceID[:], peer.DeviceID[:])
	_, err := a.store.Authenticate(ctx, workspaceID, deviceID, token, now)
	return err
}
