package relay

import (
	"context"
	"errors"
	"time"
)

type PeerAuthorizer func(context.Context, PeerIdentity) (bool, error)

// RunAuthorizationMonitor bounds the lifetime of a session revoked by the
// out-of-process local admin CLI. Authorization lookup errors fail closed for
// the affected active peer.
func RunAuthorizationMonitor(
	ctx context.Context,
	hub *Hub,
	interval time.Duration,
	authorize PeerAuthorizer,
) error {
	if hub == nil || authorize == nil {
		return errors.New("hub and peer authorizer are required")
	}
	if interval <= 0 {
		return errors.New("authorization monitor interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for _, peer := range hub.ConnectedPeers() {
				authorized, err := authorize(ctx, peer)
				if err != nil || !authorized {
					hub.Disconnect(peer)
				}
			}
		}
	}
}
