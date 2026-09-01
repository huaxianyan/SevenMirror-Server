package relay

import (
	"context"
	"errors"
	"time"
)

type SessionAuthorizer func(context.Context, ConnectedSession) (bool, error)

// RunAuthorizationMonitor bounds the lifetime of a session revoked by the
// out-of-process local admin CLI. Authorization lookup errors fail closed for
// the affected active peer.
func RunAuthorizationMonitor(
	ctx context.Context,
	hub *Hub,
	interval time.Duration,
	authorize SessionAuthorizer,
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
			for _, session := range hub.ConnectedSessions() {
				authorized, err := authorize(ctx, session)
				if err != nil || !authorized {
					hub.Disconnect(session.Peer)
				}
			}
		}
	}
}
