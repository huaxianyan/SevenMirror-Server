package relay

import (
	"context"
	"errors"
	"time"
)

const deliveryBatchSize = 64

var (
	ErrDeliveryCursorAhead   = errors.New("delivery cursor exceeds relay high-water")
	ErrRecipientUnauthorized = errors.New("recipient is not authorized")
)

type StoredDelivery struct {
	ID       uint64
	Envelope []byte
}

type DeliveryBatch struct {
	HighWater     uint64
	ResetRequired bool
	Deliveries    []StoredDelivery
}

type DeliveryStore interface {
	AppendDelivery(context.Context, PeerIdentity, []byte, time.Time, time.Time) (uint64, error)
	ResumeDeliveries(context.Context, PeerIdentity, uint64, time.Time, int) (DeliveryBatch, error)
	ReadDeliveries(context.Context, PeerIdentity, uint64, time.Time, int) (DeliveryBatch, error)
	AcknowledgeDelivery(context.Context, PeerIdentity, uint64) error
}

type RecipientAuthorizer interface {
	IsRecipientAuthorized(context.Context, PeerIdentity) (bool, error)
}
