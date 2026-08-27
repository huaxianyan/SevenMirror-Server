package relay

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testDeliveryStore struct {
	mu         sync.Mutex
	deliveries map[PeerIdentity][]StoredDelivery
	next       map[PeerIdentity]uint64
	acked      map[PeerIdentity]uint64
}

func newTestHub(t *testing.T) *Hub {
	t.Helper()
	store := &testDeliveryStore{
		deliveries: make(map[PeerIdentity][]StoredDelivery),
		next:       make(map[PeerIdentity]uint64),
		acked:      make(map[PeerIdentity]uint64),
	}
	hub, err := NewHub(store, testRecipientAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return hub
}

func (s *testDeliveryStore) AppendDelivery(
	_ context.Context,
	peer PeerIdentity,
	envelope []byte,
	_ time.Time,
	_ time.Time,
) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.next[peer] + 1
	s.next[peer] = id
	s.deliveries[peer] = append(s.deliveries[peer], StoredDelivery{
		ID: id, Envelope: append([]byte(nil), envelope...),
	})
	return id, nil
}

func (s *testDeliveryStore) ResumeDeliveries(
	ctx context.Context,
	peer PeerIdentity,
	cursor uint64,
	_ time.Time,
	limit int,
) (DeliveryBatch, error) {
	if cursor > 0 {
		if err := s.AcknowledgeDelivery(ctx, peer, cursor); err != nil {
			return DeliveryBatch{}, err
		}
	}
	return s.ReadDeliveries(ctx, peer, cursor, time.Now(), limit)
}

func (s *testDeliveryStore) ReadDeliveries(
	_ context.Context,
	peer PeerIdentity,
	after uint64,
	_ time.Time,
	limit int,
) (DeliveryBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.deliveries[peer]
	batch := DeliveryBatch{}
	batch.HighWater = s.next[peer]
	for _, item := range all {
		if item.ID <= after {
			continue
		}
		batch.Deliveries = append(batch.Deliveries, StoredDelivery{
			ID: item.ID, Envelope: append([]byte(nil), item.Envelope...),
		})
		if len(batch.Deliveries) == limit {
			break
		}
	}
	return batch, nil
}

func (s *testDeliveryStore) AcknowledgeDelivery(
	_ context.Context,
	peer PeerIdentity,
	cursor uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cursor > s.acked[peer] {
		s.acked[peer] = cursor
	}
	all := s.deliveries[peer]
	kept := all[:0]
	for _, item := range all {
		if item.ID > cursor {
			kept = append(kept, item)
		}
	}
	s.deliveries[peer] = kept
	return nil
}

type testRecipientAuthorizer struct{}

func (testRecipientAuthorizer) IsRecipientAuthorized(
	context.Context,
	PeerIdentity,
) (bool, error) {
	return true, nil
}
