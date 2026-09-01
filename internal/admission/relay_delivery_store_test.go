package admission

import (
	"context"
	"testing"
	"time"
)

func TestRelayDeliveryStoreIsolatesRecipientCursorsAndReportsExpiredHistory(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.Now()
	workspace, err := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	first := registerRelayTestDevice(t, store, workspace, DeviceChrome, "First", now)
	second := registerRelayTestDevice(t, store, workspace, DeviceChrome, "Second", now)
	firstPeer := relayPeer(first)
	secondPeer := relayPeer(second)

	firstID, err := store.AppendDelivery(ctx, firstPeer, []byte{1}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := store.AppendDelivery(ctx, secondPeer, []byte{2}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	nextFirstID, err := store.AppendDelivery(ctx, firstPeer, []byte{3}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if firstID != 1 || secondID != 1 || nextFirstID != 2 {
		t.Fatalf("recipient delivery IDs = first %d/%d, second %d", firstID, nextFirstID, secondID)
	}
	if err := store.AcknowledgeDelivery(ctx, firstPeer, 1); err != nil {
		t.Fatal(err)
	}
	firstBatch, err := store.ResumeDeliveries(ctx, firstPeer, 1, now, 16)
	if err != nil || len(firstBatch.Deliveries) != 1 || firstBatch.Deliveries[0].ID != 2 {
		t.Fatalf("first recipient batch=%+v error=%v", firstBatch, err)
	}
	secondBatch, err := store.ResumeDeliveries(ctx, secondPeer, 0, now, 16)
	if err != nil || len(secondBatch.Deliveries) != 1 || secondBatch.Deliveries[0].ID != 1 {
		t.Fatalf("second recipient batch=%+v error=%v", secondBatch, err)
	}

	expiringID, err := store.AppendDelivery(
		ctx, firstPeer, []byte{4}, now.Add(time.Millisecond), now)
	if err != nil || expiringID != 3 {
		t.Fatalf("expiring delivery ID=%d error=%v", expiringID, err)
	}
	reset, err := store.ResumeDeliveries(ctx, firstPeer, 1, now.Add(time.Second), 16)
	if err != nil || !reset.ResetRequired || reset.HighWater != 3 || len(reset.Deliveries) != 0 {
		t.Fatalf("expired-history reset=%+v error=%v", reset, err)
	}
}
