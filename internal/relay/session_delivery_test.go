package relay

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/relaydelivery"
)

// This in-memory store models cancellation followed by storage cleanup. Returning
// from cancellation and completing that cleanup are deliberately separate steps.
type cancelingAckStore struct {
	*testDeliveryStore
	first    sync.Once
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	deadline time.Time
}

func (s *cancelingAckStore) AcknowledgeDelivery(ctx context.Context, peer PeerIdentity, cursor uint64) error {
	block := false
	s.first.Do(func() { block = true })
	if !block {
		return s.testDeliveryStore.AcknowledgeDelivery(ctx, peer, cursor)
	}
	s.deadline, _ = ctx.Deadline()
	close(s.started)
	<-ctx.Done()
	close(s.canceled)
	<-s.release
	return ctx.Err()
}

func TestReconnectReceivesDeliveryWhoseOldAcknowledgmentWasCanceled(t *testing.T) {
	frame := canonicalFrame(t)
	peer := peerFromFrame(t, frame, 40)
	token := bytes.Repeat([]byte{3}, 32)
	store := &cancelingAckStore{
		testDeliveryStore: &testDeliveryStore{
			deliveries: map[PeerIdentity][]StoredDelivery{peer: {{ID: 1, Envelope: frame}}},
			next:       map[PeerIdentity]uint64{peer: 1},
			acked:      make(map[PeerIdentity]uint64),
		},
		started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(store.release) })
	hub, err := NewHub(store, testRecipientAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAuthenticatedWebSocketHandler(hub, ConnectionAuthenticatorFunc(func(
		_ context.Context, candidate PeerIdentity, received []byte, _ time.Time,
	) (int64, error) {
		if candidate != peer || !bytes.Equal(received, token) {
			return 0, errors.New("unauthorized")
		}
		return 1, nil
	}), clientaddress.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	defer release()
	original := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer original.Close()
	observed := hub.ConnectedSessions()[0]

	resume, err := relaydelivery.EncodeResume(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.WriteMessage(websocket.BinaryMessage, resume); err != nil {
		t.Fatal(err)
	}
	readFirstSessionDelivery(t, original, frame)
	ack, err := relaydelivery.EncodeAcknowledgement(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.WriteMessage(websocket.BinaryMessage, ack); err != nil {
		t.Fatal(err)
	}
	waitForSessionStep(t, store.started, "old ACK entered storage")
	if remaining := time.Until(store.deadline); remaining <= 0 || remaining > 5*time.Second {
		t.Fatal("storage operation did not receive the documented five-second budget")
	}
	retired := make(chan struct{})
	go func() {
		hub.Disconnect(observed)
		close(retired)
	}()
	t.Cleanup(func() { waitForSessionStep(t, retired, "retirement finished") })
	waitForSessionStep(t, store.canceled, "old storage context canceled")
	// Admission must be responsive, but reserve this slot until storage returns.
	admission := make(chan error, 1)
	go func() {
		_, unregister, err := hub.Register(peer, 1, 1)
		if unregister != nil {
			unregister()
		}
		admission <- err
	}()
	select {
	case err := <-admission:
		if !errors.Is(err, ErrAlreadyConnected) {
			t.Fatal("replacement admitted while old storage work was still running")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("storage cleanup held the global admission lock")
	}
	release()
	waitForSessionStep(t, retired, "retirement finished")
	replacement := dialAndAuthenticateDevice(t, server.URL, peer, token)
	defer replacement.Close()
	if err := replacement.WriteMessage(websocket.BinaryMessage, resume); err != nil {
		t.Fatal(err)
	}
	readFirstSessionDelivery(t, replacement, frame)
}

func readFirstSessionDelivery(t *testing.T, connection *websocket.Conn, want []byte) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	kind, encoded, err := connection.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage {
		t.Fatalf("delivery read failed: %v", err)
	}
	expected := append([]byte{'S', 'N', 'D', '1', 0, 0, 0, 0, 0, 0, 0, 1}, want...)
	if !bytes.Equal(encoded, expected) {
		t.Fatal("expected retained delivery 1")
	}
}

func waitForSessionStep(t *testing.T, signal <-chan struct{}, step string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out: %s", step)
	}
}

func TestOldConnectionHandlesCannotAccessReconnectedDeliveryState(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1, 0)
	frame := canonicalFrame(t)
	sender := peerFromFrame(t, frame, 24)
	recipient := peerFromFrame(t, frame, 40)
	hub := newTestHub(t)
	oldSender, retireSender, err := hub.Register(sender, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	oldRecipient, retireRecipient, err := hub.Register(recipient, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	retireSender()
	retireRecipient()
	currentSender, closeSender, err := hub.Register(sender, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSender()
	currentRecipient, closeRecipient, err := hub.Register(recipient, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRecipient()
	if err := hub.RouteDurable(ctx, currentSender, frame, now); err != nil {
		t.Fatal(err)
	}
	operations := []func() error{
		func() error { return hub.RouteOnline(ctx, oldSender, frame) },
		func() error { return hub.RouteDurable(ctx, oldSender, frame, now) },
		func() error { _, err := hub.ResumeDeliveries(ctx, oldRecipient, 0, now); return err },
		func() error { _, err := hub.ReadDeliveries(ctx, oldRecipient, 0, now); return err },
		func() error { return hub.AcknowledgeDelivery(ctx, oldRecipient, 1) },
	}
	for _, operation := range operations {
		if err := operation(); !errors.Is(err, ErrSessionOffline) {
			t.Fatalf("old session operation result = %v", err)
		}
	}
	batch, err := hub.ResumeDeliveries(ctx, currentRecipient, 0, now)
	if err != nil || len(batch.Deliveries) != 1 || batch.Deliveries[0].ID != 1 || !bytes.Equal(batch.Deliveries[0].Envelope, frame) {
		t.Fatalf("current session did not receive delivery 1: %v", err)
	}
	if err := hub.AcknowledgeDelivery(ctx, currentRecipient, 1); err != nil {
		t.Fatal(err)
	}
	batch, err = hub.ReadDeliveries(ctx, currentRecipient, 0, now)
	if err != nil || len(batch.Deliveries) != 0 {
		t.Fatalf("current session ACK did not remove delivery: %v", err)
	}
}
