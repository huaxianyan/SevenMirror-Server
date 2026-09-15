package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

type envelopeVector struct {
	FrameHex string `json:"frameHex"`
}

func TestHubRoutesUnchangedCiphertextToOneRecipient(t *testing.T) {
	frame := canonicalFrame(t)
	sender := peerFromFrame(t, frame, 24)
	recipient := peerFromFrame(t, frame, 40)
	hub := newTestHub(t)
	senderSession, unregisterSender, err := hub.Register(sender, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	recipientSession, unregister, err := hub.Register(recipient, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	select {
	case <-recipientSession.session.disconnected:
		t.Fatal("new session was already disconnected")
	default:
	}

	if err := hub.RouteOnline(context.Background(), senderSession, frame); err != nil {
		t.Fatal(err)
	}
	routed := <-recipientSession.session.immediate
	if hex.EncodeToString(routed) != hex.EncodeToString(frame) {
		t.Fatal("relay modified encrypted frame")
	}
	routed[0] ^= 0xff
	if frame[0] == routed[0] {
		t.Fatal("relay did not isolate recipient copy")
	}
}

func TestHubRejectsIdentityMismatchOfflineAndBackpressure(t *testing.T) {
	frame := canonicalFrame(t)
	sender := peerFromFrame(t, frame, 24)
	recipient := peerFromFrame(t, frame, 40)
	hub := newTestHub(t)

	wrongSender := sender
	wrongSender.DeviceID[0] ^= 1
	if err := hub.RouteOnline(context.Background(), ConnectedSession{Peer: wrongSender}, frame); !errors.Is(err, ErrSenderMismatch) {
		t.Fatalf("wrong sender error = %v", err)
	}
	wrongWorkspace := sender
	wrongWorkspace.WorkspaceID[0] ^= 1
	if err := hub.RouteOnline(context.Background(), ConnectedSession{Peer: wrongWorkspace}, frame); !errors.Is(err, ErrSenderMismatch) {
		t.Fatalf("wrong workspace error = %v", err)
	}
	senderSession, unregisterSender, err := hub.Register(sender, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	if err := hub.RouteOnline(context.Background(), senderSession, frame); !errors.Is(err, ErrRecipientOffline) {
		t.Fatalf("offline error = %v", err)
	}
	_, unregister, err := hub.Register(recipient, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	if err := hub.RouteOnline(context.Background(), senderSession, frame); err != nil {
		t.Fatal(err)
	}
	if err := hub.RouteOnline(context.Background(), senderSession, frame); !errors.Is(err, ErrRecipientBusy) {
		t.Fatalf("backpressure error = %v", err)
	}
}

func TestHubDisconnectRemovesRoutingAndSignalsExactSession(t *testing.T) {
	frame := canonicalFrame(t)
	sender := peerFromFrame(t, frame, 24)
	recipient := peerFromFrame(t, frame, 40)
	hub := newTestHub(t)
	senderSession, unregisterSender, err := hub.Register(sender, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	recipientSession, unregister, err := hub.Register(recipient, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	if !hub.Disconnect(recipientSession) {
		t.Fatal("connected recipient was not disconnected")
	}
	select {
	case <-recipientSession.session.disconnected:
	default:
		t.Fatal("disconnect signal was not closed")
	}
	if hub.IsConnected(recipient) {
		t.Fatal("disconnected recipient remained routable")
	}
	if err := hub.RouteOnline(context.Background(), senderSession, frame); !errors.Is(err, ErrRecipientOffline) {
		t.Fatalf("route after recipient disconnect error = %v", err)
	}
	if !hub.Disconnect(senderSession) {
		t.Fatal("connected sender was not disconnected")
	}
	if err := hub.RouteOnline(context.Background(), senderSession, frame); !errors.Is(err, ErrSessionOffline) {
		t.Fatalf("route after sender disconnect error = %v", err)
	}
	if hub.Disconnect(recipientSession) {
		t.Fatal("duplicate disconnect reported a change")
	}
}

// A replacement that authenticated with an older credential version must never
// roll a rotated credential backwards.
func TestRegisterRefusesToRollBackTheCredentialVersion(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	hub := newTestHub(t)
	current, retireCurrent, err := hub.Register(peer, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer retireCurrent()
	if _, _, err := hub.Register(peer, 1, 1); !errors.Is(err, ErrStaleCredential) {
		t.Fatalf("older credential admission error = %v", err)
	}
	if !hub.IsConnected(peer) {
		t.Fatal("stale admission released the newer session slot")
	}
	select {
	case <-current.session.superseded:
		t.Fatal("stale admission retired the newer session")
	default:
	}
	_, finish, err := hub.beginOperation(context.Background(), current, sessionOperationTimeout)
	if err != nil {
		t.Fatalf("newer session stopped accepting operations: %v", err)
	}
	finish()
}

// An authenticated replacement for the same credential version takes the slot.
// The retired instance is signalled through the replacement channel, and its own
// late cleanup must not touch the replacement.
func TestRegisterHandsOverTheSlotToAnAuthenticatedReplacement(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	hub := newTestHub(t)
	retired, retireRetired, err := hub.Register(peer, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer retireRetired()
	// Model the retiring connection's own cleanup path: its owner observes the
	// replacement signal and unregisters, which is what releases the slot.
	go func() {
		<-retired.session.superseded
		retireRetired()
	}()
	replacement, retireReplacement, err := hub.Register(peer, 1, 1)
	if err != nil {
		t.Fatalf("replacement admission error = %v", err)
	}
	defer retireReplacement()
	if _, finish, err := hub.beginOperation(context.Background(), replacement, sessionOperationTimeout); err != nil {
		t.Fatalf("replacement is not usable: %v", err)
	} else {
		finish()
	}
	if _, _, err := hub.beginOperation(context.Background(), retired, sessionOperationTimeout); !errors.Is(err, ErrSessionOffline) {
		t.Fatalf("retired session still accepted operations: %v", err)
	}
	if hub.Disconnect(retired) {
		t.Fatal("late cleanup of the retired session reported a change")
	}
	if !hub.IsConnected(peer) {
		t.Fatal("late cleanup of the retired session removed the replacement")
	}
}

// A slot whose admitted work never drains must stay reserved. The waiting
// replacement gets a bounded refusal instead of a slot that is not really free.
func TestRegisterBoundsTheWaitForAStuckRetirement(t *testing.T) {
	peer := PeerIdentity{WorkspaceID: WorkspaceID{1}, DeviceID: DeviceID{2}}
	hub := newTestHub(t)
	hub.handoverTimeout = 100 * time.Millisecond
	stuck, retireStuck, err := hub.Register(peer, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer retireStuck()
	// The owner observes the replacement but never releases the slot.
	observed := make(chan struct{})
	go func() {
		<-stuck.session.superseded
		close(observed)
	}()
	started := time.Now()
	if _, _, err := hub.Register(peer, 1, 1); !errors.Is(err, ErrHandoverTimeout) {
		t.Fatalf("stuck handover error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("handover wait was not bounded: %v", elapsed)
	}
	select {
	case <-observed:
	default:
		t.Fatal("replacement did not signal the stuck session")
	}
	if !hub.IsConnected(peer) {
		t.Fatal("a slot that was never released was reassigned")
	}
}

func canonicalFrame(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile("../../protocol/test-vectors/encrypted-envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture envelopeVector
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	frame, err := hex.DecodeString(fixture.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func peerFromFrame(t *testing.T, frame []byte, deviceHeaderOffset int) PeerIdentity {
	t.Helper()
	var result PeerIdentity
	copy(result.WorkspaceID[:], frame[12:28])
	start := 4 + deviceHeaderOffset
	copy(result.DeviceID[:], frame[start:start+len(result.DeviceID)])
	return result
}
