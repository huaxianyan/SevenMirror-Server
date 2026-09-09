package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
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
