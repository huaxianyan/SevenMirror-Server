package relay

import (
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
	hub := NewHub()
	_, _, unregisterSender, err := hub.Register(sender, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	deliveries, disconnected, unregister, err := hub.Register(recipient, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	select {
	case <-disconnected:
		t.Fatal("new session was already disconnected")
	default:
	}

	if err := hub.Route(sender, frame); err != nil {
		t.Fatal(err)
	}
	routed := <-deliveries
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
	hub := NewHub()

	wrongSender := sender
	wrongSender.DeviceID[0] ^= 1
	if err := hub.Route(wrongSender, frame); !errors.Is(err, ErrSenderMismatch) {
		t.Fatalf("wrong sender error = %v", err)
	}
	wrongWorkspace := sender
	wrongWorkspace.WorkspaceID[0] ^= 1
	if err := hub.Route(wrongWorkspace, frame); !errors.Is(err, ErrSenderMismatch) {
		t.Fatalf("wrong workspace error = %v", err)
	}
	_, _, unregisterSender, err := hub.Register(sender, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	if err := hub.Route(sender, frame); !errors.Is(err, ErrRecipientOffline) {
		t.Fatalf("offline error = %v", err)
	}
	_, _, unregister, err := hub.Register(recipient, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	if err := hub.Route(sender, frame); err != nil {
		t.Fatal(err)
	}
	if err := hub.Route(sender, frame); !errors.Is(err, ErrRecipientBusy) {
		t.Fatalf("backpressure error = %v", err)
	}
}

func TestHubDisconnectRemovesRoutingAndSignalsExactSession(t *testing.T) {
	frame := canonicalFrame(t)
	sender := peerFromFrame(t, frame, 24)
	recipient := peerFromFrame(t, frame, 40)
	hub := NewHub()
	_, _, unregisterSender, err := hub.Register(sender, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterSender()
	_, disconnected, unregister, err := hub.Register(recipient, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	if !hub.Disconnect(recipient) {
		t.Fatal("connected recipient was not disconnected")
	}
	select {
	case <-disconnected:
	default:
		t.Fatal("disconnect signal was not closed")
	}
	if hub.IsConnected(recipient) {
		t.Fatal("disconnected recipient remained routable")
	}
	if err := hub.Route(sender, frame); !errors.Is(err, ErrRecipientOffline) {
		t.Fatalf("route after recipient disconnect error = %v", err)
	}
	if !hub.Disconnect(sender) {
		t.Fatal("connected sender was not disconnected")
	}
	if err := hub.Route(sender, frame); !errors.Is(err, ErrSenderOffline) {
		t.Fatalf("route after sender disconnect error = %v", err)
	}
	if hub.Disconnect(recipient) {
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
