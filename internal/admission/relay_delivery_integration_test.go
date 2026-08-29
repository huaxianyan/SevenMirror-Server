package admission

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/relaydelivery"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/routingheader"
)

func TestOfflineRecipientResumesDurableCiphertextAfterServerRestart(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	now := time.Now()
	workspace, err := store.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	sender := registerRelayTestDevice(t, store, workspace, DeviceAndroid, "Phone", now)
	recipient := registerRelayTestDevice(t, store, workspace, DeviceChrome, "Browser", now)
	senderPeer := relayPeer(sender)
	recipientPeer := relayPeer(recipient)
	businessCanary := []byte("sevenmirror-relay-business-canary-e9168b42")
	envelope := routedTestEnvelope(t, senderPeer, recipientPeer, now, businessCanary)

	hub, err := relay.NewHub(store, store)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewRelayAuthenticator(store)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.NewAuthenticatedWebSocketHandler(hub, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := httptestServer(t, handler)
	senderConnection := dialRegisteredDevice(t, firstServer.URL, senderPeer, sender.AuthToken)
	if _, message, err := senderConnection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("sender authentication acknowledgement = %q, error = %v", message, err)
	}
	submission, err := relaydelivery.EncodeDurableSubmission(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := senderConnection.WriteMessage(websocket.BinaryMessage, submission); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for storedDeliveryCount(t, store) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("durable ciphertext was not committed while recipient was offline")
		}
		time.Sleep(time.Millisecond)
	}
	assertCanaryAbsentFromDatabaseFiles(t, path, businessCanary)
	senderConnection.Close()
	firstServer.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertCanaryAbsentFromDatabaseFiles(t, path, businessCanary)

	restarted, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedHub, err := relay.NewHub(restarted, restarted)
	if err != nil {
		t.Fatal(err)
	}
	restartedAuthenticator, err := NewRelayAuthenticator(restarted)
	if err != nil {
		t.Fatal(err)
	}
	restartedHandler, err := relay.NewAuthenticatedWebSocketHandler(
		restartedHub, restartedAuthenticator)
	if err != nil {
		t.Fatal(err)
	}
	secondServer := httptestServer(t, restartedHandler)
	defer secondServer.Close()
	recipientConnection := dialRegisteredDevice(
		t, secondServer.URL, recipientPeer, recipient.AuthToken)
	defer recipientConnection.Close()
	if _, message, err := recipientConnection.ReadMessage(); err != nil || string(message) != "SNO1" {
		t.Fatalf("recipient authentication acknowledgement = %q, error = %v", message, err)
	}
	resume, err := relaydelivery.EncodeResume(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipientConnection.WriteMessage(websocket.BinaryMessage, resume); err != nil {
		t.Fatal(err)
	}
	_, delivery, err := recipientConnection.ReadMessage()
	if err != nil || len(delivery) != relaydelivery.DeliveryPrefixSize+len(envelope) ||
		string(delivery[:4]) != "SND1" || binary.BigEndian.Uint64(delivery[4:12]) != 1 ||
		!bytes.Equal(delivery[12:], envelope) {
		t.Fatalf("resumed delivery was not the exact queued ciphertext: error=%v", err)
	}
	_, caughtUp, err := recipientConnection.ReadMessage()
	if err != nil || string(caughtUp[:4]) != "SND2" ||
		binary.BigEndian.Uint64(caughtUp[4:12]) != 1 {
		t.Fatalf("caught-up marker=%x error=%v", caughtUp, err)
	}
	ack, err := relaydelivery.EncodeAcknowledgement(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipientConnection.WriteMessage(websocket.BinaryMessage, ack); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for storedDeliveryCount(t, restarted) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("acknowledged ciphertext remained in relay history")
		}
		time.Sleep(time.Millisecond)
	}
}

func registerRelayTestDevice(
	t *testing.T,
	store *Store,
	workspace WorkspaceID,
	deviceType DeviceType,
	name string,
	now time.Time,
) RegisteredDevice {
	t.Helper()
	code, err := store.IssuePairingCode(
		context.Background(), workspace, deviceType, name, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.Register(context.Background(), Registration{
		PairingCode: code, DeviceType: deviceType, DeviceName: name,
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func relayPeer(device RegisteredDevice) relay.PeerIdentity {
	var peer relay.PeerIdentity
	copy(peer.WorkspaceID[:], device.WorkspaceID[:])
	copy(peer.DeviceID[:], device.DeviceID[:])
	return peer
}

func routedTestEnvelope(
	t *testing.T,
	sender relay.PeerIdentity,
	recipient relay.PeerIdentity,
	now time.Time,
	businessCanary []byte,
) []byte {
	t.Helper()
	content, err := os.ReadFile("../../protocol/test-vectors/encrypted-envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		FrameHex string `json:"frameHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(vector.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := envelopeframe.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	header, err := routingheader.Decode(frame.RoutingHeader[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(header.WorkspaceID[:], sender.WorkspaceID[:])
	copy(header.SenderDeviceID[:], sender.DeviceID[:])
	copy(header.RecipientDeviceID[:], recipient.DeviceID[:])
	header.CreatedAtUnixMs = uint64(now.UnixMilli())
	header.ExpiresAtUnixMs = uint64(now.Add(time.Hour).UnixMilli())
	frame.RoutingHeader, err = routingheader.Encode(header)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x7c}, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	frame.Ciphertext = aead.Seal(nil, bytes.Repeat([]byte{0x29}, aead.NonceSize()), businessCanary, frame.RoutingHeader[:])
	if bytes.Contains(frame.Ciphertext, businessCanary) {
		t.Fatal("test encryption fixture retained business plaintext")
	}
	encoded, err = envelopeframe.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertCanaryAbsentFromDatabaseFiles(t *testing.T, path string, canary []byte) {
	t.Helper()
	for _, databaseFile := range []string{path, path + "-wal", path + "-shm"} {
		contents, err := os.ReadFile(databaseFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if bytes.Contains(contents, canary) {
			t.Fatalf("business plaintext persisted in %s", filepath.Base(databaseFile))
		}
	}
}

func storedDeliveryCount(t *testing.T, store *Store) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM relay_deliveries`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func httptestServer(
	t *testing.T,
	handler *relay.AuthenticatedWebSocketHandler,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}
