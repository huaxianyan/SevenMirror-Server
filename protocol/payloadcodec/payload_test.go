package payloadcodec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	notificationv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/notification/v1"
	"google.golang.org/protobuf/proto"
)

func validPayload() *notificationv1.EncryptedPayload {
	reply := "acknowledged"
	return &notificationv1.EncryptedPayload{
		SchemaVersion: SchemaVersion,
		Body: &notificationv1.EncryptedPayload_ActionInvoke{
			ActionInvoke: &notificationv1.ActionInvoke{
				NotificationId:       "test.notification/42",
				NotificationRevision: 7,
				ActionId:             bytes.Repeat([]byte{0xa1}, IdentifierSize),
				IdempotencyKey:       bytes.Repeat([]byte{0xb2}, IdentifierSize),
				ReplyText:            &reply,
			},
		},
	}
}

func TestCanonicalVector(t *testing.T) {
	content, err := os.ReadFile("../test-vectors/encrypted-payload-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		EncodedHex string `json:"encodedHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vector.EncodedHex)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(validPayload())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("encoded payload differs from canonical vector: %x", encoded)
	}
	if _, err := Decode(expected); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	encoded, err := Encode(validPayload())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetActionInvoke().GetNotificationRevision() != 7 {
		t.Fatal("revision changed")
	}
}

func TestRejectsNonCanonicalDuplicateAndUnknownFields(t *testing.T) {
	encoded, err := Encode(validPayload())
	if err != nil {
		t.Fatal(err)
	}
	duplicateVersion := append([]byte{0x08, 0x01}, encoded...)
	if _, err := Decode(duplicateVersion); err == nil {
		t.Fatal("duplicate field accepted")
	}
	unknown := append(append([]byte(nil), encoded...), 0x78, 0x01)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestActionResultRoundTrip(t *testing.T) {
	detail := "revision changed"
	payload := &notificationv1.EncryptedPayload{
		SchemaVersion: SchemaVersion,
		Body: &notificationv1.EncryptedPayload_ActionResult{
			ActionResult: &notificationv1.ActionResult{
				IdempotencyKey: bytes.Repeat([]byte{0xb2}, IdentifierSize),
				Status:         notificationv1.ActionResultStatus_ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION,
				Detail:         &detail,
			},
		},
	}
	encoded, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile("../test-vectors/encrypted-payload-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ActionResultEncodedHex string `json:"actionResultEncodedHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vector.ActionResultEncodedHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("encoded action result differs from canonical vector: %x", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetActionResult().GetStatus() != notificationv1.ActionResultStatus_ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION {
		t.Fatal("action result status changed")
	}
}

func TestRejectsInvalidActionFields(t *testing.T) {
	tests := []struct {
		name   string
		change func(*notificationv1.ActionInvoke)
	}{
		{"empty notification", func(a *notificationv1.ActionInvoke) { a.NotificationId = "" }},
		{"zero revision", func(a *notificationv1.ActionInvoke) { a.NotificationRevision = 0 }},
		{"large revision", func(a *notificationv1.ActionInvoke) { a.NotificationRevision = 1 << 63 }},
		{"short action id", func(a *notificationv1.ActionInvoke) { a.ActionId = a.ActionId[:15] }},
		{"zero idempotency", func(a *notificationv1.ActionInvoke) { a.IdempotencyKey = make([]byte, 16) }},
		{"empty reply", func(a *notificationv1.ActionInvoke) { empty := ""; a.ReplyText = &empty }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := proto.Clone(validPayload()).(*notificationv1.EncryptedPayload)
			test.change(payload.GetActionInvoke())
			if _, err := Encode(payload); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}
