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

func TestActionResultAckRoundTrip(t *testing.T) {
	content, err := os.ReadFile("../test-vectors/encrypted-payload-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ActionResultSHA256Hex     string `json:"actionResultSha256Hex"`
		ActionResultAckEncodedHex string `json:"actionResultAckEncodedHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(vector.ActionResultSHA256Hex)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vector.ActionResultAckEncodedHex)
	if err != nil {
		t.Fatal(err)
	}
	payload := &notificationv1.EncryptedPayload{
		SchemaVersion: SchemaVersion,
		Body: &notificationv1.EncryptedPayload_ActionResultAck{
			ActionResultAck: &notificationv1.ActionResultAck{
				IdempotencyKey: bytes.Repeat([]byte{0xb2}, IdentifierSize),
				ResultSha256:   digest,
			},
		},
	}
	encoded, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("encoded action result acknowledgement differs from canonical vector: %x", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetActionResultAck().GetResultSha256(), digest) {
		t.Fatal("action result acknowledgement digest changed")
	}

	payload.GetActionResultAck().ResultSha256 = make([]byte, SHA256Size)
	if _, err := Encode(payload); err == nil {
		t.Fatal("zero action result acknowledgement digest accepted")
	}
}

func TestNotificationCanonicalVectors(t *testing.T) {
	content, err := os.ReadFile("../test-vectors/encrypted-payload-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		NotificationID                string `json:"notificationPayloadId"`
		NotificationUpsertRevision    uint64 `json:"notificationUpsertRevision,string"`
		NotificationRemovedRevision   uint64 `json:"notificationRemovedRevision,string"`
		NotificationTitle             string `json:"notificationTitle"`
		NotificationBody              string `json:"notificationBody"`
		NotificationUpsertEncodedHex  string `json:"notificationUpsertEncodedHex"`
		NotificationRemovedEncodedHex string `json:"notificationRemovedEncodedHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	decodeHex := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	upsert := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationUpsert{
			NotificationUpsert: &notificationv1.NotificationUpsert{
				NotificationId:       vector.NotificationID,
				NotificationRevision: vector.NotificationUpsertRevision,
				Title:                &vector.NotificationTitle,
				Body:                 &vector.NotificationBody,
			},
		},
	}
	assertCanonicalPayload(t, upsert, decodeHex(vector.NotificationUpsertEncodedHex))

	removed := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationRemoved{
			NotificationRemoved: &notificationv1.NotificationRemoved{
				NotificationId:       vector.NotificationID,
				NotificationRevision: vector.NotificationRemovedRevision,
			},
		},
	}
	assertCanonicalPayload(t, removed, decodeHex(vector.NotificationRemovedEncodedHex))
}

func TestRejectsInvalidNotificationFieldsAndSchema(t *testing.T) {
	title := "Synthetic notification"
	valid := func() *notificationv1.EncryptedPayload {
		return &notificationv1.EncryptedPayload{
			SchemaVersion: NotificationSchemaVersion,
			Body: &notificationv1.EncryptedPayload_NotificationUpsert{
				NotificationUpsert: &notificationv1.NotificationUpsert{
					NotificationId:       "synthetic.notification/42",
					NotificationRevision: 7,
					Title:                &title,
				},
			},
		}
	}
	tests := []struct {
		name   string
		change func(*notificationv1.EncryptedPayload)
	}{
		{"action schema", func(p *notificationv1.EncryptedPayload) { p.SchemaVersion = SchemaVersion }},
		{"empty notification id", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().NotificationId = "" }},
		{"zero revision", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().NotificationRevision = 0 }},
		{"missing text", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().Title = nil }},
		{"empty title", func(p *notificationv1.EncryptedPayload) { empty := ""; p.GetNotificationUpsert().Title = &empty }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := valid()
			test.change(payload)
			if _, err := Encode(payload); err == nil {
				t.Fatal("invalid notification payload accepted")
			}
		})
	}
}

func TestIdentityKeyTransitionCanonicalVector(t *testing.T) {
	vector := loadIdentityTransitionVector(t)
	transition := &notificationv1.EncryptedPayload{
		SchemaVersion: IdentityLifecycleSchemaVersion,
		Body: &notificationv1.EncryptedPayload_IdentityKeyTransition{
			IdentityKeyTransition: &notificationv1.IdentityKeyTransition{
				TransitionId:  vector.transitionID,
				PreviousKeyId: vector.previousKeyID,
				NewPublicKey:  vector.newPublicKey,
				NewKeyId:      vector.newKeyID,
			},
		},
	}
	assertCanonicalPayload(t, transition, vector.transitionEncoded)

	ack := &notificationv1.EncryptedPayload{
		SchemaVersion: IdentityLifecycleSchemaVersion,
		Body: &notificationv1.EncryptedPayload_IdentityKeyTransitionAck{
			IdentityKeyTransitionAck: &notificationv1.IdentityKeyTransitionAck{
				TransitionId:     vector.transitionID,
				PreviousKeyId:    vector.previousKeyID,
				NewKeyId:         vector.newKeyID,
				TransitionSha256: vector.transitionSHA256,
			},
		},
	}
	assertCanonicalPayload(t, ack, vector.ackEncoded)

	commit := &notificationv1.EncryptedPayload{
		SchemaVersion: IdentityLifecycleSchemaVersion,
		Body: &notificationv1.EncryptedPayload_IdentityKeyTransitionCommit{
			IdentityKeyTransitionCommit: &notificationv1.IdentityKeyTransitionCommit{
				TransitionId:     vector.transitionID,
				PreviousKeyId:    vector.previousKeyID,
				NewKeyId:         vector.newKeyID,
				TransitionSha256: vector.transitionSHA256,
				AckSha256:        vector.ackSHA256,
			},
		},
	}
	assertCanonicalPayload(t, commit, vector.commitEncoded)
}

func TestRejectsInvalidIdentityKeyTransitionFields(t *testing.T) {
	vector := loadIdentityTransitionVector(t)
	valid := func() *notificationv1.EncryptedPayload {
		return &notificationv1.EncryptedPayload{
			SchemaVersion: IdentityLifecycleSchemaVersion,
			Body: &notificationv1.EncryptedPayload_IdentityKeyTransition{
				IdentityKeyTransition: &notificationv1.IdentityKeyTransition{
					TransitionId:  append([]byte(nil), vector.transitionID...),
					PreviousKeyId: append([]byte(nil), vector.previousKeyID...),
					NewPublicKey:  append([]byte(nil), vector.newPublicKey...),
					NewKeyId:      append([]byte(nil), vector.newKeyID...),
				},
			},
		}
	}
	tests := []struct {
		name   string
		change func(*notificationv1.EncryptedPayload)
	}{
		{"schema v1", func(p *notificationv1.EncryptedPayload) { p.SchemaVersion = SchemaVersion }},
		{"zero transition id", func(p *notificationv1.EncryptedPayload) {
			p.GetIdentityKeyTransition().TransitionId = make([]byte, IdentifierSize)
		}},
		{"same key id", func(p *notificationv1.EncryptedPayload) {
			p.GetIdentityKeyTransition().NewKeyId = append([]byte(nil), p.GetIdentityKeyTransition().PreviousKeyId...)
		}},
		{"invalid point", func(p *notificationv1.EncryptedPayload) { p.GetIdentityKeyTransition().NewPublicKey[0] = 0x05 }},
		{"wrong key digest", func(p *notificationv1.EncryptedPayload) { p.GetIdentityKeyTransition().NewKeyId[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := valid()
			test.change(payload)
			if _, err := Encode(payload); err == nil {
				t.Fatal("invalid identity key transition accepted")
			}
		})
	}
}

func TestRejectsIdentityLifecycleDigestAndSchemaMismatch(t *testing.T) {
	vector := loadIdentityTransitionVector(t)
	ack := &notificationv1.EncryptedPayload{
		SchemaVersion: IdentityLifecycleSchemaVersion,
		Body: &notificationv1.EncryptedPayload_IdentityKeyTransitionAck{
			IdentityKeyTransitionAck: &notificationv1.IdentityKeyTransitionAck{
				TransitionId:     vector.transitionID,
				PreviousKeyId:    vector.previousKeyID,
				NewKeyId:         vector.newKeyID,
				TransitionSha256: make([]byte, SHA256Size),
			},
		},
	}
	if _, err := Encode(ack); err == nil {
		t.Fatal("zero transition digest accepted")
	}
	ack.GetIdentityKeyTransitionAck().TransitionSha256 = vector.transitionSHA256
	ack.SchemaVersion = SchemaVersion
	if _, err := Encode(ack); err == nil {
		t.Fatal("identity lifecycle body accepted under schema v1")
	}

	action := validPayload()
	action.SchemaVersion = IdentityLifecycleSchemaVersion
	if _, err := Encode(action); err == nil {
		t.Fatal("action body accepted under identity lifecycle schema")
	}
}

type identityTransitionVector struct {
	transitionID      []byte
	previousKeyID     []byte
	newPublicKey      []byte
	newKeyID          []byte
	transitionEncoded []byte
	transitionSHA256  []byte
	ackEncoded        []byte
	ackSHA256         []byte
	commitEncoded     []byte
}

func loadIdentityTransitionVector(t *testing.T) identityTransitionVector {
	t.Helper()
	content, err := os.ReadFile("../test-vectors/e2ee-identity-key-transition-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		TransitionIDHex      string `json:"transitionIdHex"`
		PreviousKeyIDHex     string `json:"previousKeyIdHex"`
		NewPublicKeyHex      string `json:"newPublicKeyHex"`
		NewKeyIDHex          string `json:"newKeyIdHex"`
		TransitionEncodedHex string `json:"transitionEncodedHex"`
		TransitionSHA256Hex  string `json:"transitionSha256Hex"`
		AckEncodedHex        string `json:"ackEncodedHex"`
		AckSHA256Hex         string `json:"ackSha256Hex"`
		CommitEncodedHex     string `json:"commitEncodedHex"`
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		result, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	return identityTransitionVector{
		transitionID:      decode(raw.TransitionIDHex),
		previousKeyID:     decode(raw.PreviousKeyIDHex),
		newPublicKey:      decode(raw.NewPublicKeyHex),
		newKeyID:          decode(raw.NewKeyIDHex),
		transitionEncoded: decode(raw.TransitionEncodedHex),
		transitionSHA256:  decode(raw.TransitionSHA256Hex),
		ackEncoded:        decode(raw.AckEncodedHex),
		ackSHA256:         decode(raw.AckSHA256Hex),
		commitEncoded:     decode(raw.CommitEncodedHex),
	}
}

func assertCanonicalPayload(t *testing.T, payload *notificationv1.EncryptedPayload, expected []byte) {
	t.Helper()
	encoded, err := Encode(payload)
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
