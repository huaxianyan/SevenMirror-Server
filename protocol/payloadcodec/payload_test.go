package payloadcodec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
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
		EncodedHex        string `json:"encodedHex"`
		DismissEncodedHex string `json:"dismissEncodedHex"`
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

	dismissExpected, err := hex.DecodeString(vector.DismissEncodedHex)
	if err != nil {
		t.Fatal(err)
	}
	dismiss := &notificationv1.EncryptedPayload{
		SchemaVersion: SchemaVersion,
		Body: &notificationv1.EncryptedPayload_ActionInvoke{
			ActionInvoke: &notificationv1.ActionInvoke{
				NotificationId:       "test.notification/42",
				NotificationRevision: 8,
				IdempotencyKey:       bytes.Repeat([]byte{0xc3}, IdentifierSize),
				DismissNotification:  true,
			},
		},
	}
	assertCanonicalPayload(t, dismiss, dismissExpected)
}

func TestDecodeAcceptsLegacyDurableActionButNotLegacyDismiss(t *testing.T) {
	legacy := proto.Clone(validPayload()).(*notificationv1.EncryptedPayload)
	legacy.SchemaVersion = 1
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("legacy durable action rejected: %v", err)
	}
	if _, err := Encode(legacy); err == nil {
		t.Fatal("legacy action emitted by current encoder")
	}

	legacy.GetActionInvoke().ActionId = nil
	legacy.GetActionInvoke().ReplyText = nil
	legacy.GetActionInvoke().DismissNotification = true
	encoded, err = (proto.MarshalOptions{Deterministic: true}).Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err == nil {
		t.Fatal("dismiss accepted under legacy action schema")
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
		NotificationID                    string `json:"notificationPayloadId"`
		NotificationUpsertRevision        uint64 `json:"notificationUpsertRevision,string"`
		NotificationRemovedRevision       uint64 `json:"notificationRemovedRevision,string"`
		NotificationSourceApplicationID   string `json:"notificationSourceApplicationId"`
		NotificationSourceApplicationName string `json:"notificationSourceApplicationName"`
		NotificationTitle                 string `json:"notificationTitle"`
		NotificationBody                  string `json:"notificationBody"`
		NotificationContainsContentImage  bool   `json:"notificationContainsContentImage"`
		NotificationActions               []struct {
			ActionIDHex         string `json:"actionIdHex"`
			Title               string `json:"title"`
			RequiresTextInput   bool   `json:"requiresTextInput"`
			AllowsFreeFormInput bool   `json:"allowsFreeFormInput"`
		} `json:"notificationActions"`
		NotificationAppIcon struct {
			ContentSHA256Hex string `json:"contentSha256Hex"`
			Width            uint32 `json:"width"`
			Height           uint32 `json:"height"`
			EncodedHex       string `json:"encodedHex"`
		} `json:"notificationAppIcon"`
		NotificationAvatar struct {
			ContentSHA256Hex string `json:"contentSha256Hex"`
			Width            uint32 `json:"width"`
			Height           uint32 `json:"height"`
			EncodedHex       string `json:"encodedHex"`
		} `json:"notificationAvatar"`
		NotificationUpsertEncodedHex          string `json:"notificationUpsertEncodedHex"`
		NotificationRemovedEncodedHex         string `json:"notificationRemovedEncodedHex"`
		NotificationSnapshotHighWaterRevision uint64 `json:"notificationSnapshotHighWaterRevision,string"`
		NotificationSnapshotEntries           []struct {
			NotificationID       string `json:"notificationId"`
			NotificationRevision uint64 `json:"notificationRevision,string"`
		} `json:"notificationSnapshotEntries"`
		NotificationSnapshotRecoveryRequestIDHex string `json:"notificationSnapshotRecoveryRequestIdHex"`
		NotificationSnapshotResetHighWater       uint64 `json:"notificationSnapshotResetHighWaterDeliveryId,string"`
		NotificationSnapshotRequestEncodedHex    string `json:"notificationSnapshotRequestEncodedHex"`
		NotificationSnapshotManifestEncodedHex   string `json:"notificationSnapshotManifestEncodedHex"`
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
	media := func(contentSHA256Hex string, width, height uint32, encodedHex string) *notificationv1.NotificationMedia {
		return &notificationv1.NotificationMedia{
			ContentSha256: decodeHex(contentSHA256Hex),
			MimeType:      notificationv1.NotificationMediaMimeType_NOTIFICATION_MEDIA_MIME_TYPE_PNG,
			Width:         width,
			Height:        height,
			EncodedBytes:  decodeHex(encodedHex),
		}
	}
	actions := make([]*notificationv1.NotificationActionDescriptor, len(vector.NotificationActions))
	for index, action := range vector.NotificationActions {
		actions[index] = &notificationv1.NotificationActionDescriptor{
			ActionId:            decodeHex(action.ActionIDHex),
			Title:               action.Title,
			RequiresTextInput:   action.RequiresTextInput,
			AllowsFreeFormInput: action.AllowsFreeFormInput,
		}
	}
	upsert := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationUpsert{
			NotificationUpsert: &notificationv1.NotificationUpsert{
				NotificationId:        vector.NotificationID,
				NotificationRevision:  vector.NotificationUpsertRevision,
				SourceApplicationId:   vector.NotificationSourceApplicationID,
				SourceApplicationName: vector.NotificationSourceApplicationName,
				Title:                 &vector.NotificationTitle,
				Body:                  &vector.NotificationBody,
				AppIcon: media(
					vector.NotificationAppIcon.ContentSHA256Hex,
					vector.NotificationAppIcon.Width,
					vector.NotificationAppIcon.Height,
					vector.NotificationAppIcon.EncodedHex,
				),
				Avatar: media(
					vector.NotificationAvatar.ContentSHA256Hex,
					vector.NotificationAvatar.Width,
					vector.NotificationAvatar.Height,
					vector.NotificationAvatar.EncodedHex,
				),
				ContainsContentImage: vector.NotificationContainsContentImage,
				Actions:              actions,
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

	entries := make([]*notificationv1.NotificationSnapshotEntry, len(vector.NotificationSnapshotEntries))
	for index, entry := range vector.NotificationSnapshotEntries {
		entries[index] = &notificationv1.NotificationSnapshotEntry{
			NotificationId:       entry.NotificationID,
			NotificationRevision: entry.NotificationRevision,
		}
	}
	recoveryRequestID := decodeHex(vector.NotificationSnapshotRecoveryRequestIDHex)
	request := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationSnapshotRequest{
			NotificationSnapshotRequest: &notificationv1.NotificationSnapshotRequest{
				RecoveryRequestId:        recoveryRequestID,
				ResetHighWaterDeliveryId: vector.NotificationSnapshotResetHighWater,
			},
		},
	}
	assertCanonicalPayload(t, request, decodeHex(vector.NotificationSnapshotRequestEncodedHex))

	manifest := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationSnapshotManifest{
			NotificationSnapshotManifest: &notificationv1.NotificationSnapshotManifest{
				HighWaterRevision:   vector.NotificationSnapshotHighWaterRevision,
				ActiveNotifications: entries,
				RecoveryRequestId:   recoveryRequestID,
			},
		},
	}
	assertCanonicalPayload(t, manifest, decodeHex(vector.NotificationSnapshotManifestEncodedHex))
}

func TestRejectsInvalidNotificationSnapshotManifest(t *testing.T) {
	valid := func() *notificationv1.EncryptedPayload {
		return &notificationv1.EncryptedPayload{
			SchemaVersion: NotificationSchemaVersion,
			Body: &notificationv1.EncryptedPayload_NotificationSnapshotManifest{
				NotificationSnapshotManifest: &notificationv1.NotificationSnapshotManifest{
					HighWaterRevision: 9,
					ActiveNotifications: []*notificationv1.NotificationSnapshotEntry{
						{NotificationId: "synthetic.notification/42", NotificationRevision: 7},
						{NotificationId: "synthetic.notification/99", NotificationRevision: 9},
					},
				},
			},
		}
	}
	tests := []struct {
		name   string
		change func(*notificationv1.EncryptedPayload)
	}{
		{"wrong schema", func(p *notificationv1.EncryptedPayload) { p.SchemaVersion = SchemaVersion }},
		{"zero recovery request id", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotManifest().RecoveryRequestId = make([]byte, IdentifierSize)
		}},
		{"entry above high water", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotManifest().ActiveNotifications[0].NotificationRevision = 10
		}},
		{"duplicate id", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotManifest().ActiveNotifications[1].NotificationId = "synthetic.notification/42"
		}},
		{"unsorted ids", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotManifest().ActiveNotifications[0].NotificationId = "synthetic.notification/zz"
		}},
		{"too many entries", func(p *notificationv1.EncryptedPayload) {
			entry := p.GetNotificationSnapshotManifest().ActiveNotifications[0]
			p.GetNotificationSnapshotManifest().ActiveNotifications = make([]*notificationv1.NotificationSnapshotEntry, MaxSnapshotEntries+1)
			for index := range p.GetNotificationSnapshotManifest().ActiveNotifications {
				p.GetNotificationSnapshotManifest().ActiveNotifications[index] = entry
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := valid()
			test.change(payload)
			if _, err := Encode(payload); err == nil {
				t.Fatal("invalid notification snapshot manifest accepted")
			}
		})
	}

	empty := valid()
	empty.GetNotificationSnapshotManifest().HighWaterRevision = 0
	empty.GetNotificationSnapshotManifest().ActiveNotifications = nil
	if _, err := Encode(empty); err != nil {
		t.Fatalf("empty zero-high-water snapshot rejected: %v", err)
	}
}

func TestRejectsInvalidNotificationSnapshotRequest(t *testing.T) {
	valid := &notificationv1.EncryptedPayload{
		SchemaVersion: NotificationSchemaVersion,
		Body: &notificationv1.EncryptedPayload_NotificationSnapshotRequest{
			NotificationSnapshotRequest: &notificationv1.NotificationSnapshotRequest{
				RecoveryRequestId:        bytes.Repeat([]byte{0xd4}, IdentifierSize),
				ResetHighWaterDeliveryId: 9,
			},
		},
	}
	if _, err := Encode(valid); err != nil {
		t.Fatalf("valid snapshot request rejected: %v", err)
	}
	for _, change := range []func(*notificationv1.EncryptedPayload){
		func(p *notificationv1.EncryptedPayload) { p.SchemaVersion = SchemaVersion },
		func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotRequest().RecoveryRequestId = make([]byte, IdentifierSize)
		},
		func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationSnapshotRequest().ResetHighWaterDeliveryId = 1 << 63
		},
	} {
		candidate := proto.Clone(valid).(*notificationv1.EncryptedPayload)
		change(candidate)
		if _, err := Encode(candidate); err == nil {
			t.Fatal("invalid notification snapshot request accepted")
		}
	}
}

func TestRejectsInvalidNotificationFieldsAndSchema(t *testing.T) {
	title := "Synthetic notification"
	valid := func() *notificationv1.EncryptedPayload {
		return &notificationv1.EncryptedPayload{
			SchemaVersion: NotificationSchemaVersion,
			Body: &notificationv1.EncryptedPayload_NotificationUpsert{
				NotificationUpsert: &notificationv1.NotificationUpsert{
					NotificationId:        "synthetic.notification/42",
					NotificationRevision:  7,
					SourceApplicationId:   "dev.notificationmirroring.android",
					SourceApplicationName: "SevenMirror",
					Title:                 &title,
					Actions: []*notificationv1.NotificationActionDescriptor{
						{ActionId: bytes.Repeat([]byte{1}, IdentifierSize), Title: "Mark handled"},
					},
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
		{"empty source application id", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().SourceApplicationId = "" }},
		{"oversized source application id", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().SourceApplicationId = strings.Repeat("a", MaxNotificationAppIDBytes+1)
		}},
		{"empty source application name", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().SourceApplicationName = "" }},
		{"oversized source application name", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().SourceApplicationName = strings.Repeat("a", MaxNotificationAppNameBytes+1)
		}},
		{"missing text", func(p *notificationv1.EncryptedPayload) { p.GetNotificationUpsert().Title = nil }},
		{"empty title", func(p *notificationv1.EncryptedPayload) { empty := ""; p.GetNotificationUpsert().Title = &empty }},
		{"content image without placeholder", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().ContainsContentImage = true
		}},
		{"short action id", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().Actions[0].ActionId = make([]byte, IdentifierSize-1)
		}},
		{"empty action title", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().Actions[0].Title = ""
		}},
		{"free-form input without required text", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().Actions[0].AllowsFreeFormInput = true
		}},
		{"duplicate action id", func(p *notificationv1.EncryptedPayload) {
			p.GetNotificationUpsert().Actions = append(
				p.GetNotificationUpsert().Actions,
				proto.Clone(p.GetNotificationUpsert().Actions[0]).(*notificationv1.NotificationActionDescriptor),
			)
		}},
		{"too many actions", func(p *notificationv1.EncryptedPayload) {
			action := p.GetNotificationUpsert().Actions[0]
			p.GetNotificationUpsert().Actions = make([]*notificationv1.NotificationActionDescriptor, MaxNotificationActions+1)
			for index := range p.GetNotificationUpsert().Actions {
				p.GetNotificationUpsert().Actions[index] = action
			}
		}},
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

func TestRejectsInvalidNotificationMedia(t *testing.T) {
	png := append([]byte(pngSignature), []byte("bounded-png-test")...)
	digest := decodeTestHex("eda5ff88e35d671aeab8bb05ba83cdd505b647263f12e3feb8211e84672f56f0")
	valid := func() *notificationv1.EncryptedPayload {
		title := "Synthetic notification"
		return &notificationv1.EncryptedPayload{
			SchemaVersion: NotificationSchemaVersion,
			Body: &notificationv1.EncryptedPayload_NotificationUpsert{
				NotificationUpsert: &notificationv1.NotificationUpsert{
					NotificationId:        "synthetic.notification/42",
					NotificationRevision:  7,
					SourceApplicationId:   "dev.notificationmirroring.android",
					SourceApplicationName: "SevenMirror",
					Title:                 &title,
					AppIcon: &notificationv1.NotificationMedia{
						ContentSha256: append([]byte(nil), digest...),
						MimeType:      notificationv1.NotificationMediaMimeType_NOTIFICATION_MEDIA_MIME_TYPE_PNG,
						Width:         1, Height: 1, EncodedBytes: png,
					},
				},
			},
		}
	}
	tests := []struct {
		name   string
		change func(*notificationv1.NotificationMedia)
	}{
		{"wrong digest", func(media *notificationv1.NotificationMedia) { media.ContentSha256[0] ^= 1 }},
		{"unsupported MIME", func(media *notificationv1.NotificationMedia) {
			media.MimeType = notificationv1.NotificationMediaMimeType_NOTIFICATION_MEDIA_MIME_TYPE_UNSPECIFIED
		}},
		{"zero width", func(media *notificationv1.NotificationMedia) { media.Width = 0 }},
		{"oversized height", func(media *notificationv1.NotificationMedia) {
			media.Height = MaxNotificationMediaDimension + 1
		}},
		{"oversized bytes", func(media *notificationv1.NotificationMedia) {
			media.EncodedBytes = make([]byte, MaxNotificationMediaBytes+1)
		}},
		{"wrong PNG signature", func(media *notificationv1.NotificationMedia) {
			media.EncodedBytes[0] = 0
			media.ContentSha256 = decodeTestHex("ba2e8d793c4a70da5038eee527b1fc383247bd2a1b01e5c34499097ee70f7358")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := valid()
			test.change(payload.GetNotificationUpsert().GetAppIcon())
			if _, err := Encode(payload); err == nil {
				t.Fatal("invalid notification media accepted")
			}
		})
	}
}

func decodeTestHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
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
		{"schema v1", func(p *notificationv1.EncryptedPayload) { p.SchemaVersion = 1 }},
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
	ack.SchemaVersion = 1
	if _, err := Encode(ack); err == nil {
		t.Fatal("identity lifecycle body accepted under schema v1")
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
		{"missing action id", func(a *notificationv1.ActionInvoke) { a.ActionId = nil }},
		{"dismiss with action", func(a *notificationv1.ActionInvoke) { a.DismissNotification = true }},
		{"dismiss with reply", func(a *notificationv1.ActionInvoke) {
			a.DismissNotification = true
			a.ActionId = nil
		}},
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
