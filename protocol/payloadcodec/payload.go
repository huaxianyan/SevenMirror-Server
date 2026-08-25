package payloadcodec

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	notificationv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/notification/v1"
	"google.golang.org/protobuf/proto"
)

const (
	SchemaVersion                   = 1
	IdentityLifecycleSchemaVersion  = 2
	NotificationSchemaVersion       = 5
	MaxPlaintextSize                = 524272
	MaxNotificationIDBytes          = 512
	MaxNotificationTitleBytes       = 512
	MaxNotificationBodyBytes        = 4000
	MaxNotificationActions          = 16
	MaxNotificationActionTitleBytes = 256
	MaxNotificationMediaBytes       = 128 * 1024
	MaxNotificationMediaDimension   = 256
	MaxSnapshotEntries              = 200
	MaxReplyTextBytes               = 4000
	MaxResultDetailBytes            = 256
	IdentifierSize                  = 16
	SHA256Size                      = 32
	P256PublicKeySize               = 65
	MaxNotificationRevision         = uint64(1<<63 - 1)
)

var deterministic = proto.MarshalOptions{Deterministic: true}

func Encode(payload *notificationv1.EncryptedPayload) ([]byte, error) {
	if err := Validate(payload); err != nil {
		return nil, err
	}
	encoded, err := deterministic.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted payload: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxPlaintextSize {
		return nil, errors.New("encrypted payload size is out of range")
	}
	return encoded, nil
}

func Decode(encoded []byte) (*notificationv1.EncryptedPayload, error) {
	if len(encoded) == 0 || len(encoded) > MaxPlaintextSize {
		return nil, errors.New("encrypted payload size is out of range")
	}
	payload := &notificationv1.EncryptedPayload{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(encoded, payload); err != nil {
		return nil, fmt.Errorf("decode encrypted payload: %w", err)
	}
	if err := Validate(payload); err != nil {
		return nil, err
	}
	canonical, err := deterministic.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("re-encode encrypted payload: %w", err)
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, errors.New("encrypted payload is not canonically encoded")
	}
	return payload, nil
}

func Validate(payload *notificationv1.EncryptedPayload) error {
	if payload == nil {
		return errors.New("encrypted payload is required")
	}
	if len(payload.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("encrypted payload contains unknown fields")
	}
	switch body := payload.GetBody().(type) {
	case *notificationv1.EncryptedPayload_ActionInvoke:
		return validateSchema(payload, SchemaVersion, validateActionInvoke(body.ActionInvoke))
	case *notificationv1.EncryptedPayload_ActionResult:
		return validateSchema(payload, SchemaVersion, validateActionResult(body.ActionResult))
	case *notificationv1.EncryptedPayload_ActionResultAck:
		return validateSchema(payload, SchemaVersion, validateActionResultAck(body.ActionResultAck))
	case *notificationv1.EncryptedPayload_IdentityKeyTransition:
		return validateSchema(payload, IdentityLifecycleSchemaVersion, validateIdentityKeyTransition(body.IdentityKeyTransition))
	case *notificationv1.EncryptedPayload_IdentityKeyTransitionAck:
		return validateSchema(payload, IdentityLifecycleSchemaVersion, validateIdentityKeyTransitionAck(body.IdentityKeyTransitionAck))
	case *notificationv1.EncryptedPayload_IdentityKeyTransitionCommit:
		return validateSchema(payload, IdentityLifecycleSchemaVersion, validateIdentityKeyTransitionCommit(body.IdentityKeyTransitionCommit))
	case *notificationv1.EncryptedPayload_NotificationUpsert:
		return validateSchema(payload, NotificationSchemaVersion, validateNotificationUpsert(body.NotificationUpsert))
	case *notificationv1.EncryptedPayload_NotificationRemoved:
		return validateSchema(payload, NotificationSchemaVersion, validateNotificationRemoved(body.NotificationRemoved))
	case *notificationv1.EncryptedPayload_NotificationSnapshotManifest:
		return validateSchema(payload, NotificationSchemaVersion, validateNotificationSnapshotManifest(body.NotificationSnapshotManifest))
	default:
		return errors.New("exactly one supported encrypted payload body is required")
	}
}

func validateNotificationUpsert(notification *notificationv1.NotificationUpsert) error {
	if notification == nil || len(notification.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("notification upsert contains unknown fields")
	}
	if err := validateNotificationBinding(notification.GetNotificationId(), notification.GetNotificationRevision()); err != nil {
		return err
	}
	if notification.Title == nil && notification.Body == nil {
		return errors.New("notification upsert requires title or body")
	}
	if notification.Title != nil {
		title := notification.GetTitle()
		if !utf8.ValidString(title) || len(title) < 1 || len(title) > MaxNotificationTitleBytes {
			return errors.New("notification title must be valid UTF-8 within size limit")
		}
	}
	if notification.Body != nil {
		body := notification.GetBody()
		if !utf8.ValidString(body) || len(body) < 1 || len(body) > MaxNotificationBodyBytes {
			return errors.New("notification body must be valid UTF-8 within size limit")
		}
	}
	if notification.GetContainsContentImage() &&
		(notification.Body == nil || !strings.Contains(notification.GetBody(), "[图片]")) {
		return errors.New("notification content image requires a body placeholder")
	}
	if notification.AppIcon != nil {
		if err := validateNotificationMedia(notification.AppIcon); err != nil {
			return fmt.Errorf("notification app icon: %w", err)
		}
	}
	if notification.Avatar != nil {
		if err := validateNotificationMedia(notification.Avatar); err != nil {
			return fmt.Errorf("notification avatar: %w", err)
		}
	}
	if len(notification.GetActions()) > MaxNotificationActions {
		return errors.New("notification has too many actions")
	}
	actionIDs := make(map[string]struct{}, len(notification.GetActions()))
	for _, action := range notification.GetActions() {
		if err := validateNotificationActionDescriptor(action); err != nil {
			return err
		}
		key := string(action.GetActionId())
		if _, exists := actionIDs[key]; exists {
			return errors.New("notification action ids must be unique")
		}
		actionIDs[key] = struct{}{}
	}
	return nil
}

func validateNotificationActionDescriptor(action *notificationv1.NotificationActionDescriptor) error {
	if action == nil || len(action.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("notification action contains unknown fields")
	}
	if len(action.GetActionId()) != IdentifierSize {
		return errors.New("notification action id must be 16 bytes")
	}
	title := action.GetTitle()
	if !utf8.ValidString(title) || len(title) < 1 || len(title) > MaxNotificationActionTitleBytes {
		return errors.New("notification action title must be valid UTF-8 within size limit")
	}
	if action.GetAllowsFreeFormInput() && !action.GetRequiresTextInput() {
		return errors.New("notification action cannot allow text without requiring text input")
	}
	return nil
}

func validateNotificationMedia(media *notificationv1.NotificationMedia) error {
	if media == nil || len(media.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("media contains unknown fields")
	}
	encoded := media.GetEncodedBytes()
	if len(encoded) < 1 || len(encoded) > MaxNotificationMediaBytes {
		return errors.New("media bytes are out of range")
	}
	if media.GetWidth() < 1 || media.GetWidth() > MaxNotificationMediaDimension ||
		media.GetHeight() < 1 || media.GetHeight() > MaxNotificationMediaDimension {
		return errors.New("media dimensions are out of range")
	}
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(media.GetContentSha256(), digest[:]) {
		return errors.New("media content digest does not match encoded bytes")
	}
	switch media.GetMimeType() {
	case notificationv1.NotificationMediaMimeType_NOTIFICATION_MEDIA_MIME_TYPE_PNG:
		if len(encoded) < len(pngSignature) || string(encoded[:len(pngSignature)]) != pngSignature {
			return errors.New("media bytes do not have a PNG signature")
		}
	case notificationv1.NotificationMediaMimeType_NOTIFICATION_MEDIA_MIME_TYPE_WEBP:
		if len(encoded) < 12 || !bytes.Equal(encoded[:4], []byte("RIFF")) ||
			!bytes.Equal(encoded[8:12], []byte("WEBP")) {
			return errors.New("media bytes do not have a WebP signature")
		}
	default:
		return errors.New("media MIME type is unsupported")
	}
	return nil
}

const pngSignature = "\x89PNG\r\n\x1a\n"

func validateNotificationRemoved(notification *notificationv1.NotificationRemoved) error {
	if notification == nil || len(notification.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("notification removed contains unknown fields")
	}
	return validateNotificationBinding(notification.GetNotificationId(), notification.GetNotificationRevision())
}

func validateNotificationSnapshotManifest(manifest *notificationv1.NotificationSnapshotManifest) error {
	if manifest == nil || len(manifest.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("notification snapshot manifest contains unknown fields")
	}
	if manifest.GetHighWaterRevision() > MaxNotificationRevision {
		return errors.New("notification snapshot high-water revision is out of range")
	}
	entries := manifest.GetActiveNotifications()
	if len(entries) > MaxSnapshotEntries {
		return errors.New("notification snapshot has too many active entries")
	}
	previousID := ""
	for _, entry := range entries {
		if entry == nil || len(entry.ProtoReflect().GetUnknown()) != 0 {
			return errors.New("notification snapshot entry contains unknown fields")
		}
		if err := validateNotificationBinding(entry.GetNotificationId(), entry.GetNotificationRevision()); err != nil {
			return err
		}
		if entry.GetNotificationRevision() > manifest.GetHighWaterRevision() {
			return errors.New("notification snapshot entry exceeds high-water revision")
		}
		if previousID != "" && entry.GetNotificationId() <= previousID {
			return errors.New("notification snapshot entries are not unique and strictly sorted")
		}
		previousID = entry.GetNotificationId()
	}
	return nil
}

func validateNotificationBinding(notificationID string, revision uint64) error {
	if !utf8.ValidString(notificationID) || len(notificationID) < 1 || len(notificationID) > MaxNotificationIDBytes {
		return errors.New("notification id must be valid UTF-8 within size limit")
	}
	if revision < 1 || revision > MaxNotificationRevision {
		return errors.New("notification revision is out of range")
	}
	return nil
}

func validateActionInvoke(action *notificationv1.ActionInvoke) error {
	if len(action.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("action invocation contains unknown fields")
	}
	if err := validateNotificationBinding(action.GetNotificationId(), action.GetNotificationRevision()); err != nil {
		return err
	}
	if len(action.GetActionId()) != IdentifierSize {
		return errors.New("action id must be 16 bytes")
	}
	if len(action.GetIdempotencyKey()) != IdentifierSize || allZero(action.GetIdempotencyKey()) {
		return errors.New("idempotency key must be a non-zero 16-byte value")
	}
	if action.ReplyText != nil {
		reply := action.GetReplyText()
		if !utf8.ValidString(reply) || len(reply) < 1 || len(reply) > MaxReplyTextBytes {
			return errors.New("reply text must be valid UTF-8 within size limit")
		}
	}
	return nil
}

func validateActionResult(result *notificationv1.ActionResult) error {
	if result == nil || len(result.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("action result contains unknown fields")
	}
	if len(result.GetIdempotencyKey()) != IdentifierSize || allZero(result.GetIdempotencyKey()) {
		return errors.New("idempotency key must be a non-zero 16-byte value")
	}
	if result.GetStatus() < notificationv1.ActionResultStatus_ACTION_RESULT_STATUS_SUCCEEDED ||
		result.GetStatus() > notificationv1.ActionResultStatus_ACTION_RESULT_STATUS_OUTCOME_UNKNOWN {
		return errors.New("action result status is unsupported")
	}
	if result.Detail != nil {
		detail := result.GetDetail()
		if !utf8.ValidString(detail) || len(detail) < 1 || len(detail) > MaxResultDetailBytes {
			return errors.New("action result detail must be valid UTF-8 within size limit")
		}
	}
	return nil
}

func validateActionResultAck(ack *notificationv1.ActionResultAck) error {
	if ack == nil || len(ack.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("action result acknowledgement contains unknown fields")
	}
	if len(ack.GetIdempotencyKey()) != IdentifierSize || allZero(ack.GetIdempotencyKey()) {
		return errors.New("idempotency key must be a non-zero 16-byte value")
	}
	if len(ack.GetResultSha256()) != SHA256Size || allZero(ack.GetResultSha256()) {
		return errors.New("result SHA-256 must be a non-zero 32-byte value")
	}
	return nil
}

func validateSchema(payload *notificationv1.EncryptedPayload, expected uint32, bodyError error) error {
	if payload.GetSchemaVersion() != expected {
		return errors.New("encrypted payload schema version does not match body")
	}
	return bodyError
}

func validateIdentityKeyTransition(transition *notificationv1.IdentityKeyTransition) error {
	if transition == nil || len(transition.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("identity key transition contains unknown fields")
	}
	if err := validateTransitionBinding(
		transition.GetTransitionId(),
		transition.GetPreviousKeyId(),
		transition.GetNewKeyId(),
	); err != nil {
		return err
	}
	publicKey := transition.GetNewPublicKey()
	if len(publicKey) != P256PublicKeySize {
		return errors.New("new identity public key must be a 65-byte P-256 point")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil || y == nil {
		return errors.New("new identity public key must be a valid P-256 point")
	}
	digest := sha256.Sum256(publicKey)
	if !bytes.Equal(digest[:], transition.GetNewKeyId()) {
		return errors.New("new identity key id must equal SHA-256 of public key")
	}
	return nil
}

func validateIdentityKeyTransitionAck(ack *notificationv1.IdentityKeyTransitionAck) error {
	if ack == nil || len(ack.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("identity key transition acknowledgement contains unknown fields")
	}
	if err := validateTransitionBinding(ack.GetTransitionId(), ack.GetPreviousKeyId(), ack.GetNewKeyId()); err != nil {
		return err
	}
	if len(ack.GetTransitionSha256()) != SHA256Size || allZero(ack.GetTransitionSha256()) {
		return errors.New("transition SHA-256 must be a non-zero 32-byte value")
	}
	return nil
}

func validateIdentityKeyTransitionCommit(commit *notificationv1.IdentityKeyTransitionCommit) error {
	if commit == nil || len(commit.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("identity key transition commit contains unknown fields")
	}
	if err := validateTransitionBinding(commit.GetTransitionId(), commit.GetPreviousKeyId(), commit.GetNewKeyId()); err != nil {
		return err
	}
	if len(commit.GetTransitionSha256()) != SHA256Size || allZero(commit.GetTransitionSha256()) {
		return errors.New("transition SHA-256 must be a non-zero 32-byte value")
	}
	if len(commit.GetAckSha256()) != SHA256Size || allZero(commit.GetAckSha256()) {
		return errors.New("transition acknowledgement SHA-256 must be a non-zero 32-byte value")
	}
	return nil
}

func validateTransitionBinding(transitionID, previousKeyID, newKeyID []byte) error {
	if len(transitionID) != IdentifierSize || allZero(transitionID) {
		return errors.New("transition id must be a non-zero 16-byte value")
	}
	if len(previousKeyID) != SHA256Size || allZero(previousKeyID) {
		return errors.New("previous identity key id must be a non-zero 32-byte value")
	}
	if len(newKeyID) != SHA256Size || allZero(newKeyID) {
		return errors.New("new identity key id must be a non-zero 32-byte value")
	}
	if bytes.Equal(previousKeyID, newKeyID) {
		return errors.New("new identity key must differ from previous key")
	}
	return nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
