package payloadcodec

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	notificationv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/notification/v1"
	"google.golang.org/protobuf/proto"
)

const (
	SchemaVersion           = 1
	MaxPlaintextSize        = 524272
	MaxNotificationIDBytes  = 512
	MaxReplyTextBytes       = 4000
	MaxResultDetailBytes    = 256
	IdentifierSize          = 16
	SHA256Size              = 32
	MaxNotificationRevision = uint64(1<<63 - 1)
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
	if payload.GetSchemaVersion() != SchemaVersion {
		return errors.New("unsupported encrypted payload schema version")
	}
	switch body := payload.GetBody().(type) {
	case *notificationv1.EncryptedPayload_ActionInvoke:
		return validateActionInvoke(body.ActionInvoke)
	case *notificationv1.EncryptedPayload_ActionResult:
		return validateActionResult(body.ActionResult)
	case *notificationv1.EncryptedPayload_ActionResultAck:
		return validateActionResultAck(body.ActionResultAck)
	default:
		return errors.New("exactly one supported encrypted payload body is required")
	}
}

func validateActionInvoke(action *notificationv1.ActionInvoke) error {
	if len(action.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("action invocation contains unknown fields")
	}
	if !utf8.ValidString(action.GetNotificationId()) || len(action.GetNotificationId()) < 1 || len(action.GetNotificationId()) > MaxNotificationIDBytes {
		return errors.New("notification id must be valid UTF-8 within size limit")
	}
	if action.GetNotificationRevision() < 1 || action.GetNotificationRevision() > MaxNotificationRevision {
		return errors.New("notification revision is out of range")
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

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
