// Package relaydelivery implements the fixed Relay Delivery v1 transport controls.
package relaydelivery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
)

const (
	ControlSize          = 12
	DeliveryPrefixSize   = 12
	SubmissionPrefixSize = 4
	MaxClientMessageSize = SubmissionPrefixSize + envelopeframe.MaxFrameSize
	MaxServerMessageSize = DeliveryPrefixSize + envelopeframe.MaxFrameSize
)

var (
	durableSubmissionMagic = [4]byte{'S', 'N', 'Q', '1'}
	resumeMagic            = [4]byte{'S', 'N', 'C', '1'}
	ackMagic               = [4]byte{'S', 'N', 'C', '2'}
	deliveryMagic          = [4]byte{'S', 'N', 'D', '1'}
	caughtUpMagic          = [4]byte{'S', 'N', 'D', '2'}
	resetMagic             = [4]byte{'S', 'N', 'R', '1'}
)

type ClientMessageKind int

const (
	ClientEnvelopeOnline ClientMessageKind = iota + 1
	ClientEnvelopeDurable
	ClientResume
	ClientAcknowledge
)

type ClientMessage struct {
	Kind     ClientMessageKind
	Cursor   uint64
	Envelope []byte
}

func DecodeClientMessage(encoded []byte) (ClientMessage, error) {
	if len(encoded) >= envelopeframe.MinFrameSize && bytes.Equal(encoded[:4], []byte("SNE1")) {
		if _, err := envelopeframe.Decode(encoded); err != nil {
			return ClientMessage{}, err
		}
		return ClientMessage{Kind: ClientEnvelopeOnline, Envelope: append([]byte(nil), encoded...)}, nil
	}
	if len(encoded) >= SubmissionPrefixSize+envelopeframe.MinFrameSize &&
		bytes.Equal(encoded[:4], durableSubmissionMagic[:]) {
		envelope := encoded[SubmissionPrefixSize:]
		if _, err := envelopeframe.Decode(envelope); err != nil {
			return ClientMessage{}, fmt.Errorf("invalid durable encrypted envelope: %w", err)
		}
		return ClientMessage{Kind: ClientEnvelopeDurable, Envelope: append([]byte(nil), envelope...)}, nil
	}
	if len(encoded) != ControlSize {
		return ClientMessage{}, errors.New("unsupported relay delivery message")
	}
	cursor := binary.BigEndian.Uint64(encoded[4:12])
	if cursor > math.MaxInt64 {
		return ClientMessage{}, errors.New("relay delivery cursor is out of range")
	}
	switch {
	case bytes.Equal(encoded[:4], resumeMagic[:]):
		return ClientMessage{Kind: ClientResume, Cursor: cursor}, nil
	case bytes.Equal(encoded[:4], ackMagic[:]):
		if cursor == 0 {
			return ClientMessage{}, errors.New("relay delivery acknowledgement must be positive")
		}
		return ClientMessage{Kind: ClientAcknowledge, Cursor: cursor}, nil
	default:
		return ClientMessage{}, errors.New("unsupported relay delivery message")
	}
}

func EncodeDurableSubmission(envelope []byte) ([]byte, error) {
	if _, err := envelopeframe.Decode(envelope); err != nil {
		return nil, err
	}
	encoded := make([]byte, SubmissionPrefixSize+len(envelope))
	copy(encoded[:4], durableSubmissionMagic[:])
	copy(encoded[4:], envelope)
	return encoded, nil
}

func EncodeResume(cursor uint64) ([]byte, error) {
	return encodeControl(resumeMagic, cursor, true)
}

func EncodeAcknowledgement(cursor uint64) ([]byte, error) {
	return encodeControl(ackMagic, cursor, false)
}

func EncodeDelivery(deliveryID uint64, envelope []byte) ([]byte, error) {
	if deliveryID == 0 || deliveryID > math.MaxInt64 {
		return nil, errors.New("delivery ID must be in 1..2^63-1")
	}
	if _, err := envelopeframe.Decode(envelope); err != nil {
		return nil, err
	}
	encoded := make([]byte, DeliveryPrefixSize+len(envelope))
	copy(encoded[:4], deliveryMagic[:])
	binary.BigEndian.PutUint64(encoded[4:12], deliveryID)
	copy(encoded[12:], envelope)
	return encoded, nil
}

func EncodeCaughtUp(highWater uint64) ([]byte, error) {
	return encodeControl(caughtUpMagic, highWater, true)
}

func EncodeResetRequired(highWater uint64) ([]byte, error) {
	return encodeControl(resetMagic, highWater, true)
}

func encodeControl(magic [4]byte, cursor uint64, allowZero bool) ([]byte, error) {
	if cursor > math.MaxInt64 || (!allowZero && cursor == 0) {
		return nil, errors.New("relay delivery cursor is out of range")
	}
	encoded := make([]byte, ControlSize)
	copy(encoded[:4], magic[:])
	binary.BigEndian.PutUint64(encoded[4:12], cursor)
	return encoded, nil
}
