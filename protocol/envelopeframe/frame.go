// Package envelopeframe implements Encrypted Envelope v1 transport framing.
package envelopeframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/huaxianyan/SyncNotifications-Server/protocol/routingheader"
)

const (
	PrefixSize        = 233
	EncapsulatedSize  = 65
	MinCiphertextSize = 16
	MaxCiphertextSize = 512 * 1024
	MinFrameSize      = PrefixSize + MinCiphertextSize
	MaxFrameSize      = PrefixSize + MaxCiphertextSize
)

var magic = [4]byte{'S', 'N', 'E', '1'}

// Frame is one recipient-specific encrypted transport message.
type Frame struct {
	RoutingHeader   [routingheader.EncodedSize]byte
	EncapsulatedKey [EncapsulatedSize]byte
	Ciphertext      []byte
}

// Encode validates and serializes a frame.
func Encode(frame Frame) ([]byte, error) {
	if err := Validate(frame); err != nil {
		return nil, err
	}
	encoded := make([]byte, PrefixSize+len(frame.Ciphertext))
	copy(encoded[0:4], magic[:])
	copy(encoded[4:164], frame.RoutingHeader[:])
	copy(encoded[164:229], frame.EncapsulatedKey[:])
	binary.BigEndian.PutUint32(encoded[229:233], uint32(len(frame.Ciphertext)))
	copy(encoded[233:], frame.Ciphertext)
	return encoded, nil
}

// Decode strictly parses a complete binary WebSocket frame and copies all data.
func Decode(encoded []byte) (Frame, error) {
	var frame Frame
	if len(encoded) < MinFrameSize || len(encoded) > MaxFrameSize {
		return frame, fmt.Errorf("encrypted envelope must be %d..%d bytes", MinFrameSize, MaxFrameSize)
	}
	if !bytes.Equal(encoded[0:4], magic[:]) {
		return frame, errors.New("unsupported encrypted envelope magic/version")
	}
	ciphertextSize := int(binary.BigEndian.Uint32(encoded[229:233]))
	if ciphertextSize < MinCiphertextSize || ciphertextSize > MaxCiphertextSize {
		return frame, errors.New("ciphertext length is out of range")
	}
	if len(encoded) != PrefixSize+ciphertextSize {
		return frame, errors.New("encrypted envelope length does not match ciphertext length")
	}

	copy(frame.RoutingHeader[:], encoded[4:164])
	copy(frame.EncapsulatedKey[:], encoded[164:229])
	frame.Ciphertext = append([]byte(nil), encoded[233:]...)
	if err := Validate(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// Validate applies all structural limits without attempting decryption.
func Validate(frame Frame) error {
	if _, err := routingheader.Decode(frame.RoutingHeader[:]); err != nil {
		return fmt.Errorf("invalid routing header: %w", err)
	}
	if frame.EncapsulatedKey[0] != 0x04 {
		return errors.New("encapsulated key must be an uncompressed P-256 point")
	}
	if len(frame.Ciphertext) < MinCiphertextSize || len(frame.Ciphertext) > MaxCiphertextSize {
		return errors.New("ciphertext length is out of range")
	}
	return nil
}
