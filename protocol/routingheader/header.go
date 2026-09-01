// Package routingheader implements the fixed-width Routing Header v1 AAD codec.
package routingheader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	EncodedSize          = 160
	SuiteID       uint16 = 1
	MaxTTLMillis  uint64 = 24 * 60 * 60 * 1000
	maxSafeMillis        = 1<<53 - 1
)

var magic = [4]byte{'S', 'N', 'H', '1'}

// Header is routing metadata visible to the relay and authenticated as HPKE AAD.
type Header struct {
	WorkspaceID       [16]byte
	SenderDeviceID    [16]byte
	RecipientDeviceID [16]byte
	SenderKeyID       [32]byte
	RecipientKeyID    [32]byte
	MessageID         [16]byte
	Sequence          uint64
	CreatedAtUnixMs   uint64
	ExpiresAtUnixMs   uint64
}

// Encode validates and serializes a header to its sole canonical representation.
func Encode(header Header) ([EncodedSize]byte, error) {
	var encoded [EncodedSize]byte
	if err := Validate(header); err != nil {
		return encoded, err
	}

	copy(encoded[0:4], magic[:])
	binary.BigEndian.PutUint16(encoded[4:6], SuiteID)
	binary.BigEndian.PutUint16(encoded[6:8], 0)
	copy(encoded[8:24], header.WorkspaceID[:])
	copy(encoded[24:40], header.SenderDeviceID[:])
	copy(encoded[40:56], header.RecipientDeviceID[:])
	copy(encoded[56:88], header.SenderKeyID[:])
	copy(encoded[88:120], header.RecipientKeyID[:])
	copy(encoded[120:136], header.MessageID[:])
	binary.BigEndian.PutUint64(encoded[136:144], header.Sequence)
	binary.BigEndian.PutUint64(encoded[144:152], header.CreatedAtUnixMs)
	binary.BigEndian.PutUint64(encoded[152:160], header.ExpiresAtUnixMs)
	return encoded, nil
}

// Decode validates and parses exact original AAD bytes. Callers must retain and
// authenticate the input bytes; decoded fields are not a replacement for AAD.
func Decode(encoded []byte) (Header, error) {
	var header Header
	if len(encoded) != EncodedSize {
		return header, fmt.Errorf("routing header must be %d bytes", EncodedSize)
	}
	if !bytes.Equal(encoded[0:4], magic[:]) {
		return header, errors.New("unsupported routing header magic/version")
	}
	if binary.BigEndian.Uint16(encoded[4:6]) != SuiteID {
		return header, errors.New("unsupported E2EE suite")
	}
	if binary.BigEndian.Uint16(encoded[6:8]) != 0 {
		return header, errors.New("reserved routing flags must be zero")
	}

	copy(header.WorkspaceID[:], encoded[8:24])
	copy(header.SenderDeviceID[:], encoded[24:40])
	copy(header.RecipientDeviceID[:], encoded[40:56])
	copy(header.SenderKeyID[:], encoded[56:88])
	copy(header.RecipientKeyID[:], encoded[88:120])
	copy(header.MessageID[:], encoded[120:136])
	header.Sequence = binary.BigEndian.Uint64(encoded[136:144])
	header.CreatedAtUnixMs = binary.BigEndian.Uint64(encoded[144:152])
	header.ExpiresAtUnixMs = binary.BigEndian.Uint64(encoded[152:160])
	if err := Validate(header); err != nil {
		return Header{}, err
	}
	return header, nil
}

// Validate enforces the cross-platform v1 structural limits.
func Validate(header Header) error {
	if allZero(header.WorkspaceID[:]) {
		return errors.New("workspace ID must not be zero")
	}
	if allZero(header.SenderDeviceID[:]) {
		return errors.New("sender device ID must not be zero")
	}
	if allZero(header.RecipientDeviceID[:]) {
		return errors.New("recipient device ID must not be zero")
	}
	if allZero(header.SenderKeyID[:]) {
		return errors.New("sender key ID must not be zero")
	}
	if allZero(header.RecipientKeyID[:]) {
		return errors.New("recipient key ID must not be zero")
	}
	if allZero(header.MessageID[:]) {
		return errors.New("message ID must not be zero")
	}
	if header.Sequence == 0 || header.Sequence > math.MaxInt64 {
		return errors.New("sequence must be in 1..2^63-1")
	}
	if header.CreatedAtUnixMs > maxSafeMillis || header.ExpiresAtUnixMs > maxSafeMillis {
		return errors.New("timestamps must be in 0..2^53-1")
	}
	if header.ExpiresAtUnixMs <= header.CreatedAtUnixMs {
		return errors.New("expiry must be greater than creation time")
	}
	if header.ExpiresAtUnixMs-header.CreatedAtUnixMs > MaxTTLMillis {
		return errors.New("routing header TTL exceeds 24 hours")
	}
	return nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
