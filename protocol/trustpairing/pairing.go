package trustpairing

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	OfferSize    = 133
	ApprovalSize = 149
	MaxTTLMillis = uint64(10 * 60 * 1000)
	QRPrefix     = "sntrust1:"
	safetyDomain = "SyncNotifications-Trust-SAS-v1"
	crockford    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var (
	offerMagic    = [4]byte{'S', 'N', 'T', '1'}
	approvalMagic = [4]byte{'S', 'N', 'T', '2'}
)

type Offer struct {
	WorkspaceID [16]byte
	DeviceID    [16]byte
	PublicKey   [65]byte
	Nonce       [16]byte
	CreatedAtMS uint64
	ExpiresAtMS uint64
}

type Approval struct {
	OfferHash   [32]byte
	DeviceID    [16]byte
	PublicKey   [65]byte
	Nonce       [16]byte
	CreatedAtMS uint64
	ExpiresAtMS uint64
}

func EncodeOffer(value Offer) ([]byte, error) {
	if err := validateOffer(value); err != nil {
		return nil, err
	}
	encoded := make([]byte, OfferSize)
	copy(encoded[0:4], offerMagic[:])
	copy(encoded[4:20], value.WorkspaceID[:])
	copy(encoded[20:36], value.DeviceID[:])
	copy(encoded[36:101], value.PublicKey[:])
	copy(encoded[101:117], value.Nonce[:])
	binary.BigEndian.PutUint64(encoded[117:125], value.CreatedAtMS)
	binary.BigEndian.PutUint64(encoded[125:133], value.ExpiresAtMS)
	return encoded, nil
}

func DecodeOffer(encoded []byte) (Offer, error) {
	var value Offer
	if len(encoded) != OfferSize {
		return value, errors.New("trust offer must be 133 bytes")
	}
	if string(encoded[:4]) != string(offerMagic[:]) {
		return value, errors.New("unsupported trust offer magic/version")
	}
	copy(value.WorkspaceID[:], encoded[4:20])
	copy(value.DeviceID[:], encoded[20:36])
	copy(value.PublicKey[:], encoded[36:101])
	copy(value.Nonce[:], encoded[101:117])
	value.CreatedAtMS = binary.BigEndian.Uint64(encoded[117:125])
	value.ExpiresAtMS = binary.BigEndian.Uint64(encoded[125:133])
	return value, validateOffer(value)
}

func EncodeApproval(value Approval) ([]byte, error) {
	if err := validateApproval(value); err != nil {
		return nil, err
	}
	encoded := make([]byte, ApprovalSize)
	copy(encoded[0:4], approvalMagic[:])
	copy(encoded[4:36], value.OfferHash[:])
	copy(encoded[36:52], value.DeviceID[:])
	copy(encoded[52:117], value.PublicKey[:])
	copy(encoded[117:133], value.Nonce[:])
	binary.BigEndian.PutUint64(encoded[133:141], value.CreatedAtMS)
	binary.BigEndian.PutUint64(encoded[141:149], value.ExpiresAtMS)
	return encoded, nil
}

func DecodeApproval(encoded []byte) (Approval, error) {
	var value Approval
	if len(encoded) != ApprovalSize {
		return value, errors.New("trust approval must be 149 bytes")
	}
	if string(encoded[:4]) != string(approvalMagic[:]) {
		return value, errors.New("unsupported trust approval magic/version")
	}
	copy(value.OfferHash[:], encoded[4:36])
	copy(value.DeviceID[:], encoded[36:52])
	copy(value.PublicKey[:], encoded[52:117])
	copy(value.Nonce[:], encoded[117:133])
	value.CreatedAtMS = binary.BigEndian.Uint64(encoded[133:141])
	value.ExpiresAtMS = binary.BigEndian.Uint64(encoded[141:149])
	return value, validateApproval(value)
}

func EncodeQR(record []byte) (string, error) {
	if _, err := decodeRecord(record); err != nil {
		return "", err
	}
	return QRPrefix + base64.RawURLEncoding.EncodeToString(record), nil
}

func DecodeQR(text string) ([]byte, error) {
	if !strings.HasPrefix(text, QRPrefix) || strings.TrimSpace(text) != text {
		return nil, errors.New("trust QR prefix or whitespace is invalid")
	}
	body := strings.TrimPrefix(text, QRPrefix)
	if body == "" || strings.Contains(body, "=") {
		return nil, errors.New("trust QR base64url is not canonical")
	}
	record, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("trust QR base64url is invalid")
	}
	if base64.RawURLEncoding.EncodeToString(record) != body {
		return nil, errors.New("trust QR base64url is not canonical")
	}
	if _, err := decodeRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

func ValidatePair(offerBytes, approvalBytes []byte) error {
	offer, err := DecodeOffer(offerBytes)
	if err != nil {
		return err
	}
	approval, err := DecodeApproval(approvalBytes)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(offerBytes)
	if hash != approval.OfferHash {
		return errors.New("approval does not bind the exact trust offer")
	}
	if approval.ExpiresAtMS > offer.ExpiresAtMS {
		return errors.New("approval expiry exceeds offer expiry")
	}
	if offer.DeviceID == approval.DeviceID {
		return errors.New("offerer and approver device IDs must differ")
	}
	if offer.PublicKey == approval.PublicKey {
		return errors.New("offerer and approver public keys must differ")
	}
	return nil
}

func SafetyCode(offerBytes, approvalBytes []byte) (string, error) {
	if err := ValidatePair(offerBytes, approvalBytes); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(safetyDomain))
	h.Write(offerBytes)
	h.Write(approvalBytes)
	digest := h.Sum(nil)
	var output [12]byte
	for i := range output {
		bit := i * 5
		byteIndex := bit / 8
		shift := 11 - (bit % 8)
		var pair uint16 = uint16(digest[byteIndex]) << 8
		if byteIndex+1 < len(digest) {
			pair |= uint16(digest[byteIndex+1])
		}
		output[i] = crockford[(pair>>shift)&31]
	}
	return string(output[0:4]) + "-" + string(output[4:8]) + "-" + string(output[8:12]), nil
}

func decodeRecord(record []byte) (any, error) {
	if len(record) < 4 {
		return nil, errors.New("trust record is truncated")
	}
	switch string(record[:4]) {
	case string(offerMagic[:]):
		return DecodeOffer(record)
	case string(approvalMagic[:]):
		return DecodeApproval(record)
	default:
		return nil, errors.New("unsupported trust record magic/version")
	}
}

func validateOffer(value Offer) error {
	if allZero(value.WorkspaceID[:]) || allZero(value.DeviceID[:]) || allZero(value.Nonce[:]) {
		return errors.New("trust offer IDs and nonce must be non-zero")
	}
	if err := validatePublicKey(value.PublicKey[:]); err != nil {
		return err
	}
	return validateTTL(value.CreatedAtMS, value.ExpiresAtMS)
}
func validateApproval(value Approval) error {
	if allZero(value.OfferHash[:]) || allZero(value.DeviceID[:]) || allZero(value.Nonce[:]) {
		return errors.New("trust approval hash, device ID, and nonce must be non-zero")
	}
	if err := validatePublicKey(value.PublicKey[:]); err != nil {
		return err
	}
	return validateTTL(value.CreatedAtMS, value.ExpiresAtMS)
}
func validateTTL(created, expires uint64) error {
	if expires <= created || expires-created > MaxTTLMillis {
		return errors.New("trust record TTL must be in (0, 10 minutes]")
	}
	return nil
}
func validatePublicKey(value []byte) error {
	if len(value) != 65 || value[0] != 4 {
		return errors.New("trust public key must be an uncompressed P-256 point")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), value)
	if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
		return errors.New("trust public key is not a valid P-256 point")
	}
	if !equal(elliptic.Marshal(elliptic.P256(), x, y), value) {
		return errors.New("trust public key is not canonical")
	}
	return nil
}
func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
