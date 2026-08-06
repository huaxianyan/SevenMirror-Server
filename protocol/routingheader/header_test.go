package routingheader

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

type vector struct {
	WorkspaceID       string `json:"workspaceId"`
	SenderDeviceID    string `json:"senderDeviceId"`
	RecipientDeviceID string `json:"recipientDeviceId"`
	SenderKeyID       string `json:"senderKeyId"`
	RecipientKeyID    string `json:"recipientKeyId"`
	MessageID         string `json:"messageId"`
	Sequence          string `json:"sequence"`
	CreatedAtUnixMs   uint64 `json:"createdAtUnixMs"`
	ExpiresAtUnixMs   uint64 `json:"expiresAtUnixMs"`
	HeaderHex         string `json:"headerHex"`
}

func TestCanonicalVector(t *testing.T) {
	fixture := loadVector(t)
	sequence, err := strconv.ParseUint(fixture.Sequence, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	header := Header{
		WorkspaceID:       decode16(t, fixture.WorkspaceID),
		SenderDeviceID:    decode16(t, fixture.SenderDeviceID),
		RecipientDeviceID: decode16(t, fixture.RecipientDeviceID),
		SenderKeyID:       decode32(t, fixture.SenderKeyID),
		RecipientKeyID:    decode32(t, fixture.RecipientKeyID),
		MessageID:         decode16(t, fixture.MessageID),
		Sequence:          sequence,
		CreatedAtUnixMs:   fixture.CreatedAtUnixMs,
		ExpiresAtUnixMs:   fixture.ExpiresAtUnixMs,
	}

	encoded, err := Encode(header)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got := hex.EncodeToString(encoded[:]); got != fixture.HeaderHex {
		t.Fatalf("encoded header mismatch\ngot  %s\nwant %s", got, fixture.HeaderHex)
	}
	decoded, err := Decode(encoded[:])
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded != header {
		t.Fatalf("decoded header mismatch\ngot  %#v\nwant %#v", decoded, header)
	}
}

func TestDecodeRejectsInvalidHeaders(t *testing.T) {
	fixture := loadVector(t)
	valid, err := hex.DecodeString(fixture.HeaderHex)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func([]byte) []byte{
		"length":                 func(value []byte) []byte { return value[:len(value)-1] },
		"magic":                  func(value []byte) []byte { value[0] ^= 0xff; return value },
		"suite":                  func(value []byte) []byte { value[5] = 2; return value },
		"flags":                  func(value []byte) []byte { value[7] = 1; return value },
		"zero ID":                func(value []byte) []byte { clear(value[8:24]); return value },
		"zero sequence":          func(value []byte) []byte { clear(value[136:144]); return value },
		"expiry before creation": func(value []byte) []byte { copy(value[152:160], value[144:152]); return value },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := mutate(append([]byte(nil), valid...))
			if _, err := Decode(input); err == nil {
				t.Fatal("Decode() unexpectedly accepted invalid header")
			}
		})
	}
}

func loadVector(t *testing.T) vector {
	t.Helper()
	content, err := os.ReadFile("../test-vectors/routing-header-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture vector
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decode16(t *testing.T, value string) [16]byte {
	t.Helper()
	decoded := decodeHex(t, value, 16)
	var result [16]byte
	copy(result[:], decoded)
	return result
}

func decode32(t *testing.T, value string) [32]byte {
	t.Helper()
	decoded := decodeHex(t, value, 32)
	var result [32]byte
	copy(result[:], decoded)
	return result
}

func decodeHex(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != size {
		t.Fatalf("decoded length = %d, want %d", len(decoded), size)
	}
	return decoded
}
