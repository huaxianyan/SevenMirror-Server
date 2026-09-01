package envelopeframe

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	RoutingHeader   string `json:"routingHeader"`
	EncapsulatedKey string `json:"encapsulatedKey"`
	Ciphertext      string `json:"ciphertext"`
	FrameHex        string `json:"frameHex"`
}

func TestCanonicalVector(t *testing.T) {
	fixture := loadVector(t)
	var frame Frame
	copy(frame.RoutingHeader[:], decodeHex(t, fixture.RoutingHeader))
	copy(frame.EncapsulatedKey[:], decodeHex(t, fixture.EncapsulatedKey))
	frame.Ciphertext = decodeHex(t, fixture.Ciphertext)

	encoded, err := Encode(frame)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got := hex.EncodeToString(encoded); got != fixture.FrameHex {
		t.Fatalf("encoded frame mismatch\ngot  %s\nwant %s", got, fixture.FrameHex)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got := hex.EncodeToString(decoded.Ciphertext); got != fixture.Ciphertext {
		t.Fatalf("decoded ciphertext mismatch: %s", got)
	}
}

func TestDecodeRejectsMalformedFrames(t *testing.T) {
	valid := decodeHex(t, loadVector(t).FrameHex)
	invalid := [][]byte{
		append([]byte(nil), valid[:len(valid)-1]...),
		append(append([]byte(nil), valid...), 0),
		append([]byte(nil), valid...),
		append([]byte(nil), valid...),
	}
	invalid[2][0] = 0
	invalid[3][164] = 3
	for _, frame := range invalid {
		if _, err := Decode(frame); err == nil {
			t.Fatal("Decode() unexpectedly accepted malformed frame")
		}
	}
}

func loadVector(t *testing.T) vector {
	t.Helper()
	content, err := os.ReadFile("../test-vectors/encrypted-envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture vector
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
