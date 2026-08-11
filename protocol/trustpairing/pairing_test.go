package trustpairing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	WorkspaceID string `json:"workspaceId"`
	Offer       struct {
		DeviceID, PublicKey, Nonce, Encoded, QR string
		CreatedAtUnixMS, ExpiresAtUnixMS        uint64
	} `json:"offer"`
	Approval struct {
		OfferSHA256                             string `json:"offerSha256"`
		DeviceID, PublicKey, Nonce, Encoded, QR string
		CreatedAtUnixMS, ExpiresAtUnixMS        uint64
	} `json:"approval"`
	SafetyCode string `json:"safetyCode"`
}

func TestCanonicalVector(t *testing.T) {
	v := loadVector(t)
	offer := Offer{CreatedAtMS: v.Offer.CreatedAtUnixMS, ExpiresAtMS: v.Offer.ExpiresAtUnixMS}
	copyHex(t, offer.WorkspaceID[:], v.WorkspaceID)
	copyHex(t, offer.DeviceID[:], v.Offer.DeviceID)
	copyHex(t, offer.PublicKey[:], v.Offer.PublicKey)
	copyHex(t, offer.Nonce[:], v.Offer.Nonce)
	offerBytes, err := EncodeOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(offerBytes) != v.Offer.Encoded {
		t.Fatal("offer vector mismatch")
	}
	approval := Approval{CreatedAtMS: v.Approval.CreatedAtUnixMS, ExpiresAtMS: v.Approval.ExpiresAtUnixMS}
	copyHex(t, approval.OfferHash[:], v.Approval.OfferSHA256)
	copyHex(t, approval.DeviceID[:], v.Approval.DeviceID)
	copyHex(t, approval.PublicKey[:], v.Approval.PublicKey)
	copyHex(t, approval.Nonce[:], v.Approval.Nonce)
	approvalBytes, err := EncodeApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(approvalBytes) != v.Approval.Encoded {
		t.Fatal("approval vector mismatch")
	}
	if qr, _ := EncodeQR(offerBytes); qr != v.Offer.QR {
		t.Fatal("offer QR mismatch")
	}
	if qr, _ := EncodeQR(approvalBytes); qr != v.Approval.QR {
		t.Fatal("approval QR mismatch")
	}
	if decoded, err := DecodeQR(v.Offer.QR); err != nil || !equal(decoded, offerBytes) {
		t.Fatalf("offer QR decode: %v", err)
	}
	if code, err := SafetyCode(offerBytes, approvalBytes); err != nil || code != v.SafetyCode {
		t.Fatalf("safety code %q: %v", code, err)
	}
}

func TestRejectsMutationAndNonCanonicalQR(t *testing.T) {
	v := loadVector(t)
	offer, _ := hex.DecodeString(v.Offer.Encoded)
	approval, _ := hex.DecodeString(v.Approval.Encoded)
	mutated := append([]byte(nil), offer...)
	mutated[10] ^= 1
	if err := ValidatePair(mutated, approval); err == nil {
		t.Fatal("mutated offer accepted")
	}
	if _, err := DecodeQR(v.Offer.QR + "="); err == nil {
		t.Fatal("padded QR accepted")
	}
	if _, err := DecodeQR(" " + v.Offer.QR); err == nil {
		t.Fatal("whitespace QR accepted")
	}
	badPoint := append([]byte(nil), offer...)
	for i := 36; i < 101; i++ {
		badPoint[i] = 0
	}
	badPoint[36] = 4
	if _, err := DecodeOffer(badPoint); err == nil {
		t.Fatal("invalid P-256 point accepted")
	}
	badApproval := append([]byte(nil), approval...)
	badApproval[4] ^= 1
	if _, err := SafetyCode(offer, badApproval); err == nil {
		t.Fatal("wrong offer hash accepted")
	}
}

func TestVectorFileHash(t *testing.T) {
	contents, err := os.ReadFile("../test-vectors/trusted-device-pairing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(contents)
	const want = "4b428c92adfa42ca30b79bf360657befaf870ccd2fa4028e07f821b39e0999c1"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("vector hash changed: %x", got)
	}
}

func loadVector(t *testing.T) vector {
	t.Helper()
	contents, err := os.ReadFile("../test-vectors/trusted-device-pairing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(contents, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func copyHex(t *testing.T, target []byte, encoded string) {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(target) {
		t.Fatalf("bad vector hex %v", err)
	}
	copy(target, decoded)
}
