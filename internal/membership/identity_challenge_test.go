package membership

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"
	"time"

	"filippo.io/hpke"
	hpkeecdh "filippo.io/hpke/crypto/ecdh"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

func TestIdentityChallengeUsesRFC9180BaseHPKEAndCanonicalBinding(t *testing.T) {
	workspaceID := bytes.Repeat([]byte{0x11}, 16)
	deviceID := bytes.Repeat([]byte{0x22}, 16)
	privateScalar := make([]byte, 32)
	privateScalar[31] = 2
	x, y := elliptic.P256().ScalarBaseMult(privateScalar)
	publicKey := elliptic.Marshal(elliptic.P256(), x, y)
	now := time.UnixMilli(1_800_000_000_000)
	challenge, err := CreateIdentityChallenge(workspaceID, deviceID, publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(challenge.Secret[:])
	defer clear(challenge.CanonicalPlaintext)
	identityKeyID := sha256.Sum256(publicKey)
	info, err := membershipcodec.PossessionHPKEInfo(workspaceID, deviceID, identityKeyID[:])
	if err != nil {
		t.Fatal(err)
	}
	kem := hpke.DHKEM(hpkeecdh.P256())
	privateKey, err := kem.NewPrivateKey(privateScalar)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(
		challenge.EncapsulatedKey, privateKey, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(nil, challenge.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if !bytes.Equal(plaintext, challenge.CanonicalPlaintext) {
		t.Fatal("opened challenge differs from canonical plaintext")
	}
	decoded, err := membershipcodec.DecodeIdentityPossessionChallenge(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetChallengeSecret(), challenge.Secret[:]) ||
		decoded.GetExpiresAtUnixMs()-decoded.GetIssuedAtUnixMs() != uint64(IdentityChallengeLifetime/time.Millisecond) {
		t.Fatal("opened challenge binding or lifetime changed")
	}
	digest, err := membershipcodec.ChallengeDigest(decoded)
	if err != nil || digest != challenge.Digest {
		t.Fatalf("challenge digest=%x error=%v", digest, err)
	}
}
