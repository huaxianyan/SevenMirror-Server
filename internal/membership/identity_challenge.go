package membership

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"filippo.io/hpke"
	hpkeecdh "filippo.io/hpke/crypto/ecdh"
	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/membershipcodec"
)

const IdentityChallengeLifetime = 5 * time.Minute

type IdentityChallenge struct {
	CanonicalPlaintext []byte
	Digest             [sha256.Size]byte
	Secret             [sha256.Size]byte
	ExpiresAt          time.Time
	EncapsulatedKey    []byte
	Ciphertext         []byte
}

func CreateIdentityChallenge(
	workspaceID []byte,
	deviceID []byte,
	identityPublicKey []byte,
	now time.Time,
) (IdentityChallenge, error) {
	if now.UnixMilli() <= 0 {
		return IdentityChallenge{}, errors.New("identity challenge time must be positive")
	}
	identityKeyID := sha256.Sum256(identityPublicKey)
	info, err := membershipcodec.PossessionHPKEInfo(workspaceID, deviceID, identityKeyID[:])
	if err != nil {
		return IdentityChallenge{}, err
	}
	var secret [sha256.Size]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IdentityChallenge{}, fmt.Errorf("generate identity challenge secret: %w", err)
	}
	expiresAt := now.Add(IdentityChallengeLifetime)
	challenge := &membershipv1.IdentityPossessionChallenge{
		ProtocolVersion: membershipcodec.ProtocolVersion,
		WorkspaceId:     append([]byte(nil), workspaceID...),
		DeviceId:        append([]byte(nil), deviceID...),
		IdentityKeyId:   identityKeyID[:],
		ChallengeSecret: secret[:],
		IssuedAtUnixMs:  uint64(now.UnixMilli()),
		ExpiresAtUnixMs: uint64(expiresAt.UnixMilli()),
	}
	plaintext, err := membershipcodec.EncodeIdentityPossessionChallenge(challenge)
	if err != nil {
		clear(secret[:])
		return IdentityChallenge{}, err
	}
	digest, err := membershipcodec.ChallengeDigest(challenge)
	if err != nil {
		clear(secret[:])
		return IdentityChallenge{}, err
	}
	kem := hpke.DHKEM(hpkeecdh.P256())
	publicKey, err := kem.NewPublicKey(identityPublicKey)
	if err != nil {
		clear(secret[:])
		return IdentityChallenge{}, fmt.Errorf("parse identity challenge recipient: %w", err)
	}
	encapsulatedKey, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		clear(secret[:])
		return IdentityChallenge{}, fmt.Errorf("create identity challenge sender: %w", err)
	}
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		clear(secret[:])
		return IdentityChallenge{}, fmt.Errorf("seal identity challenge: %w", err)
	}
	return IdentityChallenge{
		CanonicalPlaintext: plaintext,
		Digest:             digest,
		Secret:             secret,
		ExpiresAt:          expiresAt,
		EncapsulatedKey:    append([]byte(nil), encapsulatedKey...),
		Ciphertext:         append([]byte(nil), ciphertext...),
	}, nil
}
