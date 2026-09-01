package membershipcodec

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"google.golang.org/protobuf/proto"
)

type membershipVector struct {
	AuthoritySeedHex                    string `json:"authoritySeedHex"`
	AuthorityPublicKeyHex               string `json:"authorityPublicKeyHex"`
	ChallengeEncodedHex                 string `json:"challengeEncodedHex"`
	ChallengeDigestHex                  string `json:"challengeDigestHex"`
	ProofEncodedHex                     string `json:"proofEncodedHex"`
	CertificateEncodedHex               string `json:"certificateEncodedHex"`
	CertificateIDHex                    string `json:"certificateIdHex"`
	InitialRosterEncodedHex             string `json:"initialRosterEncodedHex"`
	InitialRosterDigestHex              string `json:"initialRosterDigestHex"`
	RevokedRosterEncodedHex             string `json:"revokedRosterEncodedHex"`
	RevokedRosterDigestHex              string `json:"revokedRosterDigestHex"`
	RenamedCertificateEncodedHex        string `json:"renamedCertificateEncodedHex"`
	RenamedCertificateIDHex             string `json:"renamedCertificateIdHex"`
	RenameTransitionEncodedHex          string `json:"renameTransitionEncodedHex"`
	RenameRosterEncodedHex              string `json:"renameRosterEncodedHex"`
	RenameRosterDigestHex               string `json:"renameRosterDigestHex"`
	NewAuthorityPublicKeyHex            string `json:"newAuthorityPublicKeyHex"`
	AuthorityTransitionEncodedHex       string `json:"authorityTransitionEncodedHex"`
	AuthorityTransitionDigestHex        string `json:"authorityTransitionDigestHex"`
	AuthorityActivationRosterEncodedHex string `json:"authorityActivationRosterEncodedHex"`
}

func TestWorkspaceMembershipCanonicalVector(t *testing.T) {
	vector := readMembershipVector(t)
	seed := decodeVectorHex(t, vector.AuthoritySeedHex)
	privateKey := ed25519.NewKeyFromSeed(seed)
	defer clear(privateKey)
	publicKey := ed25519.PublicKey(decodeVectorHex(t, vector.AuthorityPublicKeyHex))
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("authority seed does not match vector public key")
	}

	challengeBytes := decodeVectorHex(t, vector.ChallengeEncodedHex)
	challenge, err := DecodeIdentityPossessionChallenge(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	encodedChallenge, encodeErr := EncodeIdentityPossessionChallenge(challenge)
	assertEncoded(t, challengeBytes, encodedChallenge, encodeErr)
	digest, err := ChallengeDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest[:], decodeVectorHex(t, vector.ChallengeDigestHex)) {
		t.Fatalf("challenge digest = %x", digest)
	}

	proofBytes := decodeVectorHex(t, vector.ProofEncodedHex)
	proof, err := DecodePendingIdentityProof(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	encodedProof, encodeErr := EncodePendingIdentityProof(proof)
	assertEncoded(t, proofBytes, encodedProof, encodeErr)
	if err := ValidateProofAgainstChallenge(proof, challenge); err != nil {
		t.Fatal(err)
	}

	certificateBytes := decodeVectorHex(t, vector.CertificateEncodedHex)
	certificate, err := DecodeSignedDeviceCertificate(certificateBytes, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certificate.GetCertificateId(), decodeVectorHex(t, vector.CertificateIDHex)) {
		t.Fatal("certificate ID differs from vector")
	}
	encodedCertificate, encodeErr := EncodeSignedDeviceCertificate(certificate, publicKey)
	assertEncoded(t, certificateBytes, encodedCertificate, encodeErr)
	resigned, err := SignDeviceCertificate(certificate.GetCertificate(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	resignedBytes, encodeErr := EncodeSignedDeviceCertificate(resigned, publicKey)
	assertEncoded(t, certificateBytes, resignedBytes, encodeErr)

	initialBytes := decodeVectorHex(t, vector.InitialRosterEncodedHex)
	initial, err := DecodeSignedWorkspaceRoster(initialBytes, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initial.GetRosterDigest(), decodeVectorHex(t, vector.InitialRosterDigestHex)) {
		t.Fatal("initial roster digest differs from vector")
	}
	encodedInitial, encodeErr := EncodeSignedWorkspaceRoster(initial, publicKey)
	assertEncoded(t, initialBytes, encodedInitial, encodeErr)

	revokedBytes := decodeVectorHex(t, vector.RevokedRosterEncodedHex)
	revoked, err := DecodeSignedWorkspaceRoster(revokedBytes, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(revoked.GetRosterDigest(), decodeVectorHex(t, vector.RevokedRosterDigestHex)) ||
		!bytes.Equal(revoked.GetRoster().GetPreviousRosterDigest(), initial.GetRosterDigest()) {
		t.Fatal("revoked roster does not extend the initial roster")
	}
	encodedRevoked, encodeErr := EncodeSignedWorkspaceRoster(revoked, publicKey)
	assertEncoded(t, revokedBytes, encodedRevoked, encodeErr)

	renamedCertificateBytes := decodeVectorHex(t, vector.RenamedCertificateEncodedHex)
	renamedCertificate, err := DecodeSignedDeviceCertificate(renamedCertificateBytes, publicKey)
	if err != nil || !bytes.Equal(renamedCertificate.GetCertificateId(), decodeVectorHex(t, vector.RenamedCertificateIDHex)) {
		t.Fatalf("renamed certificate differs from vector: %v", err)
	}
	renameRosterBytes := decodeVectorHex(t, vector.RenameRosterEncodedHex)
	renameRoster, err := DecodeSignedWorkspaceRoster(renameRosterBytes, publicKey)
	if err != nil || !bytes.Equal(renameRoster.GetRosterDigest(), decodeVectorHex(t, vector.RenameRosterDigestHex)) ||
		len(renameRoster.GetRoster().GetCertificateTransitions()) != 1 {
		t.Fatalf("rename roster differs from vector: %v", err)
	}
	renameTransition := renameRoster.GetRoster().GetCertificateTransitions()[0]
	if err := ValidateDisplayNameCertificateTransition(certificate, renamedCertificate, renameTransition); err != nil {
		t.Fatal(err)
	}
	renameTransitionBytes, err := deterministic.Marshal(renameTransition)
	if err != nil || !bytes.Equal(renameTransitionBytes, decodeVectorHex(t, vector.RenameTransitionEncodedHex)) {
		t.Fatalf("rename transition differs from vector: %v", err)
	}
	encodedRenameRoster, encodeErr := EncodeSignedWorkspaceRoster(renameRoster, publicKey)
	assertEncoded(t, renameRosterBytes, encodedRenameRoster, encodeErr)

	transitionBytes := decodeVectorHex(t, vector.AuthorityTransitionEncodedHex)
	transition, err := DecodeSignedAuthorityKeyTransition(transitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(transition.GetTransitionDigest(), decodeVectorHex(t, vector.AuthorityTransitionDigestHex)) ||
		!bytes.Equal(transition.GetTransition().GetPreviousAuthorityPublicKey(), publicKey) ||
		!bytes.Equal(transition.GetTransition().GetNewAuthorityPublicKey(), decodeVectorHex(t, vector.NewAuthorityPublicKeyHex)) {
		t.Fatal("authority transition differs from vector")
	}
	encodedTransition, encodeErr := EncodeSignedAuthorityKeyTransition(transition)
	assertEncoded(t, transitionBytes, encodedTransition, encodeErr)
	if _, err := DecodeSignedWorkspaceRoster(decodeVectorHex(t, vector.AuthorityActivationRosterEncodedHex), ed25519.PublicKey(decodeVectorHex(t, vector.NewAuthorityPublicKeyHex))); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityKeyTransitionRequiresBothAuthoritiesAndRejectsForks(t *testing.T) {
	oldSeed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)
	newSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	oldKey := ed25519.NewKeyFromSeed(oldSeed)
	newKey := ed25519.NewKeyFromSeed(newSeed)
	defer clear(oldKey)
	defer clear(newKey)
	transition := &membershipv1.AuthorityKeyTransition{
		ProtocolVersion:            ProtocolVersion,
		WorkspaceId:                bytes.Repeat([]byte{0x11}, IdentifierSize),
		TransitionEpoch:            2,
		PreviousTransitionDigest:   make([]byte, DigestSize),
		PreviousAuthorityPublicKey: append([]byte(nil), oldKey.Public().(ed25519.PublicKey)...),
		NewAuthorityPublicKey:      append([]byte(nil), newKey.Public().(ed25519.PublicKey)...),
		ActivationRosterEpoch:      7,
		PreviousRosterDigest:       bytes.Repeat([]byte{0x33}, DigestSize),
		IssuedAtUnixMs:             1_800_000_000_000,
	}
	signed, err := SignAuthorityKeyTransition(transition, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSignedAuthorityKeyTransition(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedAuthorityKeyTransition(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetTransitionDigest(), signed.GetTransitionDigest()) {
		t.Fatal("transition digest changed")
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecodeSignedAuthorityKeyTransition(tampered); err == nil {
		t.Fatal("tampered new-authority proof accepted")
	}

	fork := proto.Clone(transition).(*membershipv1.AuthorityKeyTransition)
	fork.NewAuthorityPublicKey = append([]byte(nil), oldKey.Public().(ed25519.PublicKey)...)
	if _, err := SignAuthorityKeyTransition(fork, oldKey, oldKey); err == nil {
		t.Fatal("same-key transition accepted")
	}

	nonInitial := proto.Clone(transition).(*membershipv1.AuthorityKeyTransition)
	nonInitial.TransitionEpoch = 3
	if _, err := SignAuthorityKeyTransition(nonInitial, oldKey, newKey); err == nil {
		t.Fatal("missing previous transition digest accepted")
	}
}

func TestWorkspaceMembershipRejectsCanonicalAndAuthorizationBoundaryViolations(t *testing.T) {
	vector := readMembershipVector(t)
	publicKey := ed25519.PublicKey(decodeVectorHex(t, vector.AuthorityPublicKeyHex))
	certificateBytes := decodeVectorHex(t, vector.CertificateEncodedHex)
	certificate, err := DecodeSignedDeviceCertificate(certificateBytes, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	initialBytes := decodeVectorHex(t, vector.InitialRosterEncodedHex)
	initial, err := DecodeSignedWorkspaceRoster(initialBytes, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	unknown := append(append([]byte(nil), certificateBytes...), 0x20, 0x01)
	if _, err := DecodeSignedDeviceCertificate(unknown, publicKey); err == nil {
		t.Fatal("unknown certificate field accepted")
	}
	challengeBytes := decodeVectorHex(t, vector.ChallengeEncodedHex)
	duplicateVersion := append([]byte{0x08, 0x01}, challengeBytes...)
	if _, err := DecodeIdentityPossessionChallenge(duplicateVersion); err == nil {
		t.Fatal("non-canonical duplicate challenge field accepted")
	}

	unsortedRoles := proto.Clone(certificate.GetCertificate()).(*membershipv1.DeviceCertificate)
	unsortedRoles.Roles[0], unsortedRoles.Roles[1] = unsortedRoles.Roles[1], unsortedRoles.Roles[0]
	seed := decodeVectorHex(t, vector.AuthoritySeedHex)
	privateKey := ed25519.NewKeyFromSeed(seed)
	defer clear(privateKey)
	if _, err := SignDeviceCertificate(unsortedRoles, privateKey); err == nil {
		t.Fatal("unsorted certificate roles accepted")
	}

	badPrevious := proto.Clone(initial.GetRoster()).(*membershipv1.WorkspaceRoster)
	badPrevious.PreviousRosterDigest[0] = 1
	if _, err := SignWorkspaceRoster(badPrevious, privateKey); err == nil {
		t.Fatal("non-zero initial previous roster digest accepted")
	}

	activeAndRevoked := proto.Clone(initial.GetRoster()).(*membershipv1.WorkspaceRoster)
	activeAndRevoked.Revocations = []*membershipv1.RevokedCertificate{{
		CertificateId:   append([]byte(nil), certificate.GetCertificateId()...),
		DeviceId:        append([]byte(nil), certificate.GetCertificate().GetDeviceId()...),
		RevokedAtUnixMs: 1_800_000_600_000,
	}}
	if _, err := SignWorkspaceRoster(activeAndRevoked, privateKey); err == nil {
		t.Fatal("simultaneously active and revoked certificate accepted")
	}

	replacementBody := proto.Clone(certificate.GetCertificate()).(*membershipv1.DeviceCertificate)
	replacementBody.DisplayName = "Renamed browser"
	replacementBody.IssuedAtUnixMs++
	replacementBody.MembershipEpoch = 2
	replacement, err := SignDeviceCertificate(replacementBody, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateTransition := &membershipv1.DeviceCertificateTransition{
		ProtocolVersion:       ProtocolVersion,
		WorkspaceId:           append([]byte(nil), replacementBody.GetWorkspaceId()...),
		DeviceId:              append([]byte(nil), replacementBody.GetDeviceId()...),
		PreviousCertificateId: append([]byte(nil), certificate.GetCertificateId()...),
		NewCertificateId:      append([]byte(nil), replacement.GetCertificateId()...),
		ActivationRosterEpoch: 2,
		PreviousRosterDigest:  append([]byte(nil), initial.GetRosterDigest()...),
		Reason:                membershipv1.DeviceCertificateTransitionReason_DEVICE_CERTIFICATE_TRANSITION_REASON_DISPLAY_NAME,
		IssuedAtUnixMs:        replacementBody.GetIssuedAtUnixMs(),
	}
	if err := ValidateDisplayNameCertificateTransition(
		certificate, replacement, certificateTransition); err != nil {
		t.Fatal(err)
	}
	renameRoster := &membershipv1.WorkspaceRoster{
		ProtocolVersion:        ProtocolVersion,
		WorkspaceId:            append([]byte(nil), replacementBody.GetWorkspaceId()...),
		RosterEpoch:            2,
		PreviousRosterDigest:   append([]byte(nil), initial.GetRosterDigest()...),
		ActiveCertificates:     []*membershipv1.SignedDeviceCertificate{replacement},
		CertificateTransitions: []*membershipv1.DeviceCertificateTransition{certificateTransition},
	}
	if _, err := SignWorkspaceRoster(renameRoster, privateKey); err != nil {
		t.Fatal(err)
	}
	invalidTransition := proto.Clone(renameRoster).(*membershipv1.WorkspaceRoster)
	invalidTransition.CertificateTransitions[0].Reason =
		membershipv1.DeviceCertificateTransitionReason_DEVICE_CERTIFICATE_TRANSITION_REASON_UNSPECIFIED
	if _, err := SignWorkspaceRoster(invalidTransition, privateKey); err == nil {
		t.Fatal("unsupported certificate transition accepted")
	}
}

func readMembershipVector(t *testing.T) membershipVector {
	t.Helper()
	content, err := os.ReadFile("../test-vectors/workspace-membership-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector membershipVector
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertEncoded(t *testing.T, expected []byte, actual []byte, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("canonical bytes differ:\nactual:   %x\nexpected: %x", actual, expected)
	}
}
