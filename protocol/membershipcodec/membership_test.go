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
	AuthoritySeedHex        string `json:"authoritySeedHex"`
	AuthorityPublicKeyHex   string `json:"authorityPublicKeyHex"`
	ChallengeEncodedHex     string `json:"challengeEncodedHex"`
	ChallengeDigestHex      string `json:"challengeDigestHex"`
	ProofEncodedHex         string `json:"proofEncodedHex"`
	CertificateEncodedHex   string `json:"certificateEncodedHex"`
	CertificateIDHex        string `json:"certificateIdHex"`
	InitialRosterEncodedHex string `json:"initialRosterEncodedHex"`
	InitialRosterDigestHex  string `json:"initialRosterDigestHex"`
	RevokedRosterEncodedHex string `json:"revokedRosterEncodedHex"`
	RevokedRosterDigestHex  string `json:"revokedRosterDigestHex"`
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
