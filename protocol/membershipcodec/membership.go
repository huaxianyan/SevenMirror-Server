package membershipcodec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	membershipv1 "github.com/huaxianyan/SyncNotifications-Server/protocol/generated/membership/v1"
	"google.golang.org/protobuf/proto"
)

const (
	ProtocolVersion          = 1
	IdentifierSize           = 16
	DigestSize               = 32
	P256PublicKeySize        = 65
	Ed25519SignatureSize     = 64
	MaxDisplayNameBytes      = 100
	MaxMembershipMessageSize = 1 << 20
	MaxActiveCertificates    = 256
	MaxRevocations           = 4096
	MaxChallengeLifetime     = 10 * time.Minute
)

const (
	possessionHPKEInfoDomain              = "SyncNotifications-membership-possession-hpke-info-v1\x00"
	challengeDigestDomain                 = "SyncNotifications-membership-possession-challenge-digest-v1\x00"
	certificateIDDomain                   = "SyncNotifications-membership-device-certificate-id-v1\x00"
	certificateSignatureDomain            = "SyncNotifications-membership-device-certificate-signature-v1\x00"
	rosterDigestDomain                    = "SyncNotifications-membership-workspace-roster-digest-v1\x00"
	rosterSignatureDomain                 = "SyncNotifications-membership-workspace-roster-signature-v1\x00"
	authorityTransitionDigestDomain       = "SyncNotifications-membership-authority-transition-digest-v1\x00"
	authorityTransitionOldSignatureDomain = "SyncNotifications-membership-authority-transition-old-signature-v1\x00"
	authorityTransitionNewSignatureDomain = "SyncNotifications-membership-authority-transition-new-signature-v1\x00"
)

var deterministic = proto.MarshalOptions{Deterministic: true}

func EncodeIdentityPossessionChallenge(value *membershipv1.IdentityPossessionChallenge) ([]byte, error) {
	if err := validateChallenge(value); err != nil {
		return nil, err
	}
	return encode(value)
}

func DecodeIdentityPossessionChallenge(encoded []byte) (*membershipv1.IdentityPossessionChallenge, error) {
	value := &membershipv1.IdentityPossessionChallenge{}
	if err := decodeCanonical(encoded, value); err != nil {
		return nil, err
	}
	if err := validateChallenge(value); err != nil {
		return nil, err
	}
	return value, nil
}

func EncodePendingIdentityProof(value *membershipv1.PendingIdentityProof) ([]byte, error) {
	if err := validateProof(value); err != nil {
		return nil, err
	}
	return encode(value)
}

func DecodePendingIdentityProof(encoded []byte) (*membershipv1.PendingIdentityProof, error) {
	value := &membershipv1.PendingIdentityProof{}
	if err := decodeCanonical(encoded, value); err != nil {
		return nil, err
	}
	if err := validateProof(value); err != nil {
		return nil, err
	}
	return value, nil
}

func PossessionHPKEInfo(workspaceID, deviceID, identityKeyID []byte) ([]byte, error) {
	if err := validateBinding(workspaceID, deviceID, identityKeyID); err != nil {
		return nil, err
	}
	info := make([]byte, 0, len(possessionHPKEInfoDomain)+len(workspaceID)+len(deviceID)+len(identityKeyID))
	info = append(info, possessionHPKEInfoDomain...)
	info = append(info, workspaceID...)
	info = append(info, deviceID...)
	info = append(info, identityKeyID...)
	return info, nil
}

func ChallengeDigest(challenge *membershipv1.IdentityPossessionChallenge) ([DigestSize]byte, error) {
	encoded, err := EncodeIdentityPossessionChallenge(challenge)
	if err != nil {
		return [DigestSize]byte{}, err
	}
	return domainHash(challengeDigestDomain, encoded), nil
}

func ValidateProofAgainstChallenge(
	proof *membershipv1.PendingIdentityProof,
	challenge *membershipv1.IdentityPossessionChallenge,
) error {
	if err := validateProof(proof); err != nil {
		return err
	}
	digest, err := ChallengeDigest(challenge)
	if err != nil {
		return err
	}
	if !bytes.Equal(proof.GetWorkspaceId(), challenge.GetWorkspaceId()) ||
		!bytes.Equal(proof.GetDeviceId(), challenge.GetDeviceId()) ||
		!bytes.Equal(proof.GetIdentityKeyId(), challenge.GetIdentityKeyId()) ||
		subtle.ConstantTimeCompare(proof.GetChallengeDigest(), digest[:]) != 1 ||
		subtle.ConstantTimeCompare(proof.GetChallengeSecret(), challenge.GetChallengeSecret()) != 1 {
		return errors.New("pending identity proof does not match the challenge")
	}
	return nil
}

func SignDeviceCertificate(
	certificate *membershipv1.DeviceCertificate,
	authorityPrivateKey ed25519.PrivateKey,
) (*membershipv1.SignedDeviceCertificate, error) {
	if err := validateDeviceCertificate(certificate); err != nil {
		return nil, err
	}
	if len(authorityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authority private key must be Ed25519")
	}
	encoded, err := encode(certificate)
	if err != nil {
		return nil, err
	}
	certificateID := domainHash(certificateIDDomain, encoded)
	signature := ed25519.Sign(authorityPrivateKey, domainBytes(certificateSignatureDomain, encoded))
	return &membershipv1.SignedDeviceCertificate{
		Certificate:        proto.Clone(certificate).(*membershipv1.DeviceCertificate),
		CertificateId:      certificateID[:],
		AuthoritySignature: signature,
	}, nil
}

func EncodeSignedDeviceCertificate(
	value *membershipv1.SignedDeviceCertificate,
	authorityPublicKey ed25519.PublicKey,
) ([]byte, error) {
	if err := validateSignedDeviceCertificate(value, authorityPublicKey); err != nil {
		return nil, err
	}
	return encode(value)
}

func DecodeSignedDeviceCertificate(
	encoded []byte,
	authorityPublicKey ed25519.PublicKey,
) (*membershipv1.SignedDeviceCertificate, error) {
	value := &membershipv1.SignedDeviceCertificate{}
	if err := decodeCanonical(encoded, value); err != nil {
		return nil, err
	}
	if err := validateSignedDeviceCertificate(value, authorityPublicKey); err != nil {
		return nil, err
	}
	return value, nil
}

func SignWorkspaceRoster(
	roster *membershipv1.WorkspaceRoster,
	authorityPrivateKey ed25519.PrivateKey,
) (*membershipv1.SignedWorkspaceRoster, error) {
	if len(authorityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authority private key must be Ed25519")
	}
	publicKey := authorityPrivateKey.Public().(ed25519.PublicKey)
	if err := validateWorkspaceRoster(roster, publicKey); err != nil {
		return nil, err
	}
	encoded, err := encode(roster)
	if err != nil {
		return nil, err
	}
	digest := domainHash(rosterDigestDomain, encoded)
	signature := ed25519.Sign(authorityPrivateKey, domainBytes(rosterSignatureDomain, encoded))
	return &membershipv1.SignedWorkspaceRoster{
		Roster:             proto.Clone(roster).(*membershipv1.WorkspaceRoster),
		RosterDigest:       digest[:],
		AuthoritySignature: signature,
	}, nil
}

func EncodeSignedWorkspaceRoster(
	value *membershipv1.SignedWorkspaceRoster,
	authorityPublicKey ed25519.PublicKey,
) ([]byte, error) {
	if err := validateSignedWorkspaceRoster(value, authorityPublicKey); err != nil {
		return nil, err
	}
	return encode(value)
}

func DecodeSignedWorkspaceRoster(
	encoded []byte,
	authorityPublicKey ed25519.PublicKey,
) (*membershipv1.SignedWorkspaceRoster, error) {
	value := &membershipv1.SignedWorkspaceRoster{}
	if err := decodeCanonical(encoded, value); err != nil {
		return nil, err
	}
	if err := validateSignedWorkspaceRoster(value, authorityPublicKey); err != nil {
		return nil, err
	}
	return value, nil
}

func SignAuthorityKeyTransition(
	transition *membershipv1.AuthorityKeyTransition,
	previousAuthorityPrivateKey ed25519.PrivateKey,
	newAuthorityPrivateKey ed25519.PrivateKey,
) (*membershipv1.SignedAuthorityKeyTransition, error) {
	if len(previousAuthorityPrivateKey) != ed25519.PrivateKeySize || len(newAuthorityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authority transition private keys must be Ed25519")
	}
	previousPublicKey := previousAuthorityPrivateKey.Public().(ed25519.PublicKey)
	newPublicKey := newAuthorityPrivateKey.Public().(ed25519.PublicKey)
	if err := validateAuthorityKeyTransition(transition, previousPublicKey, newPublicKey); err != nil {
		return nil, err
	}
	encoded, err := encode(transition)
	if err != nil {
		return nil, err
	}
	digest := domainHash(authorityTransitionDigestDomain, encoded)
	return &membershipv1.SignedAuthorityKeyTransition{
		Transition:                 proto.Clone(transition).(*membershipv1.AuthorityKeyTransition),
		TransitionDigest:           digest[:],
		PreviousAuthoritySignature: ed25519.Sign(previousAuthorityPrivateKey, domainBytes(authorityTransitionOldSignatureDomain, encoded)),
		NewAuthoritySignature:      ed25519.Sign(newAuthorityPrivateKey, domainBytes(authorityTransitionNewSignatureDomain, encoded)),
	}, nil
}

func EncodeSignedAuthorityKeyTransition(value *membershipv1.SignedAuthorityKeyTransition) ([]byte, error) {
	if err := validateSignedAuthorityKeyTransition(value); err != nil {
		return nil, err
	}
	return encode(value)
}

func DecodeSignedAuthorityKeyTransition(encoded []byte) (*membershipv1.SignedAuthorityKeyTransition, error) {
	value := &membershipv1.SignedAuthorityKeyTransition{}
	if err := decodeCanonical(encoded, value); err != nil {
		return nil, err
	}
	if err := validateSignedAuthorityKeyTransition(value); err != nil {
		return nil, err
	}
	return value, nil
}

func validateSignedAuthorityKeyTransition(value *membershipv1.SignedAuthorityKeyTransition) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("signed authority transition is missing or contains unknown fields")
	}
	transition := value.GetTransition()
	if transition == nil {
		return errors.New("authority transition is missing")
	}
	previousKey := ed25519.PublicKey(transition.GetPreviousAuthorityPublicKey())
	newKey := ed25519.PublicKey(transition.GetNewAuthorityPublicKey())
	if err := validateAuthorityKeyTransition(transition, previousKey, newKey); err != nil {
		return err
	}
	encoded, err := encode(transition)
	if err != nil {
		return err
	}
	expectedDigest := domainHash(authorityTransitionDigestDomain, encoded)
	if subtle.ConstantTimeCompare(value.GetTransitionDigest(), expectedDigest[:]) != 1 {
		return errors.New("authority transition digest does not match canonical transition")
	}
	if len(value.GetPreviousAuthoritySignature()) != Ed25519SignatureSize ||
		!ed25519.Verify(previousKey, domainBytes(authorityTransitionOldSignatureDomain, encoded), value.GetPreviousAuthoritySignature()) {
		return errors.New("previous authority transition signature is invalid")
	}
	if len(value.GetNewAuthoritySignature()) != Ed25519SignatureSize ||
		!ed25519.Verify(newKey, domainBytes(authorityTransitionNewSignatureDomain, encoded), value.GetNewAuthoritySignature()) {
		return errors.New("new authority transition signature is invalid")
	}
	return nil
}

func validateAuthorityKeyTransition(value *membershipv1.AuthorityKeyTransition, previousKey, newKey ed25519.PublicKey) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("authority transition is missing or contains unknown fields")
	}
	if value.GetProtocolVersion() != ProtocolVersion || len(value.GetWorkspaceId()) != IdentifierSize || allZero(value.GetWorkspaceId()) {
		return errors.New("authority transition version or workspace is invalid")
	}
	if value.GetTransitionEpoch() < 2 || value.GetTransitionEpoch() > math.MaxInt64 {
		return errors.New("authority transition epoch is invalid")
	}
	previousDigest := value.GetPreviousTransitionDigest()
	if len(previousDigest) != DigestSize || (value.GetTransitionEpoch() == 2 && !allZero(previousDigest)) ||
		(value.GetTransitionEpoch() > 2 && allZero(previousDigest)) {
		return errors.New("authority transition previous digest is invalid for its epoch")
	}
	if len(previousKey) != ed25519.PublicKeySize || len(newKey) != ed25519.PublicKeySize ||
		!bytes.Equal(previousKey, value.GetPreviousAuthorityPublicKey()) ||
		!bytes.Equal(newKey, value.GetNewAuthorityPublicKey()) || bytes.Equal(previousKey, newKey) ||
		allZero(previousKey) || allZero(newKey) {
		return errors.New("authority transition key binding is invalid")
	}
	if value.GetActivationRosterEpoch() < 2 || value.GetActivationRosterEpoch() > math.MaxInt64 ||
		len(value.GetPreviousRosterDigest()) != DigestSize || allZero(value.GetPreviousRosterDigest()) ||
		value.GetIssuedAtUnixMs() == 0 || value.GetIssuedAtUnixMs() > math.MaxInt64 {
		return errors.New("authority transition roster binding or time is invalid")
	}
	return nil
}

func validateChallenge(value *membershipv1.IdentityPossessionChallenge) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("identity possession challenge is missing or contains unknown fields")
	}
	if value.GetProtocolVersion() != ProtocolVersion {
		return errors.New("identity possession challenge protocol version is unsupported")
	}
	if err := validateBinding(value.GetWorkspaceId(), value.GetDeviceId(), value.GetIdentityKeyId()); err != nil {
		return err
	}
	if len(value.GetChallengeSecret()) != DigestSize || allZero(value.GetChallengeSecret()) {
		return errors.New("identity possession challenge secret must be a non-zero 32-byte value")
	}
	if value.GetIssuedAtUnixMs() == 0 || value.GetIssuedAtUnixMs() > math.MaxInt64 ||
		value.GetExpiresAtUnixMs() <= value.GetIssuedAtUnixMs() || value.GetExpiresAtUnixMs() > math.MaxInt64 ||
		value.GetExpiresAtUnixMs()-value.GetIssuedAtUnixMs() > uint64(MaxChallengeLifetime/time.Millisecond) {
		return errors.New("identity possession challenge lifetime is invalid")
	}
	return nil
}

func validateProof(value *membershipv1.PendingIdentityProof) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("pending identity proof is missing or contains unknown fields")
	}
	if value.GetProtocolVersion() != ProtocolVersion {
		return errors.New("pending identity proof protocol version is unsupported")
	}
	if err := validateBinding(value.GetWorkspaceId(), value.GetDeviceId(), value.GetIdentityKeyId()); err != nil {
		return err
	}
	if len(value.GetChallengeDigest()) != DigestSize || allZero(value.GetChallengeDigest()) ||
		len(value.GetChallengeSecret()) != DigestSize || allZero(value.GetChallengeSecret()) {
		return errors.New("pending identity proof digest and secret must be non-zero 32-byte values")
	}
	return nil
}

func validateSignedDeviceCertificate(value *membershipv1.SignedDeviceCertificate, authorityPublicKey ed25519.PublicKey) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("signed device certificate is missing or contains unknown fields")
	}
	if len(authorityPublicKey) != ed25519.PublicKeySize {
		return errors.New("authority public key must be Ed25519")
	}
	if err := validateDeviceCertificate(value.GetCertificate()); err != nil {
		return err
	}
	encoded, err := encode(value.GetCertificate())
	if err != nil {
		return err
	}
	expectedID := domainHash(certificateIDDomain, encoded)
	if subtle.ConstantTimeCompare(value.GetCertificateId(), expectedID[:]) != 1 {
		return errors.New("device certificate ID does not match canonical certificate")
	}
	if len(value.GetAuthoritySignature()) != Ed25519SignatureSize ||
		!ed25519.Verify(authorityPublicKey, domainBytes(certificateSignatureDomain, encoded), value.GetAuthoritySignature()) {
		return errors.New("device certificate authority signature is invalid")
	}
	return nil
}

func validateDeviceCertificate(value *membershipv1.DeviceCertificate) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("device certificate is missing or contains unknown fields")
	}
	if value.GetProtocolVersion() != ProtocolVersion {
		return errors.New("device certificate protocol version is unsupported")
	}
	if err := validateBinding(value.GetWorkspaceId(), value.GetDeviceId(), value.GetIdentityKeyId()); err != nil {
		return err
	}
	if value.GetDeviceType() != membershipv1.DeviceType_DEVICE_TYPE_ANDROID &&
		value.GetDeviceType() != membershipv1.DeviceType_DEVICE_TYPE_CHROME {
		return errors.New("device certificate type is unsupported")
	}
	name := value.GetDisplayName()
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || len(name) > MaxDisplayNameBytes {
		return errors.New("device display name must be valid non-blank UTF-8 within size limit")
	}
	roles := value.GetRoles()
	if len(roles) == 0 {
		return errors.New("device certificate requires at least one role")
	}
	previousRole := membershipv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED
	for _, role := range roles {
		if role < membershipv1.DeviceRole_DEVICE_ROLE_SEND_NOTIFICATIONS ||
			role > membershipv1.DeviceRole_DEVICE_ROLE_MANAGE_DEVICES || role <= previousRole {
			return errors.New("device certificate roles must be supported, unique, and strictly sorted")
		}
		previousRole = role
	}
	publicKey := value.GetIdentityPublicKey()
	if len(publicKey) != P256PublicKeySize {
		return errors.New("device identity public key must be a 65-byte P-256 point")
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), publicKey); x == nil || y == nil {
		return errors.New("device identity public key is not a valid P-256 point")
	}
	identityKeyID := sha256.Sum256(publicKey)
	if subtle.ConstantTimeCompare(value.GetIdentityKeyId(), identityKeyID[:]) != 1 {
		return errors.New("device identity key ID must equal SHA-256 of the public key")
	}
	if value.GetIssuedAtUnixMs() == 0 || value.GetIssuedAtUnixMs() > math.MaxInt64 ||
		value.GetExpiresAtUnixMs() > math.MaxInt64 ||
		(value.GetExpiresAtUnixMs() != 0 && value.GetExpiresAtUnixMs() <= value.GetIssuedAtUnixMs()) ||
		value.GetMembershipEpoch() == 0 || value.GetMembershipEpoch() > math.MaxInt64 {
		return errors.New("device certificate time or membership epoch is invalid")
	}
	return nil
}

func validateSignedWorkspaceRoster(value *membershipv1.SignedWorkspaceRoster, authorityPublicKey ed25519.PublicKey) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("signed workspace roster is missing or contains unknown fields")
	}
	if len(authorityPublicKey) != ed25519.PublicKeySize {
		return errors.New("authority public key must be Ed25519")
	}
	if err := validateWorkspaceRoster(value.GetRoster(), authorityPublicKey); err != nil {
		return err
	}
	encoded, err := encode(value.GetRoster())
	if err != nil {
		return err
	}
	expectedDigest := domainHash(rosterDigestDomain, encoded)
	if subtle.ConstantTimeCompare(value.GetRosterDigest(), expectedDigest[:]) != 1 {
		return errors.New("workspace roster digest does not match canonical roster")
	}
	if len(value.GetAuthoritySignature()) != Ed25519SignatureSize ||
		!ed25519.Verify(authorityPublicKey, domainBytes(rosterSignatureDomain, encoded), value.GetAuthoritySignature()) {
		return errors.New("workspace roster authority signature is invalid")
	}
	return nil
}

func validateWorkspaceRoster(value *membershipv1.WorkspaceRoster, authorityPublicKey ed25519.PublicKey) error {
	if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("workspace roster is missing or contains unknown fields")
	}
	if value.GetProtocolVersion() != ProtocolVersion || len(value.GetWorkspaceId()) != IdentifierSize || allZero(value.GetWorkspaceId()) ||
		value.GetRosterEpoch() == 0 || value.GetRosterEpoch() > math.MaxInt64 {
		return errors.New("workspace roster version, workspace, or epoch is invalid")
	}
	previousDigest := value.GetPreviousRosterDigest()
	if len(previousDigest) != DigestSize || (value.GetRosterEpoch() == 1 && !allZero(previousDigest)) ||
		(value.GetRosterEpoch() > 1 && allZero(previousDigest)) {
		return errors.New("workspace roster previous digest is invalid for its epoch")
	}
	certificates := value.GetActiveCertificates()
	if len(certificates) > MaxActiveCertificates {
		return errors.New("workspace roster has too many active certificates")
	}
	var previousDeviceID []byte
	activeCertificateIDs := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if err := validateSignedDeviceCertificate(certificate, authorityPublicKey); err != nil {
			return err
		}
		body := certificate.GetCertificate()
		if !bytes.Equal(body.GetWorkspaceId(), value.GetWorkspaceId()) || body.GetMembershipEpoch() > value.GetRosterEpoch() {
			return errors.New("active certificate is not bound to the workspace roster")
		}
		if previousDeviceID != nil && bytes.Compare(previousDeviceID, body.GetDeviceId()) >= 0 {
			return errors.New("active certificates must be unique and strictly sorted by device ID")
		}
		previousDeviceID = body.GetDeviceId()
		activeCertificateIDs[string(certificate.GetCertificateId())] = struct{}{}
	}
	revocations := value.GetRevocations()
	if len(revocations) > MaxRevocations {
		return errors.New("workspace roster has too many revocations")
	}
	var previousCertificateID []byte
	for _, revocation := range revocations {
		if revocation == nil || len(revocation.ProtoReflect().GetUnknown()) != 0 ||
			len(revocation.GetCertificateId()) != DigestSize || allZero(revocation.GetCertificateId()) ||
			len(revocation.GetDeviceId()) != IdentifierSize || allZero(revocation.GetDeviceId()) ||
			revocation.GetRevokedAtUnixMs() == 0 || revocation.GetRevokedAtUnixMs() > math.MaxInt64 {
			return errors.New("workspace roster contains an invalid revocation")
		}
		if previousCertificateID != nil && bytes.Compare(previousCertificateID, revocation.GetCertificateId()) >= 0 {
			return errors.New("workspace roster revocations must be unique and strictly sorted by certificate ID")
		}
		if _, active := activeCertificateIDs[string(revocation.GetCertificateId())]; active {
			return errors.New("workspace roster cannot revoke an active certificate")
		}
		previousCertificateID = revocation.GetCertificateId()
	}
	return nil
}

func validateBinding(workspaceID, deviceID, identityKeyID []byte) error {
	if len(workspaceID) != IdentifierSize || allZero(workspaceID) ||
		len(deviceID) != IdentifierSize || allZero(deviceID) ||
		len(identityKeyID) != DigestSize || allZero(identityKeyID) {
		return errors.New("workspace, device, and identity key binding is invalid")
	}
	return nil
}

func encode(value proto.Message) ([]byte, error) {
	encoded, err := deterministic.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode membership message: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxMembershipMessageSize {
		return nil, errors.New("membership message size is out of range")
	}
	return encoded, nil
}

func decodeCanonical(encoded []byte, value proto.Message) error {
	if len(encoded) == 0 || len(encoded) > MaxMembershipMessageSize {
		return errors.New("membership message size is out of range")
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(encoded, value); err != nil {
		return fmt.Errorf("decode membership message: %w", err)
	}
	canonical, err := deterministic.Marshal(value)
	if err != nil {
		return fmt.Errorf("re-encode membership message: %w", err)
	}
	if !bytes.Equal(canonical, encoded) {
		return errors.New("membership message is not canonically encoded")
	}
	return nil
}

func domainHash(domain string, encoded []byte) [DigestSize]byte {
	return sha256.Sum256(domainBytes(domain, encoded))
}

func domainBytes(domain string, encoded []byte) []byte {
	value := make([]byte, 0, len(domain)+len(encoded))
	value = append(value, domain...)
	value = append(value, encoded...)
	return value
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
