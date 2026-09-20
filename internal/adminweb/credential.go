package adminweb

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptMinLogN   = 10
	scryptMaxLogN   = 20
	scryptMaxR      = 32
	scryptMaxP      = 8
	scryptMinSalt   = 16
	scryptMinDigest = 32

	// The cost the console writes for a new password. Roughly 32 MiB of memory per
	// attempt, which is affordable for a single administrator login and expensive
	// for an attacker who stole the database.
	newPasswordLogN   = 15
	newPasswordR      = 8
	newPasswordP      = 1
	newPasswordSalt   = 16
	newPasswordDigest = 32
)

// passwordHash is one administrator password verifier. The cost parameters travel
// with the stored digest so the work factor can be raised later without
// invalidating an existing credential.
type passwordHash struct {
	logN   int
	r      int
	p      int
	salt   []byte
	digest []byte
}

// parsePasswordHash reads the PHC string form of a scrypt password hash:
//
//	$scrypt$ln=15,r=8,p=1$<salt base64>$<digest base64>
//
// Both base64 fields use the RFC 4648 standard alphabet without padding, which is
// what the PHC specification and every common scrypt helper emits. The accepted
// parameter ranges bound the work a single login attempt can request: an operator
// mistake or a hostile configuration must not be able to turn one request into a
// memory or time denial of service.
func parsePasswordHash(encoded string) (passwordHash, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 5 || fields[0] != "" || fields[1] != "scrypt" {
		return passwordHash{}, errors.New("password hash must use the PHC scrypt form")
	}
	parameters := strings.Split(fields[2], ",")
	if len(parameters) != 3 {
		return passwordHash{}, errors.New("password hash must carry exactly ln, r and p")
	}
	values := make(map[string]int, len(parameters))
	for _, parameter := range parameters {
		name, value, found := strings.Cut(parameter, "=")
		if !found {
			return passwordHash{}, errors.New("password hash parameters must be name=value")
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return passwordHash{}, errors.New("password hash parameters must be integers")
		}
		values[name] = parsed
	}
	logN, hasLogN := values["ln"]
	blockSize, hasBlockSize := values["r"]
	parallelism, hasParallelism := values["p"]
	if !hasLogN || !hasBlockSize || !hasParallelism {
		return passwordHash{}, errors.New("password hash must carry exactly ln, r and p")
	}
	if logN < scryptMinLogN || logN > scryptMaxLogN ||
		blockSize < 1 || blockSize > scryptMaxR ||
		parallelism < 1 || parallelism > scryptMaxP {
		return passwordHash{}, errors.New("password hash parameters are out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(fields[3])
	if err != nil || len(salt) < scryptMinSalt {
		return passwordHash{}, errors.New("password hash salt must be unpadded base64 of at least 16 bytes")
	}
	digest, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil || len(digest) < scryptMinDigest {
		return passwordHash{}, errors.New("password hash digest must be unpadded base64 of at least 32 bytes")
	}
	return passwordHash{
		logN: logN, r: blockSize, p: parallelism, salt: salt, digest: digest,
	}, nil
}

// matches reports whether the presented password derives the stored digest. The
// comparison is constant time, and the derived key is cleared before returning.
func (h passwordHash) matches(password string) bool {
	candidate, err := scrypt.Key(
		[]byte(password), h.salt, 1<<h.logN, h.r, h.p, len(h.digest))
	if err != nil {
		return false
	}
	matched := subtle.ConstantTimeCompare(candidate, h.digest) == 1
	clear(candidate)
	return matched
}

// hashPassword derives the PHC scrypt string stored for a new password. The salt
// is fresh on every call, so two administrators who choose the same password still
// store different verifiers.
func hashPassword(password string) (string, error) {
	salt := make([]byte, newPasswordSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("read password salt")
	}
	digest, err := scrypt.Key([]byte(password), salt,
		1<<newPasswordLogN, newPasswordR, newPasswordP, newPasswordDigest)
	if err != nil {
		return "", errors.New("derive password digest")
	}
	encoded := fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s",
		newPasswordLogN, newPasswordR, newPasswordP,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest))
	clear(digest)
	return encoded, nil
}

// constantTimeEquals compares two strings without leaking their common prefix
// length. It is used for the account name, which must not become an oracle.
func constantTimeEquals(left string, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}
