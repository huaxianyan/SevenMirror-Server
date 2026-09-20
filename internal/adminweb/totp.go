package adminweb

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	totpStepSeconds = 30
	totpDigits      = 6
	totpSkewSteps   = 1
	totpModulus     = 1_000_000
	totpSecretBytes = 20
	consoleIssuer   = "SevenMirror"
)

// generateTOTPSecret returns the shared secret for a new authenticator entry. The
// length matches the HMAC-SHA1 output size RFC 4226 recommends.
func generateTOTPSecret() ([]byte, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.New("read TOTP secret")
	}
	return secret, nil
}

// encodeTOTPSecret renders the secret the way an authenticator app expects to
// receive it: uppercase RFC 4648 base32 without padding.
func encodeTOTPSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// formatTOTPSecret groups the encoded secret into four character blocks, which is
// how authenticator apps display it for manual entry.
func formatTOTPSecret(encoded string) string {
	var builder strings.Builder
	for index := 0; index < len(encoded); index += 4 {
		if index > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteString(encoded[index:min(index+4, len(encoded))])
	}
	return builder.String()
}

// totpProvisioningURI builds the otpauth URI an authenticator app consumes. The
// label carries the issuer so the entry stays identifiable in a long list.
func totpProvisioningURI(accountName string, encoded string) string {
	parameters := url.Values{}
	parameters.Set("secret", encoded)
	parameters.Set("issuer", consoleIssuer)
	parameters.Set("algorithm", "SHA1")
	parameters.Set("digits", strconv.Itoa(totpDigits))
	parameters.Set("period", strconv.Itoa(totpStepSeconds))
	return "otpauth://totp/" + url.PathEscape(consoleIssuer+":"+accountName) +
		"?" + parameters.Encode()
}

// parseTOTPSecret accepts the shared secret in the form every authenticator app
// displays: the RFC 4648 base32 alphabet, case insensitive, spaces and trailing
// padding tolerated.
func parseTOTPSecret(encoded string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(encoded), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil || len(secret) < 16 {
		return nil, errors.New("TOTP secret must be base32 of at least 16 bytes")
	}
	return secret, nil
}

// totpCounter is the RFC 6238 time step that contains the given moment.
func totpCounter(moment time.Time) int64 {
	return moment.Unix() / totpStepSeconds
}

// totpCode derives the six digit code for one time step using HMAC-SHA1, the
// algorithm defined by RFC 6238 and implemented by every authenticator app.
func totpCode(secret []byte, counter int64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", truncated%totpModulus)
}

// totpVerifier checks presented codes against the shared secret. It remembers the
// newest accepted time step and refuses anything at or below it, so a code
// observed in transit cannot be replayed for the remainder of its window.
type totpVerifier struct {
	secret []byte

	mu     sync.Mutex
	newest int64
	armed  bool
}

func newTOTPVerifier(secret []byte) *totpVerifier {
	return &totpVerifier{secret: secret}
}

// verify accepts the code for the current step and for one step either side, which
// absorbs ordinary clock drift between the server and the authenticator device.
func (v *totpVerifier) verify(presented string, moment time.Time) bool {
	candidate := strings.TrimSpace(presented)
	if len(candidate) != totpDigits || !digitsOnly(candidate) {
		return false
	}
	current := totpCounter(moment)
	v.mu.Lock()
	defer v.mu.Unlock()
	var matched int64
	accepted := false
	for delta := int64(-totpSkewSteps); delta <= totpSkewSteps; delta++ {
		counter := current + delta
		if v.armed && counter <= v.newest {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(v.secret, counter)), []byte(candidate)) == 1 {
			accepted = true
			matched = counter
		}
	}
	if accepted {
		v.newest = matched
		v.armed = true
	}
	return accepted
}

func digitsOnly(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
