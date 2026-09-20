package adminweb

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"golang.org/x/crypto/scrypt"
)

// testLogN keeps the credential fixtures cheap. These tests exercise the login
// path, not the work factor, and the accepted parameter range has its own coverage.
const testLogN = 10

const (
	testSecret     = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	testPassword   = "correct horse battery staple"
	testStoredName = "operator"
)

// testPasswordHashString builds the PHC string the way the console writes it, so
// the tests run through the real parser instead of a hand built struct.
func testPasswordHashString(t *testing.T, password string) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x5a}, 16)
	digest, err := scrypt.Key([]byte(password), salt, 1<<testLogN, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	return "$scrypt$ln=" + strconv.Itoa(testLogN) + ",r=8,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(digest)
}

func testCredential(t *testing.T, name string, password string, secret string) admission.AdministratorCredential {
	t.Helper()
	return admission.AdministratorCredential{
		Name: name, PasswordHash: testPasswordHashString(t, password), TOTPSecret: secret,
		UpdatedAt: time.UnixMilli(1_800_000_000_000),
	}
}

func testSecretBytes(t *testing.T) []byte {
	t.Helper()
	secret, err := parseTOTPSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestPasswordHashMatchesOnlyTheStoredPassword(t *testing.T) {
	hash, err := parsePasswordHash(testPasswordHashString(t, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if !hash.matches(testPassword) {
		t.Fatal("password hash rejected the stored password")
	}
	for _, wrong := range []string{"", "correct horse battery stapl", "Correct horse battery staple"} {
		if hash.matches(wrong) {
			t.Fatalf("password hash accepted %q", wrong)
		}
	}
}

// A stored verifier carries its own salt, so hashing the same password twice must
// not produce the same string.
func TestHashPasswordSaltsEveryCredential(t *testing.T) {
	first, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("hashPassword reused the salt")
	}
	for _, encoded := range []string{first, second} {
		parsed, err := parsePasswordHash(encoded)
		if err != nil {
			t.Fatalf("hashPassword produced %q, which the parser rejected: %v", encoded, err)
		}
		if !parsed.matches(testPassword) {
			t.Fatalf("hashPassword produced %q, which did not verify", encoded)
		}
		if parsed.matches("another password") {
			t.Fatalf("hashPassword produced %q, which accepted a wrong password", encoded)
		}
	}
}

func TestParsePasswordHashRejectsMalformedAndOutOfRangeInput(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 16))
	digest := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	shortSalt := base64.RawStdEncoding.EncodeToString([]byte("too short"))
	paddedSalt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 16))
	for name, encoded := range map[string]string{
		"empty":            "",
		"other scheme":     "$argon2id$ln=15,r=8,p=1$" + salt + "$" + digest,
		"missing digest":   "$scrypt$ln=15,r=8,p=1$" + salt,
		"unknown flavour":  "$scrypt$ln=15,r=8$" + salt + "$" + digest,
		"logN below floor": "$scrypt$ln=8,r=8,p=1$" + salt + "$" + digest,
		"logN above ceil":  "$scrypt$ln=21,r=8,p=1$" + salt + "$" + digest,
		"block too large":  "$scrypt$ln=15,r=64,p=1$" + salt + "$" + digest,
		"short salt":       "$scrypt$ln=15,r=8,p=1$" + shortSalt + "$" + digest,
		"padded base64":    "$scrypt$ln=15,r=8,p=1$" + paddedSalt + "$" + digest,
	} {
		if _, err := parsePasswordHash(encoded); err == nil {
			t.Fatalf("parsePasswordHash accepted %s", name)
		}
	}
}

func TestParseTOTPSecretAcceptsAuthenticatorForm(t *testing.T) {
	for _, encoded := range []string{
		testSecret,
		"jbswy3dpehpk3pxpjbswy3dpehpk3pxp",
		"JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
		testSecret + "=",
	} {
		secret, err := parseTOTPSecret(encoded)
		if err != nil || len(secret) != 20 {
			t.Fatalf("secret %q bytes=%d error=%v", encoded, len(secret), err)
		}
	}
	for _, encoded := range []string{"", "JBSWY3D", "not-base32-!!!"} {
		if _, err := parseTOTPSecret(encoded); err == nil {
			t.Fatalf("parseTOTPSecret accepted %q", encoded)
		}
	}
}

func TestGeneratedTOTPSecretEncodesAndVerifies(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != totpSecretBytes {
		t.Fatalf("generated secret length=%d", len(secret))
	}
	encoded := encodeTOTPSecret(secret)
	if strings.ContainsAny(encoded, "= ") {
		t.Fatalf("encoded secret %q carries padding or spaces", encoded)
	}
	if formatTOTPSecret(encoded) != groupInFours(encoded) {
		t.Fatalf("grouped secret=%q", formatTOTPSecret(encoded))
	}
	// What the setup page shows has to survive the round trip through the parser the
	// login path uses, manual entry spaces included.
	parsed, err := parseTOTPSecret(formatTOTPSecret(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, secret) {
		t.Fatal("the displayed secret did not parse back to the generated bytes")
	}
	moment := time.Unix(1_800_000_000, 0)
	verifier := newTOTPVerifier(parsed)
	if !verifier.verify(totpCode(secret, totpCounter(moment)), moment) {
		t.Fatal("the generated secret did not verify its own code")
	}
}

func TestTOTPProvisioningURICarriesSecretAndIssuer(t *testing.T) {
	secret := testSecretBytes(t)
	uri, err := url.Parse(totpProvisioningURI(testStoredName, encodeTOTPSecret(secret)))
	if err != nil {
		t.Fatal(err)
	}
	query := uri.Query()
	if uri.Scheme != "otpauth" || uri.Host != "totp" ||
		uri.Path != "/"+consoleIssuer+":"+testStoredName {
		t.Fatalf("provisioning uri=%q", uri.String())
	}
	if query.Get("secret") != encodeTOTPSecret(secret) || query.Get("issuer") != consoleIssuer ||
		query.Get("algorithm") != "SHA1" || query.Get("digits") != "6" ||
		query.Get("period") != "30" {
		t.Fatalf("provisioning query=%v", query)
	}
}

func TestValidateNewPasswordRejectsWeakInput(t *testing.T) {
	for name, password := range map[string]string{
		"empty":          "",
		"too short":      strings.Repeat("a", minPasswordBytes-1),
		"too long":       strings.Repeat("a", maxPasswordBytes+1),
		"spaces only":    strings.Repeat(" ", minPasswordBytes+4),
		"control":        "a password with a\x00byte",
		"default reused": defaultAdministratorPassword,
	} {
		if err := validateNewPassword(password); err == nil {
			t.Fatalf("validateNewPassword accepted %s", name)
		}
	}
	if err := validateNewPassword(strings.Repeat("a", minPasswordBytes)); err != nil {
		t.Fatalf("validateNewPassword rejected a compliant password: %v", err)
	}
}

func TestValidateAccountNameRejectsSpacesAndControlCharacters(t *testing.T) {
	for name, candidate := range map[string]string{
		"empty":    "",
		"space":    "two words",
		"control":  "line\nbreak",
		"too long": strings.Repeat("a", maxAccountNameBytes+1),
		"trailing": "name ",
		"del char": "name\x7f",
	} {
		if err := validateAccountName(candidate); err == nil {
			t.Fatalf("validateAccountName accepted %s", name)
		}
	}
	if err := validateAccountName("neko7ina"); err != nil {
		t.Fatalf("validateAccountName rejected a compliant name: %v", err)
	}
}

// groupInFours is the expected rendering of the manual entry string, written
// independently of the implementation under test.
func groupInFours(value string) string {
	groups := make([]string, 0, len(value)/4+1)
	for index := 0; index < len(value); index += 4 {
		end := index + 4
		if end > len(value) {
			end = len(value)
		}
		groups = append(groups, value[index:end])
	}
	return strings.Join(groups, " ")
}

// The counters and codes below are the published RFC 4226 appendix D values for
// the shared secret 12345678901234567890. RFC 6238 reuses the same truncation for
// the six digit form, so a TOTP implementation has to reproduce them exactly.
func TestTOTPCodeMatchesPublishedVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, testCase := range []struct {
		counter int64
		code    string
	}{{0, "755224"}, {1, "287082"}, {2, "359152"}, {3, "969429"}, {9, "520489"}} {
		if code := totpCode(secret, testCase.counter); code != testCase.code {
			t.Fatalf("counter %d code=%q want %q", testCase.counter, code, testCase.code)
		}
	}
}

func TestTOTPVerifierAbsorbsOneStepOfClockDrift(t *testing.T) {
	secret := []byte("12345678901234567890")
	moment := time.Unix(1_800_000_000, 0)
	current := totpCounter(moment)

	for _, delta := range []int64{-1, 0, 1} {
		fresh := newTOTPVerifier(secret)
		if !fresh.verify(totpCode(secret, current+delta), moment) {
			t.Fatalf("verifier rejected the step offset by %d", delta)
		}
	}
	for _, delta := range []int64{-2, 2} {
		fresh := newTOTPVerifier(secret)
		if fresh.verify(totpCode(secret, current+delta), moment) {
			t.Fatalf("verifier accepted the step offset by %d", delta)
		}
	}
}

func TestTOTPVerifierRefusesReplayAndMalformedCodes(t *testing.T) {
	secret := []byte("12345678901234567890")
	moment := time.Unix(1_800_000_000, 0)
	current := totpCounter(moment)

	verifier := newTOTPVerifier(secret)
	if !verifier.verify(totpCode(secret, current), moment) {
		t.Fatal("verifier rejected the current code")
	}
	if verifier.verify(totpCode(secret, current), moment) {
		t.Fatal("verifier accepted a replayed code")
	}
	if !verifier.verify(totpCode(secret, current+1), moment) {
		t.Fatal("verifier rejected a newer code")
	}
	if verifier.verify(totpCode(secret, current), moment) {
		t.Fatal("verifier accepted a code older than the newest accepted step")
	}

	for _, malformed := range []string{"", "12345", "1234567", "abcdef", "12345a"} {
		fresh := newTOTPVerifier(secret)
		if fresh.verify(malformed, moment) {
			t.Fatalf("verifier accepted the malformed code %q", malformed)
		}
	}
}
