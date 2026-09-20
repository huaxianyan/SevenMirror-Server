package adminweb

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

// testLogN keeps the credential fixtures cheap. These tests exercise the login
// path, not the work factor, and the accepted parameter range has its own coverage.
const testLogN = 10

const (
	testSecret   = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	testPassword = "correct horse battery staple"
)

// testPasswordHashString builds the PHC string exactly the way operator tooling
// does, so the tests run through the real parser instead of a hand built struct.
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

func testAccount(t *testing.T, password string, secret []byte) Account {
	t.Helper()
	hash, err := parsePasswordHash(testPasswordHashString(t, password))
	if err != nil {
		t.Fatal(err)
	}
	return Account{Name: "operator", PasswordHash: hash, TOTPSecret: secret}
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

func setAccountEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("NM_ADMIN_USERNAME", "operator")
	t.Setenv("NM_ADMIN_PASSWORD_HASH", testPasswordHashString(t, testPassword))
	t.Setenv("NM_ADMIN_TOTP_SECRET", testSecret)
}

func TestLoadRuntimeConfigRequiresEveryAdministratorCredential(t *testing.T) {
	for _, missing := range []string{
		"NM_ADMIN_USERNAME", "NM_ADMIN_PASSWORD_HASH", "NM_ADMIN_TOTP_SECRET",
	} {
		t.Run(missing, func(t *testing.T) {
			setAccountEnvironment(t)
			t.Setenv(missing, "")
			if _, err := LoadRuntimeConfig(); err == nil {
				t.Fatalf("LoadRuntimeConfig accepted a missing %s", missing)
			}
		})
	}
}

func TestLoadRuntimeConfigReadsPasswordsOnlyFromTheHashVariable(t *testing.T) {
	setAccountEnvironment(t)
	config, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Account.Name != "operator" || !config.Account.PasswordHash.matches(testPassword) ||
		len(config.Account.TOTPSecret) != 20 || !config.RecoveryCodeEnabled ||
		len(config.TrustedProxyCIDRs) != 0 {
		t.Fatalf("runtime config = %+v", config)
	}
}

func TestLoadRuntimeConfigRejectsNonCanonicalProxyAndUnknownSwitch(t *testing.T) {
	setAccountEnvironment(t)
	t.Setenv("NM_ADMIN_TRUSTED_PROXY_CIDRS", "127.0.0.1/8")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("LoadRuntimeConfig accepted a non canonical trusted proxy prefix")
	}
	t.Setenv("NM_ADMIN_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
	t.Setenv("NM_ADMIN_RECOVERY_CODE", "maybe")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("LoadRuntimeConfig accepted an unknown recovery code switch")
	}
	t.Setenv("NM_ADMIN_RECOVERY_CODE", "off")
	config, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.RecoveryCodeEnabled || len(config.TrustedProxyCIDRs) != 1 ||
		config.TrustedProxyCIDRs[0].String() != "127.0.0.1/32" {
		t.Fatalf("runtime config = %+v", config)
	}
}
