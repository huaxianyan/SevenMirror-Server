package adminweb

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAdminAddress = "127.0.0.1:8081"
	defaultDatabasePath = "data/syncnotifications.db"
	maxAccountNameBytes = 64
)

type RuntimeConfig struct {
	Address               string
	ExpectedOrigin        string
	DatabasePath          string
	AuthorityKeyDirectory string
	Account               Account
	RecoveryCodeEnabled   bool
	TrustedProxyCIDRs     []netip.Prefix
	ShutdownTimeout       time.Duration
}

// Account is the single administrator credential the console accepts. It stays in
// configuration rather than a database row: the console owns no user table, and
// changing the password or the second factor is a redeployment decision that
// requires the same host access as reading the authority key.
type Account struct {
	Name         string
	PasswordHash passwordHash
	TOTPSecret   []byte
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	address := envOrDefault("NM_ADMIN_ADDRESS", defaultAdminAddress)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return RuntimeConfig{}, errors.New("NM_ADMIN_ADDRESS must contain an IP address and port")
	}
	addressIP, err := netip.ParseAddr(host)
	if err != nil || !addressIP.IsLoopback() || addressIP.Zone() != "" {
		return RuntimeConfig{}, errors.New("NM_ADMIN_ADDRESS must use a loopback IP address")
	}
	originText := envOrDefault("NM_ADMIN_ORIGIN", "http://"+address)
	origin, err := url.Parse(originText)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Host == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.String() != originText {
		return RuntimeConfig{}, errors.New("NM_ADMIN_ORIGIN must be an exact canonical HTTP or HTTPS origin")
	}
	if origin.Scheme == "http" {
		originHost := origin.Hostname()
		originIP, parseErr := netip.ParseAddr(originHost)
		if parseErr != nil || !originIP.IsLoopback() {
			return RuntimeConfig{}, errors.New("HTTP NM_ADMIN_ORIGIN must use a loopback IP address")
		}
	}
	account, err := loadAccount()
	if err != nil {
		return RuntimeConfig{}, err
	}
	recoveryCodeEnabled, err := loadRecoveryCodeSwitch()
	if err != nil {
		return RuntimeConfig{}, err
	}
	trustedProxies, err := parseTrustedProxyCIDRs(os.Getenv("NM_ADMIN_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return RuntimeConfig{}, err
	}
	databasePath := envOrDefault("NM_DATABASE_PATH", defaultDatabasePath)
	return RuntimeConfig{
		Address: address, ExpectedOrigin: originText, DatabasePath: databasePath,
		AuthorityKeyDirectory: envOrDefault(
			"NM_AUTHORITY_KEY_DIR", filepath.Join(filepath.Dir(databasePath), "authority-keys")),
		Account: account, RecoveryCodeEnabled: recoveryCodeEnabled,
		TrustedProxyCIDRs: trustedProxies,
		ShutdownTimeout:   10 * time.Second,
	}, nil
}

// loadAccount requires every administrator credential up front. A partially
// configured console refuses to start instead of falling back to a weaker mode.
func loadAccount() (Account, error) {
	name := strings.TrimSpace(os.Getenv("NM_ADMIN_USERNAME"))
	if name == "" || len(name) > maxAccountNameBytes || !printableName(name) {
		return Account{}, fmt.Errorf(
			"NM_ADMIN_USERNAME must be 1 through %d bytes without spaces or control characters",
			maxAccountNameBytes)
	}
	hash, err := parsePasswordHash(os.Getenv("NM_ADMIN_PASSWORD_HASH"))
	if err != nil {
		return Account{}, fmt.Errorf("NM_ADMIN_PASSWORD_HASH: %w", err)
	}
	secret, err := parseTOTPSecret(os.Getenv("NM_ADMIN_TOTP_SECRET"))
	if err != nil {
		return Account{}, fmt.Errorf("NM_ADMIN_TOTP_SECRET: %w", err)
	}
	return Account{Name: name, PasswordHash: hash, TOTPSecret: secret}, nil
}

func printableName(name string) bool {
	for index := 0; index < len(name); index++ {
		if name[index] <= ' ' || name[index] == 0x7f {
			return false
		}
	}
	return true
}

// loadRecoveryCodeSwitch keeps the startup one-time code available by default. It
// is the escape hatch for a lost authenticator device, and it does not widen the
// trust boundary: reading the code requires reading the container log, which
// already requires host access to the authority key directory.
func loadRecoveryCodeSwitch() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NM_ADMIN_RECOVERY_CODE"))) {
	case "", "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, errors.New("NM_ADMIN_RECOVERY_CODE must be on or off")
	}
}

func parseTrustedProxyCIDRs(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix != prefix.Masked() || part != prefix.String() {
			return nil, errors.New(
				"NM_ADMIN_TRUSTED_PROXY_CIDRS must contain canonical comma-separated CIDR prefixes")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
