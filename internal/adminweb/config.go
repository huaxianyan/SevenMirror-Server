package adminweb

import (
	"errors"
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
)

type RuntimeConfig struct {
	Address               string
	ExpectedOrigin        string
	DatabasePath          string
	AuthorityKeyDirectory string
	ShutdownTimeout       time.Duration
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
	databasePath := envOrDefault("NM_DATABASE_PATH", defaultDatabasePath)
	return RuntimeConfig{
		Address: address, ExpectedOrigin: originText, DatabasePath: databasePath,
		AuthorityKeyDirectory: envOrDefault(
			"NM_AUTHORITY_KEY_DIR", filepath.Join(filepath.Dir(databasePath), "authority-keys")),
		ShutdownTimeout: 10 * time.Second,
	}, nil
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
