package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddress         = "127.0.0.1:8080"
	defaultDatabasePath    = "data/syncnotifications.db"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	Address           string
	DatabasePath      string
	ShutdownTimeout   time.Duration
	TLSCertFile       string
	TLSKeyFile        string
	TrustedProxyCIDRs []netip.Prefix
}

func Load() (Config, error) {
	cfg := Config{
		Address:         envOrDefault("NM_ADDRESS", defaultAddress),
		DatabasePath:    envOrDefault("NM_DATABASE_PATH", defaultDatabasePath),
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if raw := os.Getenv("NM_SHUTDOWN_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 {
			return Config{}, fmt.Errorf("NM_SHUTDOWN_TIMEOUT_SECONDS must be a positive integer")
		}
		cfg.ShutdownTimeout = time.Duration(seconds) * time.Second
	}

	cfg.TLSCertFile = os.Getenv("NM_TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("NM_TLS_KEY_FILE")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("NM_TLS_CERT_FILE and NM_TLS_KEY_FILE must be configured together")
	}

	trustedProxies, err := parseTrustedProxyCIDRs(os.Getenv("NM_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	cfg.TrustedProxyCIDRs = trustedProxies
	return cfg, nil
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
			prefix != prefix.Masked() ||
			part != prefix.String() {
			return nil, fmt.Errorf("NM_TRUSTED_PROXY_CIDRS must contain canonical comma-separated CIDR prefixes")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
