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

type AbuseLimitOverrides struct {
	MembershipAttemptsPerMinute int
	RotationAttemptsPerMinute   int
	RateLimitMaxClientBuckets   int
	RelayAuthAttemptsPerMinute  int
	RelayAuthMaxClientBuckets   int
	RelayAuthMaxConcurrent      int
	RelayAuthFrameTimeout       time.Duration
}

type Config struct {
	Address            string
	DatabasePath       string
	ShutdownTimeout    time.Duration
	ReadHeaderTimeout  time.Duration
	RequestReadTimeout time.Duration
	TLSCertFile        string
	TLSKeyFile         string
	TrustedProxyCIDRs  []netip.Prefix
	AbuseLimits        AbuseLimitOverrides
}

func Load() (Config, error) {
	cfg := Config{
		Address:            envOrDefault("NM_ADDRESS", defaultAddress),
		DatabasePath:       envOrDefault("NM_DATABASE_PATH", defaultDatabasePath),
		ShutdownTimeout:    defaultShutdownTimeout,
		ReadHeaderTimeout:  5 * time.Second,
		RequestReadTimeout: 10 * time.Second,
	}

	if raw := os.Getenv("NM_SHUTDOWN_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := parsePositiveInteger("NM_SHUTDOWN_TIMEOUT_SECONDS", raw, 86_400)
		if err != nil {
			return Config{}, err
		}
		cfg.ShutdownTimeout = time.Duration(seconds) * time.Second
	}
	if raw := os.Getenv("NM_READ_HEADER_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := parsePositiveInteger("NM_READ_HEADER_TIMEOUT_SECONDS", raw, 86_400)
		if err != nil {
			return Config{}, err
		}
		cfg.ReadHeaderTimeout = time.Duration(seconds) * time.Second
	}
	if raw := os.Getenv("NM_REQUEST_READ_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := parsePositiveInteger("NM_REQUEST_READ_TIMEOUT_SECONDS", raw, 86_400)
		if err != nil {
			return Config{}, err
		}
		cfg.RequestReadTimeout = time.Duration(seconds) * time.Second
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

	integerLimits := []struct {
		name        string
		destination *int
		maximum     int
	}{
		{"NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE", &cfg.AbuseLimits.MembershipAttemptsPerMinute, 1_000_000},
		{"NM_ROTATION_ATTEMPTS_PER_MINUTE", &cfg.AbuseLimits.RotationAttemptsPerMinute, 1_000_000},
		{"NM_RATE_LIMIT_MAX_CLIENT_BUCKETS", &cfg.AbuseLimits.RateLimitMaxClientBuckets, 1_000_000},
		{"NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE", &cfg.AbuseLimits.RelayAuthAttemptsPerMinute, 1_000_000},
		{"NM_RELAY_AUTH_MAX_CLIENT_BUCKETS", &cfg.AbuseLimits.RelayAuthMaxClientBuckets, 1_000_000},
		{"NM_RELAY_AUTH_MAX_CONCURRENT", &cfg.AbuseLimits.RelayAuthMaxConcurrent, 65_536},
	}
	for _, limit := range integerLimits {
		raw := os.Getenv(limit.name)
		if raw == "" {
			continue
		}
		value, err := parsePositiveInteger(limit.name, raw, limit.maximum)
		if err != nil {
			return Config{}, err
		}
		*limit.destination = value
	}
	if raw := os.Getenv("NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := parsePositiveInteger(
			"NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS", raw, 86_400)
		if err != nil {
			return Config{}, err
		}
		cfg.AbuseLimits.RelayAuthFrameTimeout = time.Duration(seconds) * time.Second
	}
	return cfg, nil
}

func parsePositiveInteger(name string, raw string, maximum int) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be an integer from 1 through %d", name, maximum)
	}
	return value, nil
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
