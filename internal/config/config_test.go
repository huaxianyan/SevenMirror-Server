package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("NM_ADDRESS", "")
	t.Setenv("NM_SHUTDOWN_TIMEOUT_SECONDS", "")
	t.Setenv("NM_DATABASE_PATH", "")
	t.Setenv("NM_TLS_CERT_FILE", "")
	t.Setenv("NM_TLS_KEY_FILE", "")
	t.Setenv("NM_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("NM_READ_HEADER_TIMEOUT_SECONDS", "")
	t.Setenv("NM_REQUEST_READ_TIMEOUT_SECONDS", "")
	t.Setenv("NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE", "")
	t.Setenv("NM_ROTATION_ATTEMPTS_PER_MINUTE", "")
	t.Setenv("NM_RATE_LIMIT_MAX_CLIENT_BUCKETS", "")
	t.Setenv("NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE", "")
	t.Setenv("NM_RELAY_AUTH_MAX_CLIENT_BUCKETS", "")
	t.Setenv("NM_RELAY_AUTH_MAX_CONCURRENT", "")
	t.Setenv("NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Address != defaultAddress {
		t.Fatalf("Address = %q, want %q", cfg.Address, defaultAddress)
	}
	if cfg.DatabasePath != defaultDatabasePath {
		t.Fatalf("DatabasePath = %q, want %q", cfg.DatabasePath, defaultDatabasePath)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.RequestReadTimeout != 10*time.Second {
		t.Fatalf("HTTP read timeouts = %s/%s, want 5s/10s",
			cfg.ReadHeaderTimeout, cfg.RequestReadTimeout)
	}
	if cfg.AbuseLimits != (AbuseLimitOverrides{}) {
		t.Fatalf("AbuseLimits = %+v, want no overrides", cfg.AbuseLimits)
	}
}

func TestLoadRejectsInvalidTimeout(t *testing.T) {
	t.Setenv("NM_SHUTDOWN_TIMEOUT_SECONDS", "zero")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadParsesAbuseLimitOverrides(t *testing.T) {
	t.Setenv("NM_READ_HEADER_TIMEOUT_SECONDS", "2")
	t.Setenv("NM_REQUEST_READ_TIMEOUT_SECONDS", "3")
	t.Setenv("NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE", "3")
	t.Setenv("NM_ROTATION_ATTEMPTS_PER_MINUTE", "4")
	t.Setenv("NM_RATE_LIMIT_MAX_CLIENT_BUCKETS", "5")
	t.Setenv("NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE", "6")
	t.Setenv("NM_RELAY_AUTH_MAX_CLIENT_BUCKETS", "7")
	t.Setenv("NM_RELAY_AUTH_MAX_CONCURRENT", "8")
	t.Setenv("NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS", "9")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReadHeaderTimeout != 2*time.Second || cfg.RequestReadTimeout != 3*time.Second ||
		cfg.AbuseLimits.MembershipAttemptsPerMinute != 3 ||
		cfg.AbuseLimits.RotationAttemptsPerMinute != 4 ||
		cfg.AbuseLimits.RateLimitMaxClientBuckets != 5 ||
		cfg.AbuseLimits.RelayAuthAttemptsPerMinute != 6 ||
		cfg.AbuseLimits.RelayAuthMaxClientBuckets != 7 ||
		cfg.AbuseLimits.RelayAuthMaxConcurrent != 8 ||
		cfg.AbuseLimits.RelayAuthFrameTimeout != 9*time.Second {
		t.Fatalf("parsed limits = %+v, read header = %s", cfg.AbuseLimits, cfg.ReadHeaderTimeout)
	}
}

func TestLoadRejectsInvalidAbuseLimit(t *testing.T) {
	t.Setenv("NM_RELAY_AUTH_MAX_CONCURRENT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid abuse limit error")
	}
}

func TestLoadRequiresCompleteTLSPair(t *testing.T) {
	t.Setenv("NM_TLS_CERT_FILE", "server.pem")
	t.Setenv("NM_TLS_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want incomplete TLS configuration error")
	}
}

func TestLoadRejectsNonCanonicalTrustedProxyCIDR(t *testing.T) {
	t.Setenv("NM_TRUSTED_PROXY_CIDRS", "127.0.0.1/8")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid trusted proxy configuration")
	}
}

func TestLoadAcceptsCanonicalTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("NM_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[0].String() != "127.0.0.1/32" ||
		cfg.TrustedProxyCIDRs[1].String() != "::1/128" {
		t.Fatalf("TrustedProxyCIDRs = %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadAcceptsCompleteTLSPair(t *testing.T) {
	t.Setenv("NM_TLS_CERT_FILE", "server.pem")
	t.Setenv("NM_TLS_KEY_FILE", "server-key.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TLSCertFile != "server.pem" || cfg.TLSKeyFile != "server-key.pem" {
		t.Fatalf("TLS files = %q, %q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}
