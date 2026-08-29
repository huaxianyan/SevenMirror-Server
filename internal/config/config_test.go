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
}

func TestLoadRejectsInvalidTimeout(t *testing.T) {
	t.Setenv("NM_SHUTDOWN_TIMEOUT_SECONDS", "zero")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want validation error")
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
