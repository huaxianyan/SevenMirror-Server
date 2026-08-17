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
