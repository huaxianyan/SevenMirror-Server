package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("NM_ADDRESS", "")
	t.Setenv("NM_SHUTDOWN_TIMEOUT_SECONDS", "")
	t.Setenv("NM_DATABASE_PATH", "")

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
