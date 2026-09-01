package adminweb

import (
	"path/filepath"
	"testing"
)

func TestRuntimeConfigDefaultsToLoopbackOnly(t *testing.T) {
	t.Setenv("NM_ADMIN_ADDRESS", "")
	t.Setenv("NM_ADMIN_ORIGIN", "")
	t.Setenv("NM_DATABASE_PATH", "")
	t.Setenv("NM_AUTHORITY_KEY_DIR", "")
	config, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != "127.0.0.1:8081" ||
		config.ExpectedOrigin != "http://127.0.0.1:8081" ||
		config.DatabasePath != "data/syncnotifications.db" ||
		config.AuthorityKeyDirectory != filepath.Join("data", "authority-keys") {
		t.Fatalf("default admin config=%+v", config)
	}
}

func TestRuntimeConfigRejectsNonLoopbackListenerAndPlaintextExternalOrigin(t *testing.T) {
	t.Setenv("NM_ADMIN_ADDRESS", "0.0.0.0:8081")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("non-loopback admin listener was accepted")
	}
	t.Setenv("NM_ADMIN_ADDRESS", "127.0.0.1:8081")
	t.Setenv("NM_ADMIN_ORIGIN", "http://admin.example.com")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("plaintext external admin origin was accepted")
	}
	t.Setenv("NM_ADMIN_ORIGIN", "https://admin.example.com")
	if _, err := LoadRuntimeConfig(); err != nil {
		t.Fatalf("HTTPS external admin origin error=%v", err)
	}
}
