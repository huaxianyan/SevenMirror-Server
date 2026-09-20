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

// The console keeps no credential environment variables: an account comes from the
// registry, and a fresh one starts on the built-in default. Configuration that
// would have carried credentials must therefore not change what loads.
func TestRuntimeConfigIgnoresCredentialEnvironment(t *testing.T) {
	t.Setenv("NM_ADMIN_USERNAME", "operator")
	t.Setenv("NM_ADMIN_PASSWORD_HASH", testPasswordHashString(t, testPassword))
	t.Setenv("NM_ADMIN_TOTP_SECRET", testSecret)
	config, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.ExpectedOrigin != "http://127.0.0.1:8081" || !config.RecoveryCodeEnabled {
		t.Fatalf("runtime config = %+v", config)
	}
}

func TestLoadRuntimeConfigRejectsNonCanonicalProxyAndUnknownSwitch(t *testing.T) {
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
