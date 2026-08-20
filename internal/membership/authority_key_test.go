package membership

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAuthorityCreatesExclusiveProtectedMatchingPKCS8(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "authority-keys")
	generated, err := GenerateAuthority(directory)
	if err != nil {
		t.Fatal(err)
	}
	if generated.KeyID != AuthorityKeyID(generated.PublicKey) {
		t.Fatalf("key ID = %q", generated.KeyID)
	}
	if filepath.Dir(generated.Path) != directory {
		t.Fatalf("key path = %q", generated.Path)
	}
	info, err := os.Stat(generated.Path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
	private, err := LoadAuthorityPrivateKey(generated.Path, generated.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	message := []byte("authority-key-self-test")
	signature := ed25519.Sign(private, message)
	if !ed25519.Verify(generated.PublicKey[:], message, signature) {
		t.Fatal("generated authority key cannot verify its own signature")
	}

	second, err := GenerateAuthority(directory)
	if err != nil {
		t.Fatal(err)
	}
	if second.Path == generated.Path || bytes.Equal(second.PublicKey[:], generated.PublicKey[:]) {
		t.Fatal("independent authority generation reused key material")
	}
}

func TestLoadAuthorityPrivateKeyRejectsMismatchCorruptionAndUnsafeMode(t *testing.T) {
	directory := t.TempDir()
	generated, err := GenerateAuthority(directory)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateAuthority(directory)
	if err != nil {
		t.Fatal(err)
	}
	if private, err := LoadAuthorityPrivateKey(generated.Path, other.PublicKey); err == nil {
		clear(private)
		t.Fatal("mismatched public key unexpectedly accepted")
	}

	corruptPath := filepath.Join(directory, "corrupt.pk8")
	if err := os.WriteFile(corruptPath, []byte("not-pkcs8"), 0o600); err != nil {
		t.Fatal(err)
	}
	if private, err := LoadAuthorityPrivateKey(corruptPath, generated.PublicKey); err == nil {
		clear(private)
		t.Fatal("corrupt key unexpectedly accepted")
	}

	if runtime.GOOS != "windows" {
		symlinkPath := filepath.Join(directory, "authority-link.pk8")
		if err := os.Symlink(generated.Path, symlinkPath); err != nil {
			t.Fatal(err)
		}
		if private, err := LoadAuthorityPrivateKey(symlinkPath, generated.PublicKey); err == nil {
			clear(private)
			t.Fatal("authority key symlink unexpectedly accepted")
		}
		if err := os.Chmod(generated.Path, 0o640); err != nil {
			t.Fatal(err)
		}
		if private, err := LoadAuthorityPrivateKey(generated.Path, generated.PublicKey); err == nil {
			clear(private)
			t.Fatal("unsafe key permissions unexpectedly accepted")
		}
	}
}
