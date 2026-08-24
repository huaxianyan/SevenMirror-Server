package membership

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuthorityBackupVerifiesAndRestoresExactKey(t *testing.T) {
	liveDirectory := filepath.Join(t.TempDir(), "live")
	generated, err := GenerateAuthority(liveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := bytes.Repeat([]byte{0x42}, workspaceIDSize)
	backupDirectory := filepath.Join(t.TempDir(), "backup")

	backup, err := CreateAuthorityBackup(
		backupDirectory,
		workspaceID,
		generated.Path,
		generated.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if backup.KeyID != generated.KeyID {
		t.Fatalf("backup key ID = %q, want %q", backup.KeyID, generated.KeyID)
	}
	if _, err := VerifyAuthorityBackup(backupDirectory, workspaceID, generated.PublicKey); err != nil {
		t.Fatal(err)
	}

	restoreDirectory := filepath.Join(t.TempDir(), "restored")
	restored, err := RestoreAuthorityBackup(
		backupDirectory,
		restoreDirectory,
		workspaceID,
		generated.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restored.AlreadyPresent {
		t.Fatal("first restore unexpectedly reported an existing key")
	}
	original, err := os.ReadFile(generated.Path)
	if err != nil {
		t.Fatal(err)
	}
	restoredBytes, err := os.ReadFile(restored.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredBytes, original) {
		t.Fatal("restored authority key bytes differ from the live key")
	}
	private, err := LoadAuthorityPrivateKey(restored.PrivateKeyPath, generated.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)

	idempotent, err := RestoreAuthorityBackup(
		backupDirectory,
		restoreDirectory,
		workspaceID,
		generated.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !idempotent.AlreadyPresent {
		t.Fatal("exact repeated restore was not idempotent")
	}
}

func TestAuthorityBackupRejectsWrongRegistryAuthorityAndDamagedFiles(t *testing.T) {
	liveDirectory := filepath.Join(t.TempDir(), "live")
	generated, err := GenerateAuthority(liveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateAuthority(liveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := bytes.Repeat([]byte{0x24}, workspaceIDSize)
	backupDirectory := filepath.Join(t.TempDir(), "backup")
	backup, err := CreateAuthorityBackup(
		backupDirectory,
		workspaceID,
		generated.Path,
		generated.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyAuthorityBackup(backupDirectory, workspaceID, other.PublicKey); err == nil {
		t.Fatal("backup unexpectedly matched a different registry authority")
	}
	wrongWorkspace := bytes.Repeat([]byte{0x25}, workspaceIDSize)
	if _, err := VerifyAuthorityBackup(
		backupDirectory,
		wrongWorkspace,
		generated.PublicKey,
	); err == nil {
		t.Fatal("backup unexpectedly matched a different workspace")
	}

	keyBytes, err := os.ReadFile(backup.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes[len(keyBytes)-1] ^= 1
	if err := os.WriteFile(backup.PrivateKeyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAuthorityBackup(
		backupDirectory,
		workspaceID,
		generated.PublicKey,
	); err == nil {
		t.Fatal("damaged backup private key unexpectedly verified")
	}
}

func TestAuthorityRestoreRefusesExistingInvalidKey(t *testing.T) {
	liveDirectory := filepath.Join(t.TempDir(), "live")
	generated, err := GenerateAuthority(liveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := bytes.Repeat([]byte{0x36}, workspaceIDSize)
	backupDirectory := filepath.Join(t.TempDir(), "backup")
	if _, err := CreateAuthorityBackup(
		backupDirectory,
		workspaceID,
		generated.Path,
		generated.PublicKey,
	); err != nil {
		t.Fatal(err)
	}

	restoreDirectory := filepath.Join(t.TempDir(), "restore")
	if err := os.Mkdir(restoreDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(
		restoreDirectory,
		authorityPrivateKeyFileName(generated.KeyID),
	)
	invalid := []byte("existing-invalid-key")
	if err := os.WriteFile(destination, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(destination, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RestoreAuthorityBackup(
		backupDirectory,
		restoreDirectory,
		workspaceID,
		generated.PublicKey,
	); err == nil {
		t.Fatal("restore unexpectedly replaced an existing invalid key")
	}
	remaining, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remaining, invalid) {
		t.Fatal("restore modified an existing invalid key")
	}
}
