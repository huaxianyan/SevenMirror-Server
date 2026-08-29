package workspacebackup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
)

func TestWorkspaceBackupRestoresRegistryBoundAuthority(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	liveRegistry := filepath.Join(root, "live", "registry.sqlite")
	if err := os.MkdirAll(filepath.Dir(liveRegistry), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := admission.Open(ctx, liveRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authorityDirectory := filepath.Join(root, "live", "authority")
	generated, err := membership.GenerateAuthority(authorityDirectory)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := store.CreateWorkspace(ctx, generated.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssuePairingCode(
		ctx, workspace, admission.DeviceChrome, "Backup Browser", time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}

	backupDirectory := filepath.Join(root, "backup")
	backup, err := Create(ctx, store, backupDirectory, workspace, authorityDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if backup.AuthorityKeyID != generated.KeyID {
		t.Fatalf("backup authority key ID=%q, want %q", backup.AuthorityKeyID, generated.KeyID)
	}
	if _, err := Verify(ctx, backupDirectory, workspace); err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreTo(
		ctx, backupDirectory, workspace,
		filepath.Join(backupDirectory, "nested-registry.sqlite"),
		filepath.Join(root, "rejected-authority")); err == nil {
		t.Fatal("restore destination inside the backup directory was accepted")
	}

	restoredRegistry := filepath.Join(root, "restored", "registry.sqlite")
	restoredKeyDirectory := filepath.Join(root, "restored", "authority")
	restored, err := RestoreTo(
		ctx, backupDirectory, workspace, restoredRegistry, restoredKeyDirectory)
	if err != nil || restored.AuthorityExisted {
		t.Fatalf("restored workspace=%+v error=%v", restored, err)
	}
	publicKey, err := admission.InspectRegistryBackup(ctx, restoredRegistry, workspace)
	if err != nil || publicKey != generated.PublicKey {
		t.Fatalf("restored registry authority=%x error=%v", publicKey, err)
	}
	privateKey, err := membership.LoadAuthorityPrivateKey(restored.AuthorityKeyPath, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(privateKey)

	registry, err := os.OpenFile(backup.RegistryPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.WriteAt([]byte{0xff}, 128); err != nil {
		registry.Close()
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, backupDirectory, workspace); err == nil {
		t.Fatal("damaged registry backup unexpectedly verified")
	}
}
