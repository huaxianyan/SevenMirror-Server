package admission

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlineRegistryBackupIncludesCommittedWALState(t *testing.T) {
	ctx := context.Background()
	live := openTestStore(t, tempDatabasePath(t))
	now := time.Now()
	workspace, err := live.CreateWorkspace(ctx, testAuthorityPublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.IssuePairingCode(
		ctx, workspace, DeviceChrome, "Backup Browser", now, time.Minute); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "registry.sqlite")
	if err := live.BackupRegistry(ctx, destination); err != nil {
		t.Fatal(err)
	}
	if err := live.BackupRegistry(ctx, destination); err == nil {
		t.Fatal("existing registry backup was overwritten")
	}
	if info, err := os.Stat(destination); err != nil || info.Size() == 0 {
		t.Fatalf("registry backup size=%v error=%v", info, err)
	}

	snapshot, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if publicKey, err := snapshot.WorkspaceAuthorityPublicKey(ctx, workspace); err != nil ||
		publicKey != testAuthorityPublicKey() {
		t.Fatalf("snapshot authority=%x error=%v", publicKey, err)
	}
	var pairingCodes int
	if err := snapshot.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pairing_codes WHERE workspace_id = ?`, workspace[:]).Scan(&pairingCodes); err != nil || pairingCodes != 1 {
		t.Fatalf("snapshot pairing codes=%d error=%v", pairingCodes, err)
	}
	if err := snapshot.BackupRegistry(ctx, ""); err == nil {
		t.Fatal("empty registry backup destination was accepted")
	}
}
