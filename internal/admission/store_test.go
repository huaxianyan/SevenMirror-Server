package admission

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPairingCodeRegistersExactlyOnePersistentDevice(t *testing.T) {
	ctx := context.Background()
	path := tempDatabasePath(t)
	store := openTestStore(t, path)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("database mode = %o, want 600", info.Mode().Perm())
		}
	}
	now := time.UnixMilli(1_800_000_000_000)
	workspace, err := store.CreateWorkspace(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssuePairingCode(ctx, workspace, DeviceAndroid, "Pixel", now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Pixel",
		E2EEPublicKey: testPublicKey(), Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.AuthToken) != authTokenBytes {
		t.Fatalf("auth token has %d bytes", len(registered.AuthToken))
	}
	pairingSecret, _ := base64.RawURLEncoding.DecodeString(code)
	for _, databaseFile := range []string{path, path + "-wal"} {
		contents, readErr := os.ReadFile(databaseFile)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, pairingSecret) || bytes.Contains(contents, registered.AuthToken) {
			t.Fatalf("raw credential persisted in %s", databaseFile)
		}
	}
	if _, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Pixel",
		E2EEPublicKey: testPublicKey(), Now: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("reused code error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path)
	identity, err := reopened.Authenticate(ctx, registered.WorkspaceID, registered.DeviceID,
		registered.AuthToken, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceType != DeviceAndroid || identity.DeviceName != "Pixel" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	wrongToken := append([]byte(nil), registered.AuthToken...)
	wrongToken[0] ^= 1
	if _, err := reopened.Authenticate(ctx, registered.WorkspaceID, registered.DeviceID,
		wrongToken, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestPairingCodeConstraintsDoNotLeakOrConsumeOnWrongType(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "Browser", now, time.Minute)

	_, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceAndroid, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	})
	if !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("wrong type error = %v", err)
	}
	if _, err := store.Register(ctx, Registration{
		PairingCode: code, DeviceType: DeviceChrome, DeviceName: "Browser",
		E2EEPublicKey: testPublicKey(), Now: now,
	}); err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}

	expired, _ := store.IssuePairingCode(ctx, workspace, DeviceChrome, "", now, time.Second)
	if _, err := store.Register(ctx, Registration{
		PairingCode: expired, DeviceType: DeviceChrome, DeviceName: "Late",
		E2EEPublicKey: testPublicKey(), Now: now.Add(time.Second),
	}); !errors.Is(err, ErrInvalidPairingCode) {
		t.Fatalf("expired code error = %v", err)
	}
}

func TestConcurrentPairingCodeConsumptionAllowsOneRegistration(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, tempDatabasePath(t))
	now := time.UnixMilli(1_800_000_000_000)
	workspace, _ := store.CreateWorkspace(ctx, now)
	code, _ := store.IssuePairingCode(ctx, workspace, DeviceAndroid, "", now, time.Minute)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := store.Register(ctx, Registration{
				PairingCode: code, DeviceType: DeviceAndroid,
				DeviceName: fmt.Sprintf("phone-%d", index), E2EEPublicKey: testPublicKey(), Now: now,
			})
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrInvalidPairingCode) {
			rejected++
		} else {
			t.Fatalf("unexpected registration error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejected=%d", successes, rejected)
	}
}

func TestOpenRejectsNewerSchemaVersion(t *testing.T) {
	path := tempDatabasePath(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (2, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), path); err == nil {
		store.Close()
		t.Fatal("newer schema version unexpectedly accepted")
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func tempDatabasePath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/admission.db"
}

func testPublicKey() []byte {
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	return elliptic.Marshal(elliptic.P256(), x, y)
}
