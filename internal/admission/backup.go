package admission

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	authority "github.com/huaxianyan/SyncNotifications-Server/internal/membership"
	"modernc.org/sqlite"
)

type sqliteOnlineBackuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

// InspectRegistryBackup verifies SQLite integrity and the exact supported schema,
// then reads the workspace authority from the snapshot without running migrations.
func InspectRegistryBackup(
	ctx context.Context,
	path string,
	workspaceID WorkspaceID,
) (authority.AuthorityPublicKey, error) {
	if path == "" {
		return authority.AuthorityPublicKey{}, errors.New("registry backup path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("resolve registry backup path: %w", err)
	}
	uriPath := filepath.ToSlash(absolutePath)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	query.Set("immutable", "1")
	query.Set("mode", "ro")
	uri.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("open registry backup: %w", err)
	}
	defer database.Close()
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("run registry backup integrity check: %w", err)
	}
	if integrity != "ok" {
		return authority.AuthorityPublicKey{}, errors.New("registry backup integrity check failed")
	}
	foreignKeyRows, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("run registry backup foreign-key check: %w", err)
	}
	hasForeignKeyViolation := foreignKeyRows.Next()
	rowsErr := foreignKeyRows.Err()
	if closeErr := foreignKeyRows.Close(); closeErr != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("close registry backup foreign-key check: %w", closeErr)
	}
	if rowsErr != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("read registry backup foreign-key check: %w", rowsErr)
	}
	if hasForeignKeyViolation {
		return authority.AuthorityPublicKey{}, errors.New("registry backup foreign-key check failed")
	}
	var version int
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("read registry backup schema: %w", err)
	}
	if version != currentSchemaVersion {
		return authority.AuthorityPublicKey{}, fmt.Errorf(
			"registry backup schema version is %d, want %d", version, currentSchemaVersion)
	}
	var encoded []byte
	if err := database.QueryRowContext(ctx,
		`SELECT authority_public_key FROM workspaces WHERE id = ?`, workspaceID[:]).Scan(&encoded); err != nil {
		return authority.AuthorityPublicKey{}, fmt.Errorf("read registry backup authority: %w", err)
	}
	if len(encoded) != len(authority.AuthorityPublicKey{}) {
		return authority.AuthorityPublicKey{}, errors.New("registry backup authority is invalid")
	}
	var publicKey authority.AuthorityPublicKey
	copy(publicKey[:], encoded)
	return publicKey, nil
}

// BackupRegistry writes one transactionally consistent SQLite snapshot while
// the live WAL database remains open. The destination must not already exist.
func (s *Store) BackupRegistry(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("registry backup destination is required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("registry backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat registry backup destination: %w", err)
	}

	destinationFile, err := os.OpenFile(
		destination, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create protected registry backup: %w", err)
	}
	if err := destinationFile.Chmod(0o600); err != nil {
		destinationFile.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("protect registry backup: %w", err)
	}
	if err := destinationFile.Close(); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("close empty registry backup: %w", err)
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.Remove(destination)
		}
	}()
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open registry backup connection: %w", err)
	}
	defer connection.Close()
	if err := connection.Raw(func(driverConnection any) error {
		backuper, ok := driverConnection.(sqliteOnlineBackuper)
		if !ok {
			return errors.New("SQLite driver does not support online backup")
		}
		backup, err := backuper.NewBackup(destination)
		if err != nil {
			return err
		}
		for more := true; more; {
			more, err = backup.Step(-1)
			if err != nil {
				_ = backup.Finish()
				return err
			}
		}
		return backup.Finish()
	}); err != nil {
		return fmt.Errorf("create online registry backup: %w", err)
	}
	file, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open registry backup for sync: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync registry backup: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close registry backup: %w", err)
	}
	removePartial = false
	return nil
}
