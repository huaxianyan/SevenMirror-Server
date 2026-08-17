package admission

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	pairingSecretBytes = 24
	authTokenBytes     = 32
	maxDeviceNameBytes = 100
)

var (
	ErrInvalidPairingCode  = errors.New("invalid or expired pairing code")
	ErrInvalidRegistration = errors.New("invalid device registration")
	ErrUnauthorized        = errors.New("device authentication failed")
	ErrDeviceNotFound      = errors.New("device not found")
)

type WorkspaceID [16]byte
type DeviceID [16]byte

type DeviceType string

const (
	DeviceAndroid DeviceType = "android"
	DeviceChrome  DeviceType = "chrome"
)

type Store struct {
	db *sql.DB
}

type Registration struct {
	PairingCode   string
	DeviceType    DeviceType
	DeviceName    string
	E2EEPublicKey []byte
	Now           time.Time
}

type RegisteredDevice struct {
	WorkspaceID WorkspaceID
	DeviceID    DeviceID
	AuthToken   []byte
}

type DeviceIdentity struct {
	WorkspaceID WorkspaceID
	DeviceID    DeviceID
	DeviceType  DeviceType
	DeviceName  string
}

type DeviceSummary struct {
	Reference  string
	DeviceType DeviceType
	DeviceName string
	Revoked    bool
}

func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create admission database: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect admission database: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close admission database bootstrap file: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open admission database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateWorkspace(ctx context.Context, now time.Time) (WorkspaceID, error) {
	var id WorkspaceID
	if _, err := rand.Read(id[:]); err != nil {
		return WorkspaceID{}, fmt.Errorf("generate workspace id: %w", err)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO workspaces (id, created_at_ms) VALUES (?, ?)`, id[:], unixMillis(now))
	if err != nil {
		return WorkspaceID{}, fmt.Errorf("create workspace: %w", err)
	}
	return id, nil
}

func (s *Store) IssuePairingCode(
	ctx context.Context,
	workspaceID WorkspaceID,
	deviceType DeviceType,
	boundName string,
	now time.Time,
	ttl time.Duration,
) (string, error) {
	if err := validateDeviceType(deviceType); err != nil {
		return "", err
	}
	if boundName != "" {
		if err := validateDeviceName(boundName); err != nil {
			return "", err
		}
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return "", errors.New("pairing code TTL must be in (0, 24h]")
	}
	secret := make([]byte, pairingSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate pairing code: %w", err)
	}
	hash := sha256.Sum256(secret)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pairing_codes
		(code_hash, workspace_id, device_type, bound_name, created_at_ms, expires_at_ms)
		VALUES (?, ?, ?, NULLIF(?, ''), ?, ?)`,
		hash[:], workspaceID[:], string(deviceType), boundName,
		unixMillis(now), unixMillis(now.Add(ttl)))
	if err != nil {
		return "", fmt.Errorf("store pairing code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func (s *Store) Register(ctx context.Context, input Registration) (RegisteredDevice, error) {
	if err := validateDeviceType(input.DeviceType); err != nil {
		return RegisteredDevice{}, ErrInvalidPairingCode
	}
	if err := validateDeviceName(input.DeviceName); err != nil {
		return RegisteredDevice{}, fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
	}
	if len(input.E2EEPublicKey) != 65 || input.E2EEPublicKey[0] != 0x04 {
		return RegisteredDevice{}, fmt.Errorf("%w: E2EE public key must be a 65-byte uncompressed P-256 point", ErrInvalidRegistration)
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), input.E2EEPublicKey); x == nil || y == nil {
		return RegisteredDevice{}, fmt.Errorf("%w: E2EE public key is not a valid P-256 point", ErrInvalidRegistration)
	}
	secret, err := base64.RawURLEncoding.DecodeString(input.PairingCode)
	if err != nil || len(secret) != pairingSecretBytes {
		return RegisteredDevice{}, ErrInvalidPairingCode
	}
	codeHash := sha256.Sum256(secret)

	var deviceID DeviceID
	if _, err := rand.Read(deviceID[:]); err != nil {
		return RegisteredDevice{}, fmt.Errorf("generate device id: %w", err)
	}
	authToken := make([]byte, authTokenBytes)
	if _, err := rand.Read(authToken); err != nil {
		return RegisteredDevice{}, fmt.Errorf("generate device credential: %w", err)
	}
	authHash := sha256.Sum256(authToken)
	nowMillis := unixMillis(input.Now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RegisteredDevice{}, fmt.Errorf("begin registration: %w", err)
	}
	defer tx.Rollback()

	var workspaceBytes []byte
	var expectedType string
	var boundName sql.NullString
	var expiresAt int64
	var consumedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT workspace_id, device_type, bound_name, expires_at_ms, consumed_at_ms
		FROM pairing_codes WHERE code_hash = ?`, codeHash[:]).Scan(
		&workspaceBytes, &expectedType, &boundName, &expiresAt, &consumedAt)
	if err != nil || len(workspaceBytes) != 16 || consumedAt.Valid || expiresAt <= nowMillis ||
		expectedType != string(input.DeviceType) || (boundName.Valid && boundName.String != input.DeviceName) {
		return RegisteredDevice{}, ErrInvalidPairingCode
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE pairing_codes SET consumed_at_ms = ?
		WHERE code_hash = ? AND consumed_at_ms IS NULL AND expires_at_ms > ?`,
		nowMillis, codeHash[:], nowMillis)
	if err != nil {
		return RegisteredDevice{}, fmt.Errorf("consume pairing code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return RegisteredDevice{}, ErrInvalidPairingCode
	}

	var workspaceID WorkspaceID
	copy(workspaceID[:], workspaceBytes)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO devices
		(workspace_id, id, device_type, device_name, auth_token_hash, e2ee_public_key,
		 registered_at_ms, last_online_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		workspaceID[:], deviceID[:], string(input.DeviceType), input.DeviceName,
		authHash[:], input.E2EEPublicKey, nowMillis, nowMillis)
	if err != nil {
		return RegisteredDevice{}, fmt.Errorf("register device: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RegisteredDevice{}, fmt.Errorf("commit registration: %w", err)
	}
	return RegisteredDevice{WorkspaceID: workspaceID, DeviceID: deviceID, AuthToken: authToken}, nil
}

func (s *Store) ListDevices(ctx context.Context, workspaceID WorkspaceID) ([]DeviceSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, device_type, device_name, revoked_at_ms IS NOT NULL
		FROM devices WHERE workspace_id = ? ORDER BY registered_at_ms, id`, workspaceID[:])
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	devices := make([]DeviceSummary, 0)
	references := make(map[string]struct{})
	for rows.Next() {
		var idBytes []byte
		var deviceType, deviceName string
		var revoked bool
		if err := rows.Scan(&idBytes, &deviceType, &deviceName, &revoked); err != nil {
			return nil, fmt.Errorf("read device: %w", err)
		}
		if len(idBytes) != len(DeviceID{}) {
			return nil, errors.New("stored device ID has invalid length")
		}
		var deviceID DeviceID
		copy(deviceID[:], idBytes)
		reference := deviceReference(workspaceID, deviceID)
		if _, exists := references[reference]; exists {
			return nil, errors.New("ambiguous device reference")
		}
		references[reference] = struct{}{}
		devices = append(devices, DeviceSummary{
			Reference:  reference,
			DeviceType: DeviceType(deviceType),
			DeviceName: deviceName,
			Revoked:    revoked,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return devices, nil
}

func (s *Store) RevokeDevice(
	ctx context.Context,
	workspaceID WorkspaceID,
	reference string,
	now time.Time,
) (bool, error) {
	if !validDeviceReference(reference) {
		return false, ErrDeviceNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM devices WHERE workspace_id = ?`, workspaceID[:])
	if err != nil {
		return false, fmt.Errorf("resolve device: %w", err)
	}
	var matched []byte
	for rows.Next() {
		var idBytes []byte
		if err := rows.Scan(&idBytes); err != nil {
			rows.Close()
			return false, fmt.Errorf("resolve device: %w", err)
		}
		if len(idBytes) != len(DeviceID{}) {
			rows.Close()
			return false, errors.New("stored device ID has invalid length")
		}
		var deviceID DeviceID
		copy(deviceID[:], idBytes)
		if deviceReference(workspaceID, deviceID) == reference {
			if matched != nil {
				rows.Close()
				return false, errors.New("ambiguous device reference")
			}
			matched = append([]byte(nil), idBytes...)
		}
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("resolve device: %w", err)
	}
	if matched == nil {
		return false, ErrDeviceNotFound
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE devices SET revoked_at_ms = ?
		WHERE workspace_id = ? AND id = ? AND revoked_at_ms IS NULL`,
		unixMillis(now), workspaceID[:], matched)
	if err != nil {
		return false, fmt.Errorf("revoke device: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoke device: %w", err)
	}
	return updated == 1, nil
}

func (s *Store) IsDeviceAuthorized(
	ctx context.Context,
	workspaceID WorkspaceID,
	deviceID DeviceID,
) (bool, error) {
	var authorized bool
	err := s.db.QueryRowContext(ctx, `
		SELECT revoked_at_ms IS NULL FROM devices WHERE workspace_id = ? AND id = ?`,
		workspaceID[:], deviceID[:]).Scan(&authorized)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read device authorization: %w", err)
	}
	return authorized, nil
}

func (s *Store) Authenticate(
	ctx context.Context,
	workspaceID WorkspaceID,
	deviceID DeviceID,
	authToken []byte,
	now time.Time,
) (DeviceIdentity, error) {
	if len(authToken) != authTokenBytes {
		return DeviceIdentity{}, ErrUnauthorized
	}
	hash := sha256.Sum256(authToken)
	var deviceType, deviceName string
	result, err := s.db.ExecContext(ctx, `
		UPDATE devices SET last_online_at_ms = ?
		WHERE workspace_id = ? AND id = ? AND auth_token_hash = ? AND revoked_at_ms IS NULL`,
		unixMillis(now), workspaceID[:], deviceID[:], hash[:])
	if err != nil {
		return DeviceIdentity{}, fmt.Errorf("authenticate device: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return DeviceIdentity{}, ErrUnauthorized
	}
	err = s.db.QueryRowContext(ctx, `
		SELECT device_type, device_name FROM devices
		WHERE workspace_id = ? AND id = ? AND auth_token_hash = ? AND revoked_at_ms IS NULL`,
		workspaceID[:], deviceID[:], hash[:]).Scan(&deviceType, &deviceName)
	if err != nil {
		return DeviceIdentity{}, ErrUnauthorized
	}
	return DeviceIdentity{
		WorkspaceID: workspaceID,
		DeviceID:    deviceID,
		DeviceType:  DeviceType(deviceType),
		DeviceName:  deviceName,
	}, nil
}

func (s *Store) initialize(ctx context.Context) error {
	for _, pragma := range []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA busy_timeout = 5000`,
	} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure admission database: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at_ms INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > 1 {
		return fmt.Errorf("database schema version %d is newer than supported version 1", version)
	}
	if version == 1 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE workspaces (
			id BLOB PRIMARY KEY CHECK(length(id) = 16),
			created_at_ms INTEGER NOT NULL
		) STRICT`,
		`CREATE TABLE pairing_codes (
			code_hash BLOB PRIMARY KEY CHECK(length(code_hash) = 32),
			workspace_id BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			device_type TEXT NOT NULL CHECK(device_type IN ('android', 'chrome')),
			bound_name TEXT,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL,
			consumed_at_ms INTEGER
		) STRICT`,
		`CREATE INDEX pairing_codes_expiry ON pairing_codes(expires_at_ms)`,
		`CREATE TABLE devices (
			workspace_id BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			id BLOB NOT NULL CHECK(length(id) = 16),
			device_type TEXT NOT NULL CHECK(device_type IN ('android', 'chrome')),
			device_name TEXT NOT NULL,
			auth_token_hash BLOB NOT NULL UNIQUE CHECK(length(auth_token_hash) = 32),
			e2ee_public_key BLOB NOT NULL CHECK(length(e2ee_public_key) = 65),
			registered_at_ms INTEGER NOT NULL,
			last_online_at_ms INTEGER NOT NULL,
			revoked_at_ms INTEGER,
			PRIMARY KEY(workspace_id, id)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply schema version 1: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (1, ?)`,
		time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("record schema version 1: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema version 1: %w", err)
	}
	return nil
}

func validateDeviceType(value DeviceType) error {
	if value != DeviceAndroid && value != DeviceChrome {
		return errors.New("device type must be android or chrome")
	}
	return nil
}

func validateDeviceName(value string) error {
	size := len([]byte(value))
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" || size > maxDeviceNameBytes {
		return fmt.Errorf("device name must be valid non-blank UTF-8 up to %d bytes", maxDeviceNameBytes)
	}
	return nil
}

func deviceReference(workspaceID WorkspaceID, deviceID DeviceID) string {
	digest := sha256.New()
	digest.Write([]byte("SyncNotifications-admin-device-ref-v1\x00"))
	digest.Write(workspaceID[:])
	digest.Write(deviceID[:])
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)[:12])
}

func validDeviceReference(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 12 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func unixMillis(value time.Time) int64 { return value.UTC().UnixMilli() }
