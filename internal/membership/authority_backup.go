package membership

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	authorityBackupManifestName = "manifest.txt"
	authorityBackupMagic        = "SEVENMIRROR-WORKSPACE-AUTHORITY-BACKUP-V1"
	workspaceIDSize             = 16
)

type AuthorityBackup struct {
	Directory      string
	ManifestPath   string
	PrivateKeyPath string
	KeyID          string
}

type AuthorityRestore struct {
	PrivateKeyPath string
	AlreadyPresent bool
}

// CreateAuthorityBackup creates a new protected directory containing the exact
// PKCS#8 authority file and a canonical manifest bound to one workspace.
// The caller remains responsible for encrypting and storing this directory in
// its backup system together with a separately backed-up SQLite registry.
func CreateAuthorityBackup(
	directory string,
	workspaceID []byte,
	sourcePrivateKeyPath string,
	expectedPublicKey AuthorityPublicKey,
) (AuthorityBackup, error) {
	if err := validateBackupArguments(directory, workspaceID, expectedPublicKey); err != nil {
		return AuthorityBackup{}, err
	}
	private, encoded, err := loadAuthorityPrivateKeyFile(sourcePrivateKeyPath, expectedPublicKey)
	if err != nil {
		return AuthorityBackup{}, fmt.Errorf("validate live workspace authority key: %w", err)
	}
	clear(private)
	defer clear(encoded)

	if err := os.Mkdir(directory, 0o700); err != nil {
		return AuthorityBackup{}, fmt.Errorf("create authority backup directory: %w", err)
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return AuthorityBackup{}, fmt.Errorf("protect authority backup directory: %w", err)
	}

	keyID := AuthorityKeyID(expectedPublicKey)
	keyFileName := authorityPrivateKeyFileName(keyID)
	keyPath := filepath.Join(directory, keyFileName)
	if err := writeExclusiveProtectedFile(keyPath, encoded); err != nil {
		return AuthorityBackup{}, fmt.Errorf("write authority backup private key: %w", err)
	}
	manifest := encodeAuthorityBackupManifest(authorityBackupManifest{
		WorkspaceID:        append([]byte(nil), workspaceID...),
		AuthorityPublicKey: expectedPublicKey,
		AuthorityKeyID:     keyID,
		PrivateKeyFile:     keyFileName,
		PrivateKeySHA256:   sha256.Sum256(encoded),
	})
	manifestPath := filepath.Join(directory, authorityBackupManifestName)
	if err := writeExclusiveProtectedFile(manifestPath, manifest); err != nil {
		return AuthorityBackup{}, fmt.Errorf("write authority backup manifest: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return AuthorityBackup{}, fmt.Errorf("sync authority backup directory: %w", err)
	}
	verified, err := VerifyAuthorityBackup(directory, workspaceID, expectedPublicKey)
	if err != nil {
		return AuthorityBackup{}, fmt.Errorf("verify created authority backup: %w", err)
	}
	removePartial = false
	return verified, nil
}

// VerifyAuthorityBackup verifies canonical metadata, exact workspace/public-key
// binding, PKCS#8 validity, key ID, file digest, and protected file modes.
func VerifyAuthorityBackup(
	directory string,
	workspaceID []byte,
	expectedPublicKey AuthorityPublicKey,
) (AuthorityBackup, error) {
	if err := validateBackupArguments(directory, workspaceID, expectedPublicKey); err != nil {
		return AuthorityBackup{}, err
	}
	if err := validateProtectedDirectory(directory); err != nil {
		return AuthorityBackup{}, err
	}
	manifestPath := filepath.Join(directory, authorityBackupManifestName)
	manifestBytes, err := readProtectedRegularFile(manifestPath, 4096, "authority backup manifest")
	if err != nil {
		return AuthorityBackup{}, err
	}
	defer clear(manifestBytes)
	manifest, err := decodeAuthorityBackupManifest(manifestBytes)
	if err != nil {
		return AuthorityBackup{}, err
	}
	if !bytes.Equal(manifest.WorkspaceID, workspaceID) {
		return AuthorityBackup{}, errors.New("authority backup workspace does not match the requested workspace")
	}
	if !bytes.Equal(manifest.AuthorityPublicKey[:], expectedPublicKey[:]) {
		return AuthorityBackup{}, errors.New("authority backup public key does not match the registry")
	}
	expectedKeyID := AuthorityKeyID(expectedPublicKey)
	if manifest.AuthorityKeyID != expectedKeyID ||
		manifest.PrivateKeyFile != authorityPrivateKeyFileName(expectedKeyID) {
		return AuthorityBackup{}, errors.New("authority backup key ID binding is invalid")
	}

	keyPath := filepath.Join(directory, manifest.PrivateKeyFile)
	private, encoded, err := loadAuthorityPrivateKeyFile(keyPath, expectedPublicKey)
	if err != nil {
		return AuthorityBackup{}, fmt.Errorf("validate authority backup private key: %w", err)
	}
	clear(private)
	defer clear(encoded)
	if digest := sha256.Sum256(encoded); digest != manifest.PrivateKeySHA256 {
		return AuthorityBackup{}, errors.New("authority backup private key digest does not match the manifest")
	}
	return AuthorityBackup{
		Directory:      directory,
		ManifestPath:   manifestPath,
		PrivateKeyPath: keyPath,
		KeyID:          expectedKeyID,
	}, nil
}

// RestoreAuthorityBackup restores only the exact verified authority key file.
// It never replaces an existing file. An exact valid existing file is treated
// as an idempotent completed restore.
func RestoreAuthorityBackup(
	backupDirectory string,
	destinationDirectory string,
	workspaceID []byte,
	expectedPublicKey AuthorityPublicKey,
) (AuthorityRestore, error) {
	verified, err := VerifyAuthorityBackup(backupDirectory, workspaceID, expectedPublicKey)
	if err != nil {
		return AuthorityRestore{}, fmt.Errorf("verify authority backup before restore: %w", err)
	}
	private, encoded, err := loadAuthorityPrivateKeyFile(
		verified.PrivateKeyPath,
		expectedPublicKey,
	)
	if err != nil {
		return AuthorityRestore{}, fmt.Errorf("read verified authority backup: %w", err)
	}
	clear(private)
	defer clear(encoded)

	if destinationDirectory == "" {
		return AuthorityRestore{}, errors.New("authority destination directory is required")
	}
	if err := os.MkdirAll(destinationDirectory, 0o700); err != nil {
		return AuthorityRestore{}, fmt.Errorf("create authority destination directory: %w", err)
	}
	if err := os.Chmod(destinationDirectory, 0o700); err != nil {
		return AuthorityRestore{}, fmt.Errorf("protect authority destination directory: %w", err)
	}
	destinationPath := filepath.Join(destinationDirectory, authorityPrivateKeyFileName(verified.KeyID))
	if err := writeExclusiveProtectedFile(destinationPath, encoded); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return AuthorityRestore{}, fmt.Errorf("restore workspace authority key: %w", err)
		}
		existing, existingEncoded, loadErr := loadAuthorityPrivateKeyFile(
			destinationPath,
			expectedPublicKey,
		)
		if loadErr != nil {
			return AuthorityRestore{}, fmt.Errorf(
				"refuse to replace existing workspace authority key: %w", loadErr)
		}
		clear(existing)
		defer clear(existingEncoded)
		if !bytes.Equal(existingEncoded, encoded) {
			return AuthorityRestore{}, errors.New(
				"refuse to replace existing workspace authority key with different bytes")
		}
		return AuthorityRestore{PrivateKeyPath: destinationPath, AlreadyPresent: true}, nil
	}
	if err := syncDirectory(destinationDirectory); err != nil {
		return AuthorityRestore{}, fmt.Errorf("sync authority destination directory: %w", err)
	}
	restored, err := LoadAuthorityPrivateKey(destinationPath, expectedPublicKey)
	if err != nil {
		return AuthorityRestore{}, fmt.Errorf("verify restored workspace authority key: %w", err)
	}
	clear(restored)
	return AuthorityRestore{PrivateKeyPath: destinationPath}, nil
}

type authorityBackupManifest struct {
	WorkspaceID        []byte
	AuthorityPublicKey AuthorityPublicKey
	AuthorityKeyID     string
	PrivateKeyFile     string
	PrivateKeySHA256   [sha256.Size]byte
}

func encodeAuthorityBackupManifest(value authorityBackupManifest) []byte {
	return []byte(fmt.Sprintf(
		"%s\nworkspace_id=%s\nauthority_public_key=%s\nauthority_key_id=%s\nprivate_key_file=%s\nprivate_key_sha256=%s\n",
		authorityBackupMagic,
		base64.RawURLEncoding.EncodeToString(value.WorkspaceID),
		base64.RawURLEncoding.EncodeToString(value.AuthorityPublicKey[:]),
		value.AuthorityKeyID,
		value.PrivateKeyFile,
		base64.RawURLEncoding.EncodeToString(value.PrivateKeySHA256[:]),
	))
}

func decodeAuthorityBackupManifest(encoded []byte) (authorityBackupManifest, error) {
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 7 || lines[0] != authorityBackupMagic || lines[6] != "" {
		return authorityBackupManifest{}, errors.New("authority backup manifest is not canonical")
	}
	workspaceID, err := decodeManifestValue(lines[1], "workspace_id", workspaceIDSize)
	if err != nil {
		return authorityBackupManifest{}, err
	}
	publicKeyBytes, err := decodeManifestValue(
		lines[2], "authority_public_key", len(AuthorityPublicKey{}))
	if err != nil {
		return authorityBackupManifest{}, err
	}
	keyID, err := manifestTextValue(lines[3], "authority_key_id")
	if err != nil {
		return authorityBackupManifest{}, err
	}
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(keyID); decodeErr != nil ||
		len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != keyID {
		return authorityBackupManifest{}, errors.New("authority backup manifest key ID is invalid")
	}
	privateKeyFile, err := manifestTextValue(lines[4], "private_key_file")
	if err != nil {
		return authorityBackupManifest{}, err
	}
	if filepath.Base(privateKeyFile) != privateKeyFile {
		return authorityBackupManifest{}, errors.New("authority backup private key file name is invalid")
	}
	privateKeyDigest, err := decodeManifestValue(
		lines[5], "private_key_sha256", sha256.Size)
	if err != nil {
		return authorityBackupManifest{}, err
	}
	var publicKey AuthorityPublicKey
	copy(publicKey[:], publicKeyBytes)
	var digest [sha256.Size]byte
	copy(digest[:], privateKeyDigest)
	manifest := authorityBackupManifest{
		WorkspaceID:        workspaceID,
		AuthorityPublicKey: publicKey,
		AuthorityKeyID:     keyID,
		PrivateKeyFile:     privateKeyFile,
		PrivateKeySHA256:   digest,
	}
	if !bytes.Equal(encoded, encodeAuthorityBackupManifest(manifest)) {
		return authorityBackupManifest{}, errors.New("authority backup manifest is not canonical")
	}
	return manifest, nil
}

func decodeManifestValue(line string, name string, size int) ([]byte, error) {
	value, err := manifestTextValue(line, name)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("authority backup manifest %s is invalid", name)
	}
	return decoded, nil
}

func manifestTextValue(line string, name string) (string, error) {
	prefix := name + "="
	if !strings.HasPrefix(line, prefix) || len(line) == len(prefix) {
		return "", fmt.Errorf("authority backup manifest %s is invalid", name)
	}
	return strings.TrimPrefix(line, prefix), nil
}

func validateBackupArguments(
	directory string,
	workspaceID []byte,
	publicKey AuthorityPublicKey,
) error {
	if directory == "" {
		return errors.New("authority backup directory is required")
	}
	if len(workspaceID) != workspaceIDSize {
		return errors.New("workspace ID must be 16 bytes")
	}
	if bytes.Equal(publicKey[:], make([]byte, len(publicKey))) {
		return errors.New("workspace authority public key must not be zero")
	}
	return nil
}

func validateProtectedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat authority backup directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("authority backup path must be a directory, not a symbolic link")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return fmt.Errorf("authority backup directory permissions are %o, want 700", info.Mode().Perm())
	}
	return nil
}

func readProtectedRegularFile(path string, maximumBytes int64, description string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", description, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symbolic link", description)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", description, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", description, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", description)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%s permissions are %o, want 600", description, info.Mode().Perm())
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}
	if int64(len(encoded)) > maximumBytes {
		clear(encoded)
		return nil, fmt.Errorf("%s is too large", description)
	}
	return encoded, nil
}

func writeExclusiveProtectedFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	written, err := file.Write(content)
	if err != nil {
		_ = file.Close()
		return err
	}
	if written != len(content) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	removePartial = false
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func authorityPrivateKeyFileName(keyID string) string {
	return "workspace-authority-" + keyID + ".pk8"
}
