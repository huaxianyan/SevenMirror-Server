package workspacebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/membership"
)

const (
	manifestName       = "manifest.txt"
	registryName       = "registry.sqlite"
	authorityDirectory = "authority"
	manifestMagic      = "SEVENMIRROR-WORKSPACE-BACKUP-V1"
)

type Restore struct {
	RegistryPath     string
	AuthorityKeyPath string
	AuthorityExisted bool
}

type Backup struct {
	Directory       string
	ManifestPath    string
	RegistryPath    string
	AuthorityBackup membership.AuthorityBackup
	AuthorityKeyID  string
	registrySHA256  [sha256.Size]byte
}

type manifest struct {
	WorkspaceID    admission.WorkspaceID
	RegistrySHA256 [sha256.Size]byte
	AuthorityKeyID string
}

func Create(
	ctx context.Context,
	store *admission.Store,
	directory string,
	workspaceID admission.WorkspaceID,
	authorityKeyDirectory string,
) (Backup, error) {
	if store == nil {
		return Backup{}, errors.New("admission store is required")
	}
	if directory == "" || authorityKeyDirectory == "" {
		return Backup{}, errors.New("backup and authority key directories are required")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Backup{}, fmt.Errorf("create workspace backup directory: %w", err)
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return Backup{}, fmt.Errorf("protect workspace backup directory: %w", err)
	}

	registryPath := filepath.Join(directory, registryName)
	if err := store.BackupRegistry(ctx, registryPath); err != nil {
		return Backup{}, err
	}
	publicKey, err := admission.InspectRegistryBackup(ctx, registryPath, workspaceID)
	if err != nil {
		return Backup{}, err
	}
	keyID := membership.AuthorityKeyID(publicKey)
	authorityBackupPath := filepath.Join(directory, authorityDirectory)
	if _, err := membership.CreateAuthorityBackup(
		authorityBackupPath,
		workspaceID[:],
		membership.AuthorityPrivateKeyPath(authorityKeyDirectory, keyID),
		publicKey,
	); err != nil {
		return Backup{}, err
	}
	registryDigest, err := fileSHA256(registryPath)
	if err != nil {
		return Backup{}, err
	}
	manifestPath := filepath.Join(directory, manifestName)
	if err := writeProtectedFile(manifestPath, encodeManifest(manifest{
		WorkspaceID: workspaceID, RegistrySHA256: registryDigest, AuthorityKeyID: keyID,
	})); err != nil {
		return Backup{}, fmt.Errorf("write workspace backup manifest: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return Backup{}, fmt.Errorf("sync workspace backup directory: %w", err)
	}
	verified, err := Verify(ctx, directory, workspaceID)
	if err != nil {
		return Backup{}, fmt.Errorf("verify created workspace backup: %w", err)
	}
	removePartial = false
	return verified, nil
}

func RestoreTo(
	ctx context.Context,
	directory string,
	workspaceID admission.WorkspaceID,
	destinationRegistry string,
	destinationAuthorityDirectory string,
) (Restore, error) {
	if destinationRegistry == "" || destinationAuthorityDirectory == "" {
		return Restore{}, errors.New("registry and authority restore destinations are required")
	}
	verified, err := Verify(ctx, directory, workspaceID)
	if err != nil {
		return Restore{}, fmt.Errorf("verify workspace backup before restore: %w", err)
	}
	if pathIsWithin(directory, destinationRegistry) ||
		pathIsWithin(directory, destinationAuthorityDirectory) {
		return Restore{}, errors.New("restore destinations must be outside the backup directory")
	}
	if err := prepareProtectedDirectory(filepath.Dir(destinationRegistry)); err != nil {
		return Restore{}, fmt.Errorf("prepare registry restore directory: %w", err)
	}
	if err := copyExclusive(verified.RegistryPath, destinationRegistry); err != nil {
		return Restore{}, fmt.Errorf("restore registry snapshot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destinationRegistry)); err != nil {
		_ = os.Remove(destinationRegistry)
		return Restore{}, fmt.Errorf("sync registry restore directory: %w", err)
	}
	removeRegistry := true
	defer func() {
		if removeRegistry {
			_ = os.Remove(destinationRegistry)
			_ = syncDirectory(filepath.Dir(destinationRegistry))
		}
	}()
	restoredDigest, err := fileSHA256(destinationRegistry)
	if err != nil {
		return Restore{}, fmt.Errorf("hash restored registry: %w", err)
	}
	if restoredDigest != verified.registrySHA256 {
		return Restore{}, errors.New("restored registry digest does not match the verified backup")
	}
	publicKey, err := admission.InspectRegistryBackup(ctx, destinationRegistry, workspaceID)
	if err != nil {
		return Restore{}, fmt.Errorf("verify restored registry: %w", err)
	}
	restored, err := membership.RestoreAuthorityBackup(
		verified.AuthorityBackup.Directory,
		destinationAuthorityDirectory,
		workspaceID[:],
		publicKey,
	)
	if err != nil {
		return Restore{}, err
	}
	removeRegistry = false
	return Restore{
		RegistryPath: destinationRegistry, AuthorityKeyPath: restored.PrivateKeyPath,
		AuthorityExisted: restored.AlreadyPresent,
	}, nil
}

func Verify(
	ctx context.Context,
	directory string,
	workspaceID admission.WorkspaceID,
) (Backup, error) {
	if err := validateDirectory(directory); err != nil {
		return Backup{}, err
	}
	manifestPath := filepath.Join(directory, manifestName)
	encoded, err := readProtectedFile(manifestPath, 4096)
	if err != nil {
		return Backup{}, fmt.Errorf("read workspace backup manifest: %w", err)
	}
	manifest, err := decodeManifest(encoded)
	if err != nil {
		return Backup{}, err
	}
	if manifest.WorkspaceID != workspaceID {
		return Backup{}, errors.New("workspace backup does not match the requested workspace")
	}
	registryPath := filepath.Join(directory, registryName)
	if err := validateProtectedFile(registryPath); err != nil {
		return Backup{}, fmt.Errorf("validate registry backup: %w", err)
	}
	digest, err := fileSHA256(registryPath)
	if err != nil {
		return Backup{}, err
	}
	if digest != manifest.RegistrySHA256 {
		return Backup{}, errors.New("registry backup digest does not match the manifest")
	}
	publicKey, err := admission.InspectRegistryBackup(ctx, registryPath, workspaceID)
	if err != nil {
		return Backup{}, err
	}
	if membership.AuthorityKeyID(publicKey) != manifest.AuthorityKeyID {
		return Backup{}, errors.New("workspace backup authority does not match its registry")
	}
	authorityBackupPath := filepath.Join(directory, authorityDirectory)
	authorityBackup, err := membership.VerifyAuthorityBackup(
		authorityBackupPath, workspaceID[:], publicKey)
	if err != nil {
		return Backup{}, err
	}
	if err := validateExactEntries(directory, authorityBackup); err != nil {
		return Backup{}, err
	}
	return Backup{
		Directory: directory, ManifestPath: manifestPath, RegistryPath: registryPath,
		AuthorityBackup: authorityBackup, AuthorityKeyID: manifest.AuthorityKeyID,
		registrySHA256: manifest.RegistrySHA256,
	}, nil
}

func encodeManifest(value manifest) []byte {
	return []byte(fmt.Sprintf(
		"%s\nworkspace_id=%s\nregistry_file=%s\nregistry_sha256=%s\nauthority_directory=%s\nauthority_key_id=%s\n",
		manifestMagic,
		base64.RawURLEncoding.EncodeToString(value.WorkspaceID[:]),
		registryName,
		base64.RawURLEncoding.EncodeToString(value.RegistrySHA256[:]),
		authorityDirectory,
		value.AuthorityKeyID,
	))
}

func decodeManifest(encoded []byte) (manifest, error) {
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 7 || lines[0] != manifestMagic || lines[6] != "" ||
		lines[2] != "registry_file="+registryName ||
		lines[4] != "authority_directory="+authorityDirectory {
		return manifest{}, errors.New("workspace backup manifest is not canonical")
	}
	workspaceBytes, err := decodeValue(lines[1], "workspace_id", len(admission.WorkspaceID{}))
	if err != nil {
		return manifest{}, err
	}
	digestBytes, err := decodeValue(lines[3], "registry_sha256", sha256.Size)
	if err != nil {
		return manifest{}, err
	}
	keyID := strings.TrimPrefix(lines[5], "authority_key_id=")
	keyIDBytes, err := base64.RawURLEncoding.DecodeString(keyID)
	if !strings.HasPrefix(lines[5], "authority_key_id=") || len(keyIDBytes) != sha256.Size ||
		err != nil || base64.RawURLEncoding.EncodeToString(keyIDBytes) != keyID {
		return manifest{}, errors.New("workspace backup authority key ID is invalid")
	}
	var value manifest
	copy(value.WorkspaceID[:], workspaceBytes)
	copy(value.RegistrySHA256[:], digestBytes)
	value.AuthorityKeyID = keyID
	if !bytes.Equal(encoded, encodeManifest(value)) {
		return manifest{}, errors.New("workspace backup manifest is not canonical")
	}
	return value, nil
}

func decodeValue(line string, name string, size int) ([]byte, error) {
	prefix := name + "="
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf("workspace backup manifest %s is invalid", name)
	}
	encoded := strings.TrimPrefix(line, prefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("workspace backup manifest %s is invalid", name)
	}
	return decoded, nil
}

func validateExactEntries(directory string, authorityBackup membership.AuthorityBackup) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read workspace backup directory: %w", err)
	}
	expected := map[string]bool{manifestName: false, registryName: false, authorityDirectory: false}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("workspace backup contains unexpected entry %q", entry.Name())
		}
		expected[entry.Name()] = true
	}
	for name, present := range expected {
		if !present {
			return fmt.Errorf("workspace backup is missing %q", name)
		}
	}
	authorityEntries, err := os.ReadDir(filepath.Join(directory, authorityDirectory))
	if err != nil {
		return fmt.Errorf("read authority backup directory: %w", err)
	}
	allowedAuthority := map[string]bool{
		filepath.Base(authorityBackup.ManifestPath):   false,
		filepath.Base(authorityBackup.PrivateKeyPath): false,
	}
	for _, entry := range authorityEntries {
		if _, ok := allowedAuthority[entry.Name()]; !ok {
			return fmt.Errorf("authority backup contains unexpected entry %q", entry.Name())
		}
		allowedAuthority[entry.Name()] = true
	}
	for name, present := range allowedAuthority {
		if !present {
			return fmt.Errorf("authority backup is missing %q", name)
		}
	}
	return nil
}

func pathIsWithin(root string, candidate string) bool {
	absoluteRoot, rootErr := filepath.Abs(root)
	absoluteCandidate, candidateErr := filepath.Abs(candidate)
	if rootErr != nil || candidateErr != nil {
		return true
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteCandidate)
	if err != nil {
		return true
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func prepareProtectedDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore destination must be a directory, not a symbolic link")
	}
	return os.Chmod(path, 0o700)
}

func validateDirectory(path string) error {
	if path == "" {
		return errors.New("workspace backup directory is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat workspace backup directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("workspace backup path must be a directory, not a symbolic link")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return fmt.Errorf("workspace backup directory permissions are %o, want 700", info.Mode().Perm())
	}
	return nil
}

func validateProtectedFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("backup entry must be a regular file, not a symbolic link")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("backup entry permissions are %o, want 600", info.Mode().Perm())
	}
	return nil
}

func readProtectedFile(path string, maximum int64) ([]byte, error) {
	if err := validateProtectedFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > maximum {
		return nil, errors.New("backup entry is too large")
	}
	return encoded, nil
}

func copyExclusive(source string, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.Remove(destination)
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		output.Close()
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	removePartial = false
	return nil
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("open backup entry for hashing: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("hash backup entry: %w", err)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func writeProtectedFile(path string, content []byte) error {
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
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
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
