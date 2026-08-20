package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const authorityKeyIDDomain = "SyncNotifications-workspace-authority-key-id-v1\x00"

type AuthorityPublicKey [ed25519.PublicKeySize]byte

type GeneratedAuthority struct {
	PublicKey AuthorityPublicKey
	KeyID     string
	Path      string
}

// GenerateAuthority creates a new Ed25519 authority private key in an exclusive,
// owner-only PKCS#8 file. It never returns private key material to the caller.
func GenerateAuthority(directory string) (GeneratedAuthority, error) {
	if directory == "" {
		return GeneratedAuthority{}, errors.New("authority key directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return GeneratedAuthority{}, fmt.Errorf("create authority key directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return GeneratedAuthority{}, fmt.Errorf("protect authority key directory: %w", err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedAuthority{}, fmt.Errorf("generate workspace authority key: %w", err)
	}
	defer clear(private)
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return GeneratedAuthority{}, fmt.Errorf("encode workspace authority key: %w", err)
	}
	defer clear(encoded)

	var publicKey AuthorityPublicKey
	copy(publicKey[:], public)
	keyID := AuthorityKeyID(publicKey)
	path := filepath.Join(directory, "workspace-authority-"+keyID+".pk8")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return GeneratedAuthority{}, fmt.Errorf("create workspace authority key file: %w", err)
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return GeneratedAuthority{}, fmt.Errorf("protect workspace authority key file: %w", err)
	}
	written, err := file.Write(encoded)
	if err != nil {
		_ = file.Close()
		return GeneratedAuthority{}, fmt.Errorf("write workspace authority key file: %w", err)
	}
	if written != len(encoded) {
		_ = file.Close()
		return GeneratedAuthority{}, fmt.Errorf("write workspace authority key file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return GeneratedAuthority{}, fmt.Errorf("sync workspace authority key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return GeneratedAuthority{}, fmt.Errorf("close workspace authority key file: %w", err)
	}
	removePartial = false
	return GeneratedAuthority{PublicKey: publicKey, KeyID: keyID, Path: path}, nil
}

// LoadAuthorityPrivateKey loads an exact authority key and rejects unsafe Unix
// permissions, malformed PKCS#8, non-Ed25519 keys, and public-key mismatches.
func LoadAuthorityPrivateKey(path string, expected AuthorityPublicKey) (ed25519.PrivateKey, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat workspace authority key: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("workspace authority key must not be a symbolic link")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace authority key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened workspace authority key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("workspace authority key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("workspace authority key permissions are %o, want 600", info.Mode().Perm())
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, fmt.Errorf("read workspace authority key: %w", err)
	}
	defer clear(encoded)
	if len(encoded) > 4096 {
		return nil, errors.New("workspace authority key file is too large")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse workspace authority key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("workspace authority key is not Ed25519")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, expected[:]) {
		clear(private)
		return nil, errors.New("workspace authority private key does not match the pinned public key")
	}
	return private, nil
}

func AuthorityKeyID(publicKey AuthorityPublicKey) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(authorityKeyIDDomain))
	_, _ = digest.Write(publicKey[:])
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}
