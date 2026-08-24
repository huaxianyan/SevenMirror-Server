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
	private, encoded, err := loadAuthorityPrivateKeyFile(path, expected)
	clear(encoded)
	return private, err
}

func loadAuthorityPrivateKeyFile(
	path string,
	expected AuthorityPublicKey,
) (ed25519.PrivateKey, []byte, error) {
	encoded, err := readProtectedRegularFile(path, 4096, "workspace authority key")
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		clear(encoded)
		return nil, nil, fmt.Errorf("parse workspace authority key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		clear(encoded)
		return nil, nil, errors.New("workspace authority key is not Ed25519")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, expected[:]) {
		clear(private)
		clear(encoded)
		return nil, nil, errors.New("workspace authority private key does not match the pinned public key")
	}
	return private, encoded, nil
}

func AuthorityKeyID(publicKey AuthorityPublicKey) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(authorityKeyIDDomain))
	_, _ = digest.Write(publicKey[:])
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}
