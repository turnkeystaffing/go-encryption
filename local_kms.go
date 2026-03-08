package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// LocalKMSClient implements KMSClient using locally-managed master keys
// stored in environment variables or config. It provides the same envelope
// encryption pattern as AWS KMS but without cloud dependency.
//
// Encrypted DEK format (self-describing, stored in DB):
//
//	┌──────────────┬─────────────┬──────────────────────────────┐
//	│ version (2B) │ nonce (12B) │ AES-256-GCM(dek, master_key) │
//	│ big-endian   │             │ ciphertext + 16B auth tag    │
//	└──────────────┴─────────────┴──────────────────────────────┘
//
// The version prefix allows Decrypt to select the correct master key
// without external metadata. This mirrors how AWS KMS embeds key
// metadata in its ciphertext blobs.
//
// See docs/local-kms-rotation.md for the rotation strategy and runbook.
type LocalKMSClient struct {
	currentVersion uint16
	keys           map[uint16][]byte // version → 256-bit master key
}

// LocalKMSConfig configures the local KMS client with versioned master keys.
type LocalKMSConfig struct {
	// CurrentVersion is the version used for new GenerateDataKey operations.
	CurrentVersion uint16

	// Keys maps version numbers to 256-bit (32-byte) master keys.
	// Must include CurrentVersion. Old versions must be retained for
	// decrypting existing DEKs until re-encryption migration completes.
	Keys map[uint16][]byte
}

// NewLocalKMSClient creates a LocalKMSClient from config.
//
// Panics if:
//   - no keys are provided
//   - CurrentVersion is not present in Keys
//   - any key is not exactly 32 bytes (AES-256)
func NewLocalKMSClient(cfg LocalKMSConfig) *LocalKMSClient {
	if len(cfg.Keys) == 0 {
		panic("encryption: NewLocalKMSClient requires at least one key")
	}
	if _, ok := cfg.Keys[cfg.CurrentVersion]; !ok {
		panic(fmt.Sprintf("encryption: NewLocalKMSClient current version %d not found in keys", cfg.CurrentVersion))
	}
	for v, k := range cfg.Keys {
		if len(k) != 32 {
			panic(fmt.Sprintf("encryption: NewLocalKMSClient key version %d has invalid length %d, require 32", v, len(k)))
		}
	}

	// Deep copy keys to prevent external mutation.
	keys := make(map[uint16][]byte, len(cfg.Keys))
	for v, k := range cfg.Keys {
		keyCopy := make([]byte, 32)
		copy(keyCopy, k)
		keys[v] = keyCopy
	}

	return &LocalKMSClient{
		currentVersion: cfg.CurrentVersion,
		keys:           keys,
	}
}

var _ KMSClient = (*LocalKMSClient)(nil)

// GenerateDataKey generates a random 256-bit DEK and returns both the
// plaintext DEK (for immediate use) and the encrypted DEK (for storage).
// The encrypted DEK is self-describing: it contains the master key version
// used for encryption, so Decrypt can select the correct key.
//
// The keyID parameter is ignored — key selection is driven by CurrentVersion.
func (l *LocalKMSClient) GenerateDataKey(_ context.Context, _ string) (plaintext, ciphertext []byte, err error) {
	// Generate random 256-bit DEK.
	plaintext = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		return nil, nil, fmt.Errorf("local kms: generate dek: %w", err)
	}

	ciphertext, err = l.encryptDEK(plaintext)
	if err != nil {
		ZeroDEK(plaintext)
		return nil, nil, err
	}

	return plaintext, ciphertext, nil
}

// Decrypt decrypts an encrypted DEK by reading the version prefix and
// selecting the correct master key. Returns an error if the version is
// unknown or the ciphertext is tampered with.
func (l *LocalKMSClient) Decrypt(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	// Minimum: 2 (version) + 12 (nonce) + 1 (data) + 16 (tag) = 31 bytes.
	const minLen = 2 + 12 + 16 + 1
	if len(encryptedDEK) < minLen {
		return nil, fmt.Errorf("local kms: encrypted DEK too short (%d bytes)", len(encryptedDEK))
	}

	version := binary.BigEndian.Uint16(encryptedDEK[:2])
	masterKey, ok := l.keys[version]
	if !ok {
		return nil, fmt.Errorf("local kms: unknown key version %d", version)
	}

	nonce := encryptedDEK[2:14]
	ciphertextWithTag := encryptedDEK[14:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("local kms: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("local kms: create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("local kms: decrypt dek: %w", err)
	}

	return plaintext, nil
}

// encryptDEK encrypts a plaintext DEK with the current master key version.
func (l *LocalKMSClient) encryptDEK(plainDEK []byte) ([]byte, error) {
	masterKey := l.keys[l.currentVersion]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("local kms: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("local kms: create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("local kms: generate nonce: %w", err)
	}

	// Build: [version:2] [nonce:12] [ciphertext+tag]
	result := make([]byte, 2, 2+len(nonce)+len(plainDEK)+gcm.Overhead())
	binary.BigEndian.PutUint16(result, l.currentVersion)
	result = append(result, nonce...)
	result = gcm.Seal(result, nonce, plainDEK, nil)

	return result, nil
}

// CurrentVersion returns the active master key version used for new DEKs.
func (l *LocalKMSClient) CurrentVersion() uint16 {
	return l.currentVersion
}

// HasVersion reports whether the client holds a master key for the given version.
func (l *LocalKMSClient) HasVersion(version uint16) bool {
	_, ok := l.keys[version]
	return ok
}
