package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AESFieldEncryptor implements FieldEncryptor using AES-256-GCM.
// It accepts a DEK per operation rather than holding a fixed key,
// supporting per-record envelope encryption.
type AESFieldEncryptor struct{}

// NewAESFieldEncryptor creates a new AESFieldEncryptor.
func NewAESFieldEncryptor() *AESFieldEncryptor {
	return &AESFieldEncryptor{}
}

var _ FieldEncryptor = (*AESFieldEncryptor)(nil)

// Encrypt encrypts a plaintext string using AES-256-GCM with the provided DEK.
// Returns base64(nonce + ciphertext + tag). Empty plaintext is returned as-is.
// Each call generates a unique random nonce.
func (e *AESFieldEncryptor) Encrypt(plaintext string, dek []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if len(dek) != 32 {
		return "", fmt.Errorf("field encrypt: invalid DEK length %d, require 32 (AES-256)", len(dek))
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("field encrypt: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("field encrypt: create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("field encrypt: generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag after the nonce prefix.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext using the provided
// DEK. Empty ciphertext is returned as-is.
func (e *AESFieldEncryptor) Decrypt(ciphertext string, dek []byte) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if len(dek) != 32 {
		return "", fmt.Errorf("field decrypt: invalid DEK length %d, require 32 (AES-256)", len(dek))
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("field decrypt: base64 decode: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("field decrypt: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("field decrypt: create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("field decrypt: ciphertext too short")
	}

	nonce, ciphertextWithTag := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("field decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ZeroDEK explicitly zeroes all bytes of a DEK slice to remove sensitive
// key material from memory. Callers MUST call this after using a plaintext DEK.
func ZeroDEK(dek []byte) {
	for i := range dek {
		dek[i] = 0
	}
}
