package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	return dek
}

func TestAESFieldEncryptor_RoundTrip(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek := generateTestDEK(t)

	plaintext := "123-45-6789"
	ciphertext, err := enc.Encrypt(plaintext, dek)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := enc.Decrypt(ciphertext, dek)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESFieldEncryptor_EmptyString(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek := generateTestDEK(t)

	ct, err := enc.Encrypt("", dek)
	require.NoError(t, err)
	assert.Equal(t, "", ct)

	pt, err := enc.Decrypt("", dek)
	require.NoError(t, err)
	assert.Equal(t, "", pt)
}

func TestAESFieldEncryptor_UniqueNonces(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek := generateTestDEK(t)

	ct1, err := enc.Encrypt("same-value", dek)
	require.NoError(t, err)

	ct2, err := enc.Encrypt("same-value", dek)
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "two encryptions of the same value must produce different ciphertexts")
}

func TestAESFieldEncryptor_WrongDEK(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek1 := generateTestDEK(t)
	dek2 := generateTestDEK(t)

	ct, err := enc.Encrypt("sensitive", dek1)
	require.NoError(t, err)

	_, err = enc.Decrypt(ct, dek2)
	assert.Error(t, err, "decryption with wrong DEK must fail")
}

func TestAESFieldEncryptor_InvalidDEKLength(t *testing.T) {
	enc := NewAESFieldEncryptor()
	shortDEK := make([]byte, 16)

	_, err := enc.Encrypt("test", shortDEK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DEK length")

	_, err = enc.Decrypt("test", shortDEK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DEK length")
}

func TestAESFieldEncryptor_InvalidBase64(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek := generateTestDEK(t)

	_, err := enc.Decrypt("not-valid-base64!!!", dek)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decode")
}

func TestAESFieldEncryptor_TruncatedCiphertext(t *testing.T) {
	enc := NewAESFieldEncryptor()
	dek := generateTestDEK(t)

	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	_, err := enc.Decrypt(short, dek)
	assert.Error(t, err)
}

func TestZeroDEK(t *testing.T) {
	dek := generateTestDEK(t)
	ZeroDEK(dek)
	for i, b := range dek {
		assert.Equal(t, byte(0), b, "byte %d should be zeroed", i)
	}
}

func TestZeroDEK_Nil(t *testing.T) {
	// Should not panic on nil slice.
	ZeroDEK(nil)
}
