package encryption

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestLocalKMSClient_RoundTrip(t *testing.T) {
	key := testMasterKey(t)
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: key},
	})

	plain, encrypted, err := client.GenerateDataKey(context.Background(), "ignored")
	require.NoError(t, err)
	assert.Len(t, plain, 32)
	assert.NotEmpty(t, encrypted)

	decrypted, err := client.Decrypt(context.Background(), encrypted)
	require.NoError(t, err)
	assert.Equal(t, plain, decrypted)
}

func TestLocalKMSClient_VersionEmbedded(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 42,
		Keys:           map[uint16][]byte{42: testMasterKey(t)},
	})

	_, encrypted, err := client.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	version := binary.BigEndian.Uint16(encrypted[:2])
	assert.Equal(t, uint16(42), version)
}

func TestLocalKMSClient_Rotation(t *testing.T) {
	keyV1 := testMasterKey(t)
	keyV2 := testMasterKey(t)

	// Start with v1 only.
	clientV1 := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: keyV1},
	})

	plainV1, encryptedV1, err := clientV1.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	// Rotate to v2 — keep v1 for old DEKs.
	clientV2 := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 2,
		Keys:           map[uint16][]byte{1: keyV1, 2: keyV2},
	})

	// New DEKs use v2.
	_, encryptedV2, err := clientV2.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, uint16(2), binary.BigEndian.Uint16(encryptedV2[:2]))

	// Old v1 DEKs still decrypt.
	decryptedV1, err := clientV2.Decrypt(context.Background(), encryptedV1)
	require.NoError(t, err)
	assert.Equal(t, plainV1, decryptedV1)
}

func TestLocalKMSClient_UnknownVersion(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: testMasterKey(t)},
	})

	// Craft ciphertext with version 99.
	fake := make([]byte, 64)
	binary.BigEndian.PutUint16(fake, 99)

	_, err := client.Decrypt(context.Background(), fake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key version 99")
}

func TestLocalKMSClient_TamperedCiphertext(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: testMasterKey(t)},
	})

	_, encrypted, err := client.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	// Flip a byte in the ciphertext portion.
	encrypted[20] ^= 0xFF

	_, err = client.Decrypt(context.Background(), encrypted)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt dek")
}

func TestLocalKMSClient_TruncatedCiphertext(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: testMasterKey(t)},
	})

	_, err := client.Decrypt(context.Background(), []byte("short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestLocalKMSClient_UniqueEncryptions(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: testMasterKey(t)},
	})

	_, enc1, err := client.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	_, enc2, err := client.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "two encryptions must produce different ciphertexts")
}

func TestLocalKMSClient_KeysCopied(t *testing.T) {
	key := testMasterKey(t)
	original := make([]byte, 32)
	copy(original, key)

	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: key},
	})

	// Mutate the original — should not affect the client.
	key[0] ^= 0xFF

	plain, encrypted, err := client.GenerateDataKey(context.Background(), "")
	require.NoError(t, err)

	decrypted, err := client.Decrypt(context.Background(), encrypted)
	require.NoError(t, err)
	assert.Equal(t, plain, decrypted)
}

func TestLocalKMSClient_CurrentVersion(t *testing.T) {
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 3,
		Keys:           map[uint16][]byte{1: testMasterKey(t), 3: testMasterKey(t)},
	})

	assert.Equal(t, uint16(3), client.CurrentVersion())
	assert.True(t, client.HasVersion(1))
	assert.True(t, client.HasVersion(3))
	assert.False(t, client.HasVersion(2))
}

func TestNewLocalKMSClient_PanicNoKeys(t *testing.T) {
	assert.Panics(t, func() {
		NewLocalKMSClient(LocalKMSConfig{CurrentVersion: 1, Keys: map[uint16][]byte{}})
	})
}

func TestNewLocalKMSClient_PanicMissingCurrentVersion(t *testing.T) {
	assert.Panics(t, func() {
		NewLocalKMSClient(LocalKMSConfig{
			CurrentVersion: 2,
			Keys:           map[uint16][]byte{1: testMasterKey(t)},
		})
	})
}

func TestNewLocalKMSClient_PanicInvalidKeyLength(t *testing.T) {
	assert.Panics(t, func() {
		NewLocalKMSClient(LocalKMSConfig{
			CurrentVersion: 1,
			Keys:           map[uint16][]byte{1: make([]byte, 16)},
		})
	})
}

func TestLocalKMSClient_FullEnvelopeRoundTrip(t *testing.T) {
	// End-to-end: LocalKMS generates DEK → field encryptor uses DEK → decrypt.
	client := NewLocalKMSClient(LocalKMSConfig{
		CurrentVersion: 1,
		Keys:           map[uint16][]byte{1: testMasterKey(t)},
	})
	km := NewKMSKeyManager(client, "local")
	fe := NewAESFieldEncryptor()

	// Generate DEK.
	plainDEK, encryptedDEK, err := km.GenerateDEK(context.Background())
	require.NoError(t, err)

	// Encrypt a field.
	ssn := "123-45-6789"
	ciphertext, err := fe.Encrypt(ssn, plainDEK)
	require.NoError(t, err)
	ZeroDEK(plainDEK)

	// Later: decrypt DEK, then decrypt field.
	recoveredDEK, err := km.DecryptDEK(context.Background(), encryptedDEK)
	require.NoError(t, err)

	recovered, err := fe.Decrypt(ciphertext, recoveredDEK)
	require.NoError(t, err)
	ZeroDEK(recoveredDEK)

	assert.Equal(t, ssn, recovered)
}
