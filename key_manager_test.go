package encryption

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKMSClient implements KMSClient for unit tests.
type fakeKMSClient struct {
	generateErr error
	decryptErr  error
}

func (f *fakeKMSClient) GenerateDataKey(_ context.Context, _ string) ([]byte, []byte, error) {
	if f.generateErr != nil {
		return nil, nil, f.generateErr
	}
	plain := make([]byte, 32)
	for i := range plain {
		plain[i] = byte(i)
	}
	encrypted := make([]byte, 64)
	copy(encrypted, plain)
	return plain, encrypted, nil
}

func (f *fakeKMSClient) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	// Return first 32 bytes as "plaintext".
	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return ciphertext[:32], nil
}

func TestKMSKeyManager_GenerateDEK(t *testing.T) {
	km := NewKMSKeyManager(&fakeKMSClient{}, "arn:aws:kms:us-east-1:123:key/test")

	plain, enc, err := km.GenerateDEK(context.Background())
	require.NoError(t, err)
	assert.Len(t, plain, 32)
	assert.Len(t, enc, 64)
}

func TestKMSKeyManager_GenerateDEK_Error(t *testing.T) {
	km := NewKMSKeyManager(
		&fakeKMSClient{generateErr: fmt.Errorf("kms unavailable")},
		"arn:aws:kms:us-east-1:123:key/test",
	)

	_, _, err := km.GenerateDEK(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kms generate data key")
}

func TestKMSKeyManager_DecryptDEK(t *testing.T) {
	km := NewKMSKeyManager(&fakeKMSClient{}, "arn:aws:kms:us-east-1:123:key/test")

	encrypted := make([]byte, 64)
	for i := range 32 {
		encrypted[i] = byte(i)
	}

	plain, err := km.DecryptDEK(context.Background(), encrypted)
	require.NoError(t, err)
	assert.Len(t, plain, 32)
}

func TestKMSKeyManager_DecryptDEK_Error(t *testing.T) {
	km := NewKMSKeyManager(
		&fakeKMSClient{decryptErr: fmt.Errorf("kms unavailable")},
		"arn:aws:kms:us-east-1:123:key/test",
	)

	_, err := km.DecryptDEK(context.Background(), []byte("enc"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kms decrypt dek")
}

func TestNewKMSKeyManager_PanicOnNilClient(t *testing.T) {
	assert.Panics(t, func() {
		NewKMSKeyManager(nil, "arn:aws:kms:us-east-1:123:key/test")
	})
}

func TestNewKMSKeyManager_PanicOnEmptyARN(t *testing.T) {
	assert.Panics(t, func() {
		NewKMSKeyManager(&fakeKMSClient{}, "")
	})
}

func TestNoopKMSClient(t *testing.T) {
	client := NewNoopKMSClient()

	_, _, err := client.GenerateDataKey(context.Background(), "any-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service disabled")

	_, err = client.Decrypt(context.Background(), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service disabled")
}
