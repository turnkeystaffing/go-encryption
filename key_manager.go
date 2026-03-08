package encryption

import (
	"context"
	"fmt"
)

// KMSKeyManager implements KeyManager by delegating to a KMSClient bound to
// a specific customer master key (CMK) ARN.
type KMSKeyManager struct {
	kmsClient KMSClient
	cmkARN    string
}

// NewKMSKeyManager creates a KMSKeyManager. Panics if kmsClient is nil or
// cmkARN is empty (fail-fast for misconfiguration).
func NewKMSKeyManager(kmsClient KMSClient, cmkARN string) *KMSKeyManager {
	if kmsClient == nil {
		panic("encryption: NewKMSKeyManager requires non-nil kmsClient")
	}
	if cmkARN == "" {
		panic("encryption: NewKMSKeyManager requires non-empty cmkARN")
	}
	return &KMSKeyManager{
		kmsClient: kmsClient,
		cmkARN:    cmkARN,
	}
}

var _ KeyManager = (*KMSKeyManager)(nil)

// GenerateDEK generates a new data encryption key via KMS. Returns the
// plaintext DEK (for immediate use) and the encrypted DEK (for storage).
// Callers MUST zero the plaintext DEK after use via ZeroDEK().
func (km *KMSKeyManager) GenerateDEK(ctx context.Context) (plaintext []byte, encrypted []byte, err error) {
	plaintext, encrypted, err = km.kmsClient.GenerateDataKey(ctx, km.cmkARN)
	if err != nil {
		return nil, nil, fmt.Errorf("kms generate data key: %w", err)
	}
	return plaintext, encrypted, nil
}

// DecryptDEK decrypts an encrypted DEK via KMS, returning the plaintext DEK.
// Callers MUST zero the returned plaintext DEK after use via ZeroDEK().
func (km *KMSKeyManager) DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	plaintext, err := km.kmsClient.Decrypt(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("kms decrypt dek: %w", err)
	}
	return plaintext, nil
}
