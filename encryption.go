// Package encryption provides field-level PII encryption using envelope
// encryption. Each record gets its own data encryption key (DEK). The plaintext
// DEK encrypts PII fields using AES-256-GCM; the encrypted DEK is stored
// alongside the record. Plaintext DEKs never touch persistent storage.
//
// The package provides:
//   - AES-256-GCM field encryption with unique random nonces per operation
//   - AWS KMS envelope encryption (GenerateDataKey / Decrypt)
//   - Local KMS: env-var-based master keys with versioned rotation
//   - Bounded in-memory DEK cache with secure memory zeroing
//   - GDPR crypto-shredding: delete the DEK, all PII becomes irrecoverable
//
// Two KMSClient implementations:
//   - KMSAdapter: wraps AWS KMS SDK (production, hardware-backed)
//   - LocalKMSClient: locally-managed versioned master keys (dev/staging/no-cloud)
//
// Consuming projects provide their own repository (persistence layer) and
// container wiring. A reference SQL migration is included in migration.sql.
// See docs/local-kms-rotation.md for the local key rotation strategy.
package encryption

import "context"

// FieldEncryptor encrypts and decrypts individual PII field values using a
// provided data encryption key (DEK). Implementations use authenticated
// encryption (AES-256-GCM) with unique nonces per operation.
type FieldEncryptor interface {
	Encrypt(plaintext string, dek []byte) (string, error)
	Decrypt(ciphertext string, dek []byte) (string, error)
}

// KeyManager handles data encryption key generation and decryption via an
// external key management service. It binds operations to a configured
// customer master key (CMK).
//
// Callers MUST zero the returned plaintext DEK after use via ZeroDEK().
type KeyManager interface {
	GenerateDEK(ctx context.Context) (plaintext []byte, encrypted []byte, err error)
	DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error)
}

// KMSClient abstracts key management operations for testability and provider
// flexibility. Implementations: KMSAdapter (AWS KMS), LocalKMSClient (env-var
// master keys), NoopKMSClient (disabled/testing).
type KMSClient interface {
	GenerateDataKey(ctx context.Context, keyID string) (plaintext, ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
