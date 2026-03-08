// Package encryption provides field-level PII encryption using AWS KMS envelope
// encryption. Each record gets its own data encryption key (DEK) generated via
// KMS. The plaintext DEK encrypts PII fields using AES-256-GCM; the KMS-encrypted
// DEK is stored alongside the record. Plaintext DEKs never touch persistent storage.
//
// The package provides:
//   - AES-256-GCM field encryption with unique random nonces per operation
//   - AWS KMS envelope encryption (GenerateDataKey / Decrypt)
//   - Bounded in-memory DEK cache with secure memory zeroing
//   - Optional audit trail decorator via go-audit
//   - GDPR crypto-shredding: delete the DEK, all PII becomes irrecoverable
//
// Consuming projects provide their own repository (persistence layer) and
// container wiring. A reference SQL migration is included in migration.sql.
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

// KMSClient abstracts AWS KMS operations for testability.
// Implementations: KMSAdapter (real AWS), NoopKMSClient (disabled/testing).
type KMSClient interface {
	GenerateDataKey(ctx context.Context, keyID string) (plaintext, ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
