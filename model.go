package encryption

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DataEncryptionKey represents a per-record data encryption key used for
// field-level PII encryption via AWS KMS envelope encryption.
//
// DEK Lifecycle:
//   - CREATE: KMS.GenerateDataKey produces plaintext + encrypted DEK pair.
//     Plaintext DEK encrypts PII fields; encrypted DEK is stored in this record.
//     Plaintext DEK is zeroed from memory after use.
//   - READ: Encrypted DEK is fetched, decrypted via KMS.Decrypt (or served from
//     short-TTL cache), used to decrypt PII fields, then zeroed from memory.
//   - PURGE (GDPR): Deleting this record makes all PII ciphertext in the
//     associated entity irrecoverable (crypto-shredding).
type DataEncryptionKey struct {
	ID           uuid.UUID
	EntityID     uuid.UUID // The owning record (background check, user, document, etc.)
	EncryptedDEK []byte    // KMS-encrypted DEK — never plaintext in storage
	CMKKeyARN    string    // Which CMK encrypted this DEK
	CMKVersion   int       // CMK version tracking for key rotation
	CreatedAt    time.Time
}

// EncryptionKeyRepository persists and retrieves encrypted data encryption
// keys. Each entity has at most one DEK (enforced by unique constraint on
// EntityID in the database).
//
// Consuming projects implement this interface with their own persistence layer
// (PostgreSQL, DynamoDB, etc.). A reference SQL migration is included in
// migration.sql.
type EncryptionKeyRepository interface {
	Create(ctx context.Context, dek *DataEncryptionKey) error
	FindByEntityID(ctx context.Context, entityID uuid.UUID) (*DataEncryptionKey, error)
	DeleteByEntityID(ctx context.Context, entityID uuid.UUID) error
}
