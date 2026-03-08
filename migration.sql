-- Reference migration for go-encryption DEK storage.
-- Consuming projects should adapt this to their schema and entity naming.
--
-- Defense-in-depth: In production, grant this table's SELECT/INSERT/DELETE
-- permissions only to the encryption service role, separate from the role
-- that reads/writes the entity table. This limits blast radius if either
-- role is compromised.

CREATE TABLE IF NOT EXISTS data_encryption_keys (
    id            UUID        PRIMARY KEY,
    entity_id     UUID        NOT NULL UNIQUE,  -- FK to your entity table (1 DEK per entity)
    encrypted_dek BYTEA       NOT NULL,         -- KMS-encrypted DEK (never plaintext)
    cmk_key_arn   TEXT        NOT NULL,         -- AWS KMS Customer Master Key ARN
    cmk_version   INTEGER     NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The UNIQUE constraint on entity_id already creates an implicit B-tree index.
-- Add a foreign key to your entity table after it exists:
--
--   ALTER TABLE data_encryption_keys
--       ADD CONSTRAINT fk_dek_entity_id
--       FOREIGN KEY (entity_id) REFERENCES your_entity_table(id);
