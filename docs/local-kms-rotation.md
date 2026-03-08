# Local KMS Key Rotation Strategy

This document covers the key rotation strategy for `LocalKMSClient`, the environment-variable-backed alternative to AWS KMS for envelope encryption.

## Overview

`LocalKMSClient` implements the same `KMSClient` interface as AWS KMS but uses locally-managed AES-256 master keys. Each encrypted DEK is self-describing — it carries the master key version in its first 2 bytes, so decryption always selects the correct key without external metadata.

### When to Use Local KMS vs AWS KMS

| Criteria | AWS KMS | Local KMS |
|---|---|---|
| PII in production | Recommended | Acceptable with operational discipline |
| Hardware-backed key isolation | Yes (HSM) | No — key material in process memory |
| Automatic rotation | Yes (annual, transparent) | Manual (operator-driven) |
| Key version tracking | Automatic (embedded in ciphertext) | Automatic (version prefix in ciphertext) |
| Cloud dependency | Required | None |
| Cost | ~$1/month + API calls | $0 infrastructure |
| Dev/staging/CI | Overkill | Recommended |

## Encrypted DEK Format

```
┌──────────────┬─────────────┬──────────────────────────────┐
│ version (2B) │ nonce (12B) │ AES-256-GCM(dek, master_key) │
│ big-endian   │             │ ciphertext + 16B auth tag    │
└──────────────┴─────────────┴──────────────────────────────┘
```

- **Version** (2 bytes, big-endian uint16): identifies which master key encrypted this DEK
- **Nonce** (12 bytes): unique random nonce per encryption
- **Ciphertext + Tag**: AES-256-GCM encrypted DEK with authentication tag

Total overhead: 30 bytes on top of the 32-byte DEK = 62 bytes per encrypted DEK.

## Key Generation

Generate a cryptographically random 256-bit (32-byte) master key:

```bash
# Option 1: openssl
openssl rand -base64 32

# Option 2: /dev/urandom
head -c 32 /dev/urandom | base64
```

Store the result as a base64-encoded string in your secrets management system (Vault, AWS Secrets Manager, env vars, etc.).

## Environment Variable Convention

```bash
# Master keys — base64-encoded 32-byte values
ENCRYPTION_CMK_V1=<base64-key>
ENCRYPTION_CMK_V2=<base64-key>

# Active version for new DEKs
ENCRYPTION_CMK_CURRENT_VERSION=2
```

In Go config:

```go
type EncryptionConfig struct {
    CMKCurrentVersion uint16            `yaml:"cmk_current_version" env:"ENCRYPTION_CMK_CURRENT_VERSION"`
    CMKKeys           map[uint16]string `yaml:"cmk_keys"` // version → base64-encoded key
    // Or loaded from individual env vars in container wiring
}
```

## Rotation Runbook

### Prerequisites

- [ ] Access to deploy new environment variables to all application instances
- [ ] No in-flight DEK operations (rotation is safe during normal operation, but verify)
- [ ] Backup of current environment variables

### Step 1: Generate New Master Key

```bash
NEW_KEY=$(openssl rand -base64 32)
echo "New key (save securely): $NEW_KEY"
```

### Step 2: Determine New Version Number

```bash
# Current version (from config or env)
CURRENT_VERSION=$ENCRYPTION_CMK_CURRENT_VERSION  # e.g., 1
NEW_VERSION=$((CURRENT_VERSION + 1))              # e.g., 2
```

### Step 3: Add New Key to All Instances

Add the new environment variable **without changing the current version yet**:

```bash
# Add to secrets/env — method depends on your deployment
ENCRYPTION_CMK_V2=<new-base64-key>
# ENCRYPTION_CMK_CURRENT_VERSION remains 1
```

Deploy. At this point:
- New DEKs still use v1 (current version unchanged)
- The new key is pre-loaded but unused
- All instances can decrypt both v1 and v2 DEKs

### Step 4: Switch Active Version

Update the current version:

```bash
ENCRYPTION_CMK_CURRENT_VERSION=2
```

Deploy. At this point:
- New DEKs use v2
- Old v1 DEKs still decrypt (v1 key is still loaded)
- This is a zero-downtime operation

### Step 5: Verify

```bash
# Check application logs for successful DEK operations
# Verify new records have v2-encrypted DEKs:
SELECT id, encode(substring(encrypted_dek from 1 for 2), 'hex') as version_hex
FROM data_encryption_keys
ORDER BY created_at DESC
LIMIT 10;
# version_hex should show '0002' for new records
```

### Step 6: (Optional) Re-encrypt Old DEKs

If you want to retire v1 entirely, run a batch re-encryption:

```sql
-- Find DEKs still on old version (version bytes = 0x0001)
SELECT id, entity_id
FROM data_encryption_keys
WHERE encode(substring(encrypted_dek from 1 for 2), 'hex') = '0001';
```

For each: decrypt with v1, re-encrypt with v2, update the row. This can be a background job. **Only after all DEKs are re-encrypted** can you remove v1 from the config.

### Step 7: (Optional) Remove Old Key

Only after Step 6 confirms zero remaining v1 DEKs:

```bash
# Remove from env/secrets
unset ENCRYPTION_CMK_V1
```

Deploy. If any v1 DEKs remain, decryption will fail with "unknown key version 1".

## Rotation Timeline

```
Day 0:  Generate new key, add ENCRYPTION_CMK_V2 to config
        Deploy (v1 still active, v2 pre-loaded)

Day 0+: Switch ENCRYPTION_CMK_CURRENT_VERSION=2
        Deploy (v2 active for new DEKs, v1 still available)

Day 1+: (Optional) Run re-encryption migration for old DEKs

Day N:  (Optional) After re-encryption complete, remove v1 key
```

The two-phase deploy (add key, then switch version) ensures zero-downtime rotation with no window where an instance lacks the new key.

## Emergency Key Compromise Response

If a master key version is compromised:

1. **Immediately** generate a new key and deploy as the new current version (Steps 1-4 above)
2. **Immediately** run re-encryption for all DEKs on the compromised version (Step 6)
3. **After re-encryption** remove the compromised key (Step 7)
4. **Assess** whether any encrypted DEKs were exfiltrated — if encrypted DEKs were stolen AND the master key was compromised, the attacker can derive plaintext DEKs and decrypt PII

Note: Even with a compromised master key, the attacker also needs access to the database to get the encrypted DEKs. The master key alone is not sufficient — envelope encryption provides defense in depth.

## Monitoring and Alerting

Recommended alerts:

- **Decryption failure with "unknown key version"** — indicates a DEK exists for a version that was removed too early
- **High rate of GenerateDataKey errors** — indicates master key configuration issue
- **DEK version distribution skew** — after rotation, monitor that new DEKs use the new version

Query to check version distribution:

```sql
SELECT
    encode(substring(encrypted_dek from 1 for 2), 'hex') as version_hex,
    count(*) as dek_count,
    min(created_at) as oldest,
    max(created_at) as newest
FROM data_encryption_keys
GROUP BY version_hex
ORDER BY version_hex;
```

## Security Considerations

1. **Master keys in memory**: Unlike AWS KMS (where the CMK never leaves the HSM), local master keys exist in process memory. Ensure:
   - Environment variables are not logged
   - Process memory is not swapped to disk (consider `mlockall` in production)
   - Core dumps are disabled or encrypted

2. **Key storage**: Use a secrets manager (Vault, AWS Secrets Manager) rather than plain env files when possible. The env var pattern is a convention — the actual delivery mechanism should match your security requirements.

3. **Version number space**: uint16 supports versions 0-65535. Version 0 is valid but discouraged (use 1+ for clarity). At one rotation per month, the space lasts ~5,461 years.

4. **No automatic rotation**: Unlike AWS KMS, there is no automatic rotation. Set a calendar reminder or automate via CI/CD pipeline.

## Comparison: AWS KMS Rotation vs Local KMS Rotation

| Aspect | AWS KMS | Local KMS |
|---|---|---|
| Generate new key version | Automatic (annual) or `aws kms rotate-key-on-demand` | Manual: `openssl rand` + deploy |
| Old version availability | Forever (AWS manages) | Until you remove the env var |
| Decrypt version selection | Automatic (metadata in ciphertext) | Automatic (version prefix in ciphertext) |
| Re-encryption needed | Never | Optional (only to retire old versions) |
| Rollback | N/A (all versions always available) | Keep old env vars until re-encryption done |
| Audit trail | CloudTrail logs every KMS API call | Application-level audit logging |
