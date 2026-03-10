package encryption

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EncryptionProviderConfig is the serializable configuration for the encryption
// provider. Consuming projects embed this in their config struct and load it
// from YAML files or environment variables.
//
// YAML example:
//
//	encryption:
//	  provider: "local"
//	  cmk_key_arn: ""
//	  local_kms:
//	    current_version: 1
//	    keys: "1:dGVzdGtleS4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4="
//
// Env var example (keys as delimited string):
//
//	BGCHECK_ENCRYPTION_PROVIDER=local
//	BGCHECK_ENCRYPTION_LOCAL_KMS_CURRENT_VERSION=1
//	BGCHECK_ENCRYPTION_LOCAL_KMS_KEYS=1:base64key1,2:base64key2
type EncryptionProviderConfig struct {
	// Provider selects the KMS backend: "aws", "local", or "none".
	Provider string `yaml:"provider"`

	// CMKKeyARN is the AWS KMS Customer Master Key ARN. Required when Provider is "aws".
	CMKKeyARN string `yaml:"cmk_key_arn"`

	// LocalKMS configures the local KMS client. Required when Provider is "local".
	LocalKMS LocalKMSYAMLConfig `yaml:"local_kms"`
}

// LocalKMSYAMLConfig is the YAML/env-var-friendly configuration for LocalKMSClient.
// Keys are stored as a comma-separated string of "version:base64key" pairs.
//
// Format: "1:base64key1,2:base64key2"
//
// Delimiter safety: base64 alphabet (A-Za-z0-9+/=) never contains ':' or ','
// so the delimiters are unambiguous.
type LocalKMSYAMLConfig struct {
	// CurrentVersion is the active version for new DEKs.
	CurrentVersion uint16 `yaml:"current_version"`

	// Keys is a comma-separated string of "version:base64key" pairs.
	// Each key must decode to exactly 32 bytes (AES-256).
	// Example: "1:dGVzdC4uLg==,2:bmV3a2V5Li4u"
	Keys string `yaml:"keys"`
}

// ParseKeys parses a delimited key string into a version→key map.
// Format: "version:base64key,version:base64key"
//
// Returns an error if:
//   - the string is empty
//   - any entry is malformed (missing colon, bad version number)
//   - any base64 value fails to decode
//   - any decoded key is not exactly 32 bytes
func ParseKeys(raw string) (map[uint16][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("encryption config: keys string is empty")
	}

	entries := strings.Split(raw, ",")
	keys := make(map[uint16][]byte, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("encryption config: malformed key entry %q, expected version:base64key", entry)
		}

		versionStr := strings.TrimSpace(parts[0])
		b64Key := strings.TrimSpace(parts[1])

		version, err := strconv.ParseUint(versionStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("encryption config: invalid version number %q: %w", versionStr, err)
		}

		keyBytes, err := base64.StdEncoding.DecodeString(b64Key)
		if err != nil {
			return nil, fmt.Errorf("encryption config: key version %d has invalid base64: %w", version, err)
		}

		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("encryption config: key version %d has invalid length %d bytes, require 32 (AES-256)", version, len(keyBytes))
		}

		if _, exists := keys[uint16(version)]; exists {
			return nil, fmt.Errorf("encryption config: duplicate key version %d", version)
		}

		keys[uint16(version)] = keyBytes
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("encryption config: no valid keys found")
	}

	return keys, nil
}

// BuildLocalKMSConfig validates the YAML config and produces a runtime
// LocalKMSConfig suitable for NewLocalKMSClient.
//
// Returns an error if:
//   - keys string is empty or malformed
//   - any key is not exactly 32 bytes after base64 decode
//   - CurrentVersion is not present in the parsed keys
func BuildLocalKMSConfig(cfg LocalKMSYAMLConfig) (LocalKMSConfig, error) {
	keys, err := ParseKeys(cfg.Keys)
	if err != nil {
		return LocalKMSConfig{}, err
	}

	if _, ok := keys[cfg.CurrentVersion]; !ok {
		available := make([]uint16, 0, len(keys))
		for v := range keys {
			available = append(available, v)
		}
		return LocalKMSConfig{}, fmt.Errorf(
			"encryption config: current_version %d not found in keys (available: %v)",
			cfg.CurrentVersion, available,
		)
	}

	return LocalKMSConfig{
		CurrentVersion: cfg.CurrentVersion,
		Keys:           keys,
	}, nil
}

// ValidateProviderConfig validates the EncryptionProviderConfig and returns
// a clear error describing what is wrong. Call this at startup to fail fast.
func ValidateProviderConfig(cfg EncryptionProviderConfig) error {
	switch cfg.Provider {
	case "aws":
		if cfg.CMKKeyARN == "" {
			return fmt.Errorf("encryption config: cmk_key_arn is required when provider is \"aws\"")
		}
		return nil

	case "local":
		_, err := BuildLocalKMSConfig(cfg.LocalKMS)
		return err

	case "none":
		return nil

	default:
		return fmt.Errorf("encryption config: unknown provider %q (valid: \"aws\", \"local\", \"none\")", cfg.Provider)
	}
}
