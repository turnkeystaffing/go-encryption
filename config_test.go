package encryption

import (
	"encoding/base64"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBase64Key(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

func TestParseKeys_SingleKey(t *testing.T) {
	b64 := testBase64Key(t)
	keys, err := ParseKeys("1:" + b64)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Len(t, keys[1], 32)
}

func TestParseKeys_MultipleKeys(t *testing.T) {
	b64v1 := testBase64Key(t)
	b64v2 := testBase64Key(t)
	keys, err := ParseKeys("1:" + b64v1 + ",2:" + b64v2)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Len(t, keys[1], 32)
	assert.Len(t, keys[2], 32)
}

func TestParseKeys_WhitespaceHandling(t *testing.T) {
	b64 := testBase64Key(t)
	keys, err := ParseKeys("  1 : " + b64 + " , 2 : " + testBase64Key(t) + "  ")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestParseKeys_EmptyString(t *testing.T) {
	_, err := ParseKeys("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keys string is empty")
}

func TestParseKeys_MalformedEntry(t *testing.T) {
	_, err := ParseKeys("no-colon-here")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed key entry")
}

func TestParseKeys_InvalidVersion(t *testing.T) {
	b64 := testBase64Key(t)
	_, err := ParseKeys("abc:" + b64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version number")
}

func TestParseKeys_InvalidBase64(t *testing.T) {
	_, err := ParseKeys("1:not-valid-base64!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base64")
}

func TestParseKeys_WrongKeyLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err := ParseKeys("1:" + shortKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length")
	assert.Contains(t, err.Error(), "require 32")
}

func TestParseKeys_DuplicateVersion(t *testing.T) {
	b64 := testBase64Key(t)
	_, err := ParseKeys("1:" + b64 + ",1:" + b64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate key version")
}

func TestParseKeys_VersionOverflow(t *testing.T) {
	b64 := testBase64Key(t)
	_, err := ParseKeys("99999:" + b64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version number")
}

func TestBuildLocalKMSConfig_Valid(t *testing.T) {
	b64 := testBase64Key(t)
	cfg, err := BuildLocalKMSConfig(LocalKMSYAMLConfig{
		CurrentVersion: 1,
		Keys:           "1:" + b64,
	})
	require.NoError(t, err)
	assert.Equal(t, uint16(1), cfg.CurrentVersion)
	assert.Len(t, cfg.Keys, 1)
	assert.Len(t, cfg.Keys[1], 32)
}

func TestBuildLocalKMSConfig_MissingCurrentVersion(t *testing.T) {
	b64 := testBase64Key(t)
	_, err := BuildLocalKMSConfig(LocalKMSYAMLConfig{
		CurrentVersion: 5,
		Keys:           "1:" + b64,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "current_version 5 not found")
}

func TestBuildLocalKMSConfig_InvalidKeys(t *testing.T) {
	_, err := BuildLocalKMSConfig(LocalKMSYAMLConfig{
		CurrentVersion: 1,
		Keys:           "",
	})
	require.Error(t, err)
}

func TestValidateProviderConfig_AWS_Valid(t *testing.T) {
	err := ValidateProviderConfig(EncryptionProviderConfig{
		Provider:  "aws",
		CMKKeyARN: "arn:aws:kms:us-east-1:123:key/test",
	})
	assert.NoError(t, err)
}

func TestValidateProviderConfig_AWS_MissingARN(t *testing.T) {
	err := ValidateProviderConfig(EncryptionProviderConfig{
		Provider: "aws",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cmk_key_arn is required")
}

func TestValidateProviderConfig_Local_Valid(t *testing.T) {
	b64 := testBase64Key(t)
	err := ValidateProviderConfig(EncryptionProviderConfig{
		Provider: "local",
		LocalKMS: LocalKMSYAMLConfig{
			CurrentVersion: 1,
			Keys:           "1:" + b64,
		},
	})
	assert.NoError(t, err)
}

func TestValidateProviderConfig_Local_BadKeys(t *testing.T) {
	err := ValidateProviderConfig(EncryptionProviderConfig{
		Provider: "local",
		LocalKMS: LocalKMSYAMLConfig{
			CurrentVersion: 1,
			Keys:           "",
		},
	})
	require.Error(t, err)
}

func TestValidateProviderConfig_None(t *testing.T) {
	assert.NoError(t, ValidateProviderConfig(EncryptionProviderConfig{Provider: "none"}))
}

func TestValidateProviderConfig_EmptyIsInvalid(t *testing.T) {
	err := ValidateProviderConfig(EncryptionProviderConfig{Provider: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestValidateProviderConfig_Unknown(t *testing.T) {
	err := ValidateProviderConfig(EncryptionProviderConfig{Provider: "gcp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestBuildLocalKMSConfig_EndToEnd(t *testing.T) {
	// Simulate: config loaded from YAML/env → build runtime config → create client → encrypt/decrypt.
	b64v1 := testBase64Key(t)
	b64v2 := testBase64Key(t)

	yamlCfg := LocalKMSYAMLConfig{
		CurrentVersion: 2,
		Keys:           "1:" + b64v1 + ",2:" + b64v2,
	}

	runtimeCfg, err := BuildLocalKMSConfig(yamlCfg)
	require.NoError(t, err)

	client := NewLocalKMSClient(runtimeCfg)
	assert.Equal(t, uint16(2), client.CurrentVersion())
	assert.True(t, client.HasVersion(1))
	assert.True(t, client.HasVersion(2))
}
