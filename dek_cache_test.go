package encryption

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	return dek
}

func TestDEKCache_PutGet(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	dek := fakeDEK(t)

	cache.Put("entity-1", dek)
	got, ok := cache.Get("entity-1")
	require.True(t, ok)
	assert.Equal(t, dek, got)
}

func TestDEKCache_ReturnsCopy(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	dek := fakeDEK(t)

	cache.Put("entity-1", dek)
	got1, _ := cache.Get("entity-1")
	got2, _ := cache.Get("entity-1")

	// Mutating one copy must not affect the other.
	got1[0] ^= 0xFF
	assert.NotEqual(t, got1, got2, "returned values must be independent copies")
}

func TestDEKCache_StoreCopy(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	dek := fakeDEK(t)
	original := make([]byte, len(dek))
	copy(original, dek)

	cache.Put("entity-1", dek)

	// Mutating the input must not affect the cached value.
	dek[0] ^= 0xFF
	got, ok := cache.Get("entity-1")
	require.True(t, ok)
	assert.Equal(t, original, got)
}

func TestDEKCache_Miss(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	got, ok := cache.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestDEKCache_Expiration(t *testing.T) {
	now := time.Now()
	cache := NewDEKCache(1*time.Minute, 10)
	cache.now = func() time.Time { return now }

	cache.Put("entity-1", fakeDEK(t))

	// Advance past TTL.
	cache.now = func() time.Time { return now.Add(2 * time.Minute) }
	got, ok := cache.Get("entity-1")
	assert.False(t, ok)
	assert.Nil(t, got)
	assert.Equal(t, 0, cache.Len(), "expired entry should be removed")
}

func TestDEKCache_EvictsOldest(t *testing.T) {
	now := time.Now()
	step := 0
	cache := NewDEKCache(5*time.Minute, 2)
	cache.now = func() time.Time {
		step++
		return now.Add(time.Duration(step) * time.Second)
	}

	cache.Put("entity-1", fakeDEK(t))
	cache.Put("entity-2", fakeDEK(t))
	assert.Equal(t, 2, cache.Len())

	// Adding a third should evict entity-1 (oldest).
	cache.Put("entity-3", fakeDEK(t))
	assert.Equal(t, 2, cache.Len())

	_, ok := cache.Get("entity-1")
	assert.False(t, ok, "entity-1 should have been evicted")

	_, ok = cache.Get("entity-3")
	assert.True(t, ok)
}

func TestDEKCache_Evict(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	cache.Put("entity-1", fakeDEK(t))
	assert.Equal(t, 1, cache.Len())

	cache.Evict("entity-1")
	assert.Equal(t, 0, cache.Len())

	_, ok := cache.Get("entity-1")
	assert.False(t, ok)
}

func TestDEKCache_Clear(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	cache.Put("entity-1", fakeDEK(t))
	cache.Put("entity-2", fakeDEK(t))
	assert.Equal(t, 2, cache.Len())

	cache.Clear()
	assert.Equal(t, 0, cache.Len())
}

func TestDEKCache_ReplaceExisting(t *testing.T) {
	cache := NewDEKCache(5*time.Minute, 10)
	dek1 := fakeDEK(t)
	dek2 := fakeDEK(t)

	cache.Put("entity-1", dek1)
	cache.Put("entity-1", dek2)
	assert.Equal(t, 1, cache.Len())

	got, ok := cache.Get("entity-1")
	require.True(t, ok)
	assert.Equal(t, dek2, got)
}
