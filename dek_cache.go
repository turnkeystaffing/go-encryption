package encryption

import (
	"sync"
	"time"
)

type dekCacheEntry struct {
	dek       []byte
	expiresAt time.Time
	createdAt time.Time
}

// DEKCache provides a bounded, short-TTL in-memory cache for plaintext DEKs.
// All stored DEKs are independent copies. All evicted or expired DEKs are
// zeroed from memory.
type DEKCache struct {
	mu         sync.RWMutex
	entries    map[string]*dekCacheEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time // injectable for testing
}

// NewDEKCache creates a DEK cache with the given TTL and max entry count.
func NewDEKCache(ttl time.Duration, maxEntries int) *DEKCache {
	return &DEKCache{
		entries:    make(map[string]*dekCacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Get returns a copy of the cached plaintext DEK for the given entityID.
// Returns (nil, false) if not found or expired. Expired entries are removed
// and their DEK zeroed.
func (c *DEKCache) Get(entityID string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[entityID]
	if !ok {
		return nil, false
	}

	if c.now().After(entry.expiresAt) {
		ZeroDEK(entry.dek)
		delete(c.entries, entityID)
		return nil, false
	}

	// Return a copy, not a reference.
	result := make([]byte, len(entry.dek))
	copy(result, entry.dek)
	return result, true
}

// Put stores a copy of the plaintext DEK for the given entityID. If the cache
// is at capacity, the oldest entry is evicted and its DEK zeroed.
func (c *DEKCache) Put(entityID string, dek []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, zero old DEK and replace.
	if existing, ok := c.entries[entityID]; ok {
		ZeroDEK(existing.dek)
		delete(c.entries, entityID)
	}

	// Evict oldest if at capacity.
	if len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}

	stored := make([]byte, len(dek))
	copy(stored, dek)

	now := c.now()
	c.entries[entityID] = &dekCacheEntry{
		dek:       stored,
		expiresAt: now.Add(c.ttl),
		createdAt: now,
	}
}

// Evict removes a specific entry and zeroes its DEK.
func (c *DEKCache) Evict(entityID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[entityID]; ok {
		ZeroDEK(entry.dek)
		delete(c.entries, entityID)
	}
}

// Clear zeroes and removes all entries. Intended for shutdown cleanup.
func (c *DEKCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, entry := range c.entries {
		ZeroDEK(entry.dek)
		delete(c.entries, id)
	}
}

// Len returns the current number of cached entries.
func (c *DEKCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// evictOldestLocked removes the entry with the earliest createdAt timestamp.
// Caller must hold c.mu.
func (c *DEKCache) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	first := true

	for id, entry := range c.entries {
		if first || entry.createdAt.Before(oldestTime) {
			oldestID = id
			oldestTime = entry.createdAt
			first = false
		}
	}

	if !first {
		ZeroDEK(c.entries[oldestID].dek)
		delete(c.entries, oldestID)
	}
}
