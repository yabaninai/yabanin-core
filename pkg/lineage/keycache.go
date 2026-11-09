package lineage

import (
	"context"
	"sync"
	"time"
)

// cachedKey holds decrypted key material in memory only. Never logged.
type cachedKey struct {
	keyID     string
	pub, priv []byte
	expires   time.Time
}

// KeyCache memoizes EnsureKeyPair per org (TTL-bounded). Keys rotate rarely;
// a revoked key keeps working for at most one TTL window — same trade-off as
// the resolver's model cache.
type KeyCache struct {
	ks  *KeyStore
	ttl time.Duration

	mu sync.RWMutex
	m  map[string]cachedKey
}

// NewKeyCache wraps a KeyStore with a per-org TTL cache. ttl <= 0 defaults
// to 5 minutes.
func NewKeyCache(ks *KeyStore, ttl time.Duration) *KeyCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &KeyCache{ks: ks, ttl: ttl, m: make(map[string]cachedKey)}
}

// EnsureKeyPair returns the org's active key, consulting the in-memory cache
// first. Falls through to the KeyStore on miss.
func (c *KeyCache) EnsureKeyPair(ctx context.Context, orgID string) (string, []byte, []byte, error) {
	c.mu.RLock()
	k, ok := c.m[orgID]
	c.mu.RUnlock()
	if ok && time.Now().Before(k.expires) {
		return k.keyID, k.pub, k.priv, nil
	}
	keyID, pub, priv, err := c.ks.EnsureKeyPair(ctx, orgID)
	if err != nil {
		return "", nil, nil, err
	}
	c.mu.Lock()
	c.m[orgID] = cachedKey{keyID: keyID, pub: pub, priv: priv, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return keyID, pub, priv, nil
}
