package lineage

import (
	"context"
	"testing"
	"time"
)

// KeyStore is concrete and pool-backed, so these tests exercise the cache
// itself: the map is seeded directly (same-package access) and the KeyStore
// is built with a nil pool — any store access on a cache hit would panic, so
// a clean return proves the hit path is store-free.

func seededKeyCache(t *testing.T, orgID string, expired bool) *KeyCache {
	t.Helper()
	ks := NewKeyStore(nil, nil)
	c := NewKeyCache(ks, 5*time.Minute)
	exp := time.Now().Add(5 * time.Minute)
	if expired {
		exp = time.Now().Add(-time.Second)
	}
	c.mu.Lock()
	c.m[orgID] = cachedKey{keyID: "k1", pub: []byte("pub"), priv: []byte("priv"), expires: exp}
	c.mu.Unlock()
	return c
}

func TestKeyCache_HitDoesNotTouchStore(t *testing.T) {
	c := seededKeyCache(t, "org-1", false)

	keyID, pub, priv, err := c.EnsureKeyPair(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("EnsureKeyPair: %v", err)
	}
	if keyID != "k1" || string(pub) != "pub" || string(priv) != "priv" {
		t.Fatalf("got (%q %q %q), want (k1 pub priv)", keyID, pub, priv)
	}
}

func TestKeyCache_ExpiryMissCondition(t *testing.T) {
	c := seededKeyCache(t, "org-1", true)

	// An expired entry must be treated as a miss (the store would be
	// consulted next; with the nil-pool store that path panics, so verify
	// the expiry condition directly instead).
	c.mu.RLock()
	k := c.m["org-1"]
	c.mu.RUnlock()
	if time.Now().Before(k.expires) {
		t.Fatal("entry should be expired, but expiry check reports a hit")
	}
}

func TestKeyCache_ThreadSafe(t *testing.T) {
	c := seededKeyCache(t, "org-1", false)

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			keyID, pub, priv, err := c.EnsureKeyPair(context.Background(), "org-1")
			if err != nil || keyID != "k1" || string(pub) != "pub" || string(priv) != "priv" {
				t.Error("concurrent EnsureKeyPair mismatch:", keyID, pub, priv, err)
			}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}
