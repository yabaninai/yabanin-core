// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"container/list"
	"sync"
)

// EmbedCache is a thread-safe in-memory LRU cache for embedding results.
// It caches the embedding vector for a prompt string to avoid redundant network calls.
// Both Get and Set refresh recency: the least-recently-used entry is evicted
// when the cache is over capacity, and Set replaces the value of an existing
// key instead of silently keeping the stale one.
type EmbedCache struct {
	mu      sync.Mutex // guards items and lru; Get mutates LRU order
	items   map[string]*list.Element
	lru     *list.List // front = most recently used; values are *embedEntry
	maxSize int
	onEvict func(key string, val []float32)
}

type embedEntry struct {
	key string
	vec []float32
}

// NewEmbedCache creates a new embedding cache with the given max size.
func NewEmbedCache(maxSize int) *EmbedCache {
	if maxSize <= 0 {
		maxSize = 1024
	}
	return &EmbedCache{
		items:   make(map[string]*list.Element, maxSize),
		lru:     list.New(),
		maxSize: maxSize,
	}
}

// Set stores an embedding vector for the given prompt key. An existing entry
// is updated in place (value replaced, recency refreshed).
func (c *EmbedCache) Set(key string, vec []float32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[key]; exists {
		elem.Value.(*embedEntry).vec = vec
		c.lru.MoveToFront(elem)
		return
	}

	// Evict the least-recently-used entry if at capacity.
	for len(c.items) >= c.maxSize {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.removeElementLocked(oldest)
	}

	c.items[key] = c.lru.PushFront(&embedEntry{key: key, vec: vec})
}

// Get retrieves a cached embedding vector for the given prompt key.
// Returns (vec, true) on hit, (nil, false) on miss. A hit refreshes recency.
func (c *EmbedCache) Get(key string) ([]float32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*embedEntry)
	c.lru.MoveToFront(elem)
	return entry.vec, true
}

// Delete removes a cached entry.
func (c *EmbedCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.removeElementLocked(elem)
	}
}

// Clear removes all cached entries.
func (c *EmbedCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element, c.maxSize)
	c.lru.Init()
}

// Size returns the number of items in the cache.
func (c *EmbedCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// removeElementLocked drops one entry and reports it to the eviction hook.
// Callers must hold c.mu.
func (c *EmbedCache) removeElementLocked(elem *list.Element) {
	entry := c.lru.Remove(elem).(*embedEntry)
	delete(c.items, entry.key)
	if c.onEvict != nil {
		c.onEvict(entry.key, entry.vec)
	}
}
