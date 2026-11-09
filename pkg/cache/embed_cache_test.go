package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbedCache_SetAndGet(t *testing.T) {
	cache := NewEmbedCache(100)
	vec := []float32{0.1, 0.2, 0.3}

	cache.Set("prompt-1", vec)

	got, ok := cache.Get("prompt-1")
	assert.True(t, ok)
	assert.Equal(t, vec, got)
}

func TestEmbedCache_Miss(t *testing.T) {
	cache := NewEmbedCache(100)

	_, ok := cache.Get("nonexistent")
	assert.False(t, ok)
}

func TestEmbedCache_Size(t *testing.T) {
	cache := NewEmbedCache(100)
	assert.Equal(t, 0, cache.Size())

	cache.Set("a", []float32{1})
	cache.Set("b", []float32{2})
	assert.Equal(t, 2, cache.Size())
}

func TestEmbedCache_Delete(t *testing.T) {
	cache := NewEmbedCache(100)
	cache.Set("x", []float32{1})
	assert.Equal(t, 1, cache.Size())

	cache.Delete("x")
	_, ok := cache.Get("x")
	assert.False(t, ok)
	assert.Equal(t, 0, cache.Size())
}

func TestEmbedCache_Clear(t *testing.T) {
	cache := NewEmbedCache(100)
	for i := 0; i < 50; i++ {
		cache.Set(string(rune('a'+i)), []float32{float32(i)})
	}
	assert.Equal(t, 50, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
	_, ok := cache.Get("b")
	assert.False(t, ok)
}

func TestEmbedCache_DuplicateSetUpdatesValue(t *testing.T) {
	cache := NewEmbedCache(100)
	vec1 := []float32{0.1}
	vec2 := []float32{0.2}

	cache.Set("prompt", vec1)
	cache.Set("prompt", vec2) // must replace the stale value, not keep vec1

	assert.Equal(t, 1, cache.Size())
	got, ok := cache.Get("prompt")
	assert.True(t, ok)
	// Must return the SECOND value: Set updates an existing entry.
	assert.Equal(t, vec2, got)
}

func TestEmbedCache_LRU_Eviction(t *testing.T) {
	cache := NewEmbedCache(3)

	cache.Set("a", []float32{1})
	cache.Set("b", []float32{2})
	cache.Set("c", []float32{3})
	assert.Equal(t, 3, cache.Size())

	// Adding a 4th should evict the oldest (a).
	cache.Set("d", []float32{4})
	assert.Equal(t, 3, cache.Size())

	_, ok := cache.Get("a")
	assert.False(t, ok, "oldest entry 'a' should be evicted")
	_, ok = cache.Get("d")
	assert.True(t, ok, "newest entry 'd' should exist")
}

func TestEmbedCache_LRU_GetRefreshesRecency(t *testing.T) {
	cache := NewEmbedCache(3)

	cache.Set("a", []float32{1})
	cache.Set("b", []float32{2})
	cache.Set("c", []float32{3})

	// Touch "a": it is now most-recently-used, so "b" is the LRU entry.
	_, ok := cache.Get("a")
	assert.True(t, ok)

	cache.Set("d", []float32{4})
	_, ok = cache.Get("b")
	assert.False(t, ok, "'b' is least-recently-used and must be evicted")
	_, ok = cache.Get("a")
	assert.True(t, ok, "a Get must refresh recency so 'a' survives")
	_, ok = cache.Get("c")
	assert.True(t, ok, "'c' was not least-recently-used")
	_, ok = cache.Get("d")
	assert.True(t, ok, "newest entry 'd' should exist")
}

func TestEmbedCache_LRU_SetRefreshesRecency(t *testing.T) {
	cache := NewEmbedCache(3)

	cache.Set("a", []float32{1})
	cache.Set("b", []float32{2})
	cache.Set("c", []float32{3})

	// Re-Set "a": updates value and refreshes recency, so "b" becomes the LRU.
	cache.Set("a", []float32{10})

	cache.Set("d", []float32{4})
	_, ok := cache.Get("b")
	assert.False(t, ok, "'b' is least-recently-used and must be evicted")
	got, ok := cache.Get("a")
	assert.True(t, ok, "a re-Set must refresh recency so 'a' survives")
	assert.Equal(t, []float32{10}, got, "re-Set must store the updated value")
}

func TestEmbedCache_ConcurrentAccess(t *testing.T) {
	cache := NewEmbedCache(1000)

	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 1000; i++ {
			cache.Set(string(rune('a'+i%26)), []float32{float32(i)})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			cache.Get(string(rune('a' + i%26)))
		}
		done <- true
	}()

	<-done
	<-done // goroutines complete without race
}
