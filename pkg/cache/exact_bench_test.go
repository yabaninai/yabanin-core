package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func BenchmarkExactCache_Get_Hit(b *testing.B) {
	rdb := redis.NewClient(&redis.Options{Addr: ":6379"})
	store := NewRedisStore(rdb, 24*1000)

	// Pre-populate cache.
	key := MakeKey("org-1", "smart", "abc123")
	rdb.Set(context.Background(), key, []byte(`{"id":"chatcmpl-1","choices":[{"delta":{"content":"hello"}}]}`), 24*365*24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		val, err := store.Get(context.Background(), "org-1", "smart", "abc123")
		if err != nil || val == nil {
			b.Fatal("expected hit")
		}
		if len(val) == 0 {
			b.Fatal("empty response")
		}
	}
}

func BenchmarkExactCache_Get_Miss(b *testing.B) {
	rdb := redis.NewClient(&redis.Options{Addr: ":6379"})
	store := NewRedisStore(rdb, 24*1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Get(context.Background(), "org-1", "smart", "nonexistent-key-"+strings.Repeat("a", 8))
		if err == nil {
			b.Fatal("expected miss")
		}
	}
}

func BenchmarkNormalizeMessagesJSON_Small(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":false}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := NormalizeMessagesJSON(body)
		if err != nil {
			b.Fatal(err)
		}
		if len(result) == 0 {
			b.Fatal("empty result")
		}
	}
}

func BenchmarkFastHash(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],"stream":false}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := FastHash(body)
		if len(h) != 64 {
			b.Fatal("expected 64-char hex digest")
		}
	}
}
