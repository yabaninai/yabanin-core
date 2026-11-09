package classifier

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRedisForClassifier is an in-memory mock for the cacheClient interface.
type mockRedisForClassifier struct {
	data map[string]string
}

func newMockRedisForClassifier() *mockRedisForClassifier {
	return &mockRedisForClassifier{
		data: make(map[string]string),
	}
}

// Get implements cacheClient.
func (m *mockRedisForClassifier) Get(ctx context.Context, key string) *redis.StringCmd {
	if val, ok := m.data[key]; ok {
		return redis.NewStringResult(val, nil)
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(redis.Nil)
	return cmd
}

// SetEx implements cacheClient.
func (m *mockRedisForClassifier) SetEx(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	switch v := value.(type) {
	case string:
		m.data[key] = v
	case []byte:
		m.data[key] = string(v)
	default:
		m.data[key] = fmt.Sprintf("%v", v)
	}
	_ = expiration
	return redis.NewStatusResult("OK", nil)
}

// TestRegistryWithCache_CacheMiss_WritesToCache verifies that a cache miss
// triggers classification and writes the result to Redis.
func TestRegistryWithCache_CacheMiss_WritesToCache(t *testing.T) {
	mr := newMockRedisForClassifier()
	inner := NewRegistry(NewRuleTier())
	reg := NewRegistryWithCache(inner, mr, slogDefault())

	res := reg.Classify(context.Background(), Input{Prompt: "Translate this", OrgID: "org-1"})

	require.Equal(t, ClassEasy, res.Class)
	assert.Equal(t, string(SourceRuleTier), res.Source)
	// The cache should have been written.
	assert.NotEmpty(t, mr.data, "cache should have been written")
}

// TestRegistryWithCache_CacheHit_ReturnsCachedResult verifies that a subsequent
// call with the same org+prompt returns a cached result with Source="cache_hit".
func TestRegistryWithCache_CacheHit_ReturnsCachedResult(t *testing.T) {
	mr := newMockRedisForClassifier()
	inner := NewRegistry(NewRuleTier())

	// First call — cache miss, writes to cache.
	reg := NewRegistryWithCache(inner, mr, slogDefault())
	res1 := reg.Classify(context.Background(), Input{Prompt: "Translate this", OrgID: "org-1"})
	require.Equal(t, ClassEasy, res1.Class)

	// Second call — cache hit.
	res2 := reg.Classify(context.Background(), Input{Prompt: "Translate this", OrgID: "org-1"})
	assert.Equal(t, ClassEasy, res2.Class)
	assert.Equal(t, string(SourceCacheHit), res2.Source, "should return cached result")
}

// TestRegistryWithCache_DifferentPrompts_NoCrossTalk verifies that different
// prompts produce different cache keys.
func TestRegistryWithCache_DifferentPrompts_NoCrossTalk(t *testing.T) {
	mr := newMockRedisForClassifier()
	inner := NewRegistry(NewRuleTier())
	reg := NewRegistryWithCache(inner, mr, slogDefault())

	res1 := reg.Classify(context.Background(), Input{Prompt: "Translate", OrgID: "org-1"})
	res2 := reg.Classify(context.Background(), Input{Prompt: "Debug this code", OrgID: "org-1"})

	require.Equal(t, ClassEasy, res1.Class)
	assert.Equal(t, ClassHard, res2.Class)
}

// TestRegistryWithCache_NoOrgID_SkipsCache verifies that empty org ID skips caching.
func TestRegistryWithCache_NoOrgID_SkipsCache(t *testing.T) {
	mr := newMockRedisForClassifier()
	inner := NewRegistry(NewRuleTier())
	reg := NewRegistryWithCache(inner, mr, slogDefault())

	res := reg.Classify(context.Background(), Input{Prompt: "Translate"})
	require.Equal(t, ClassEasy, res.Class)
	// Should not write to cache (no org ID).
	assert.Empty(t, mr.data, "cache should be empty when orgID is missing")
}

// TestRegistryWithCache_NoRedis_DelegatesToInner verifies that when rdb is nil,
// the classifier still works (noop mode).
func TestRegistryWithCache_NoRedis_DelegatesToInner(t *testing.T) {
	inner := NewRegistry(NewRuleTier())
	reg := NewRegistryWithCacheNoop(inner)

	res := reg.Classify(context.Background(), Input{Prompt: "Summarize this"})
	require.Equal(t, ClassEasy, res.Class)
	assert.Greater(t, res.Confidence, 0.0)
}

// TestRegistryWithCache_DifferentOrgs_NoCrossTalk verifies that the same prompt
// for different orgs gets classified independently (different cache keys).
func TestRegistryWithCache_DifferentOrgs_NoCrossTalk(t *testing.T) {
	mr := newMockRedisForClassifier()
	inner := NewRegistry(NewRuleTier())
	reg := NewRegistryWithCache(inner, mr, slogDefault())

	// Same prompt for two different orgs — should produce same classification
	// but with different cache keys.
	res1 := reg.Classify(context.Background(), Input{Prompt: "Translate", OrgID: "org-A"})
	res2 := reg.Classify(context.Background(), Input{Prompt: "Translate", OrgID: "org-B"})

	require.Equal(t, ClassEasy, res1.Class)
	require.Equal(t, ClassEasy, res2.Class)
	// Two cache entries should exist (one per org+prompt combo).
	assert.Len(t, mr.data, 2, "should have two cache entries for different orgs")
}

// slogDefault returns a basic slog.Logger for tests.
func slogDefault() *slog.Logger {
	return slog.Default()
}
