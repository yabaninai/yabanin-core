package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func redisContainer(t *testing.T) *redis.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	ctx := context.Background()

	container, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)

	portStr := port.Port()
	if i := len(portStr) - 4; i > 0 && portStr[i:] == "/tcp" {
		portStr = portStr[:i]
	}
	addr := host + ":" + portStr
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		DialTimeout:  time.Second,
	})

	// Retry loop for container startup.
	for i := 0; i < 20; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, rdb.Ping(ctx).Err(), "test redis should be reachable")

	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestRedisStore_MakeKey(t *testing.T) {
	// RT-05: keys are scoped to the route namespace segment so entries written
	// before the segment existed are never read (safe miss, TTL expiry —
	// same transition style as the org-scoped affinity keys). The v3 segment
	// is the CACHE-02 normalization namespace (v2 entries are never read).
	key := MakeKey("org-1", "smart", "abc123")
	assert.Equal(t, "cache:v3:org-1:smart:abc123", key)
}

func TestRedisStore_KeyPatterns(t *testing.T) {
	assert.Equal(t, "cache:v3:org-1:*", KeyPatternOrg("org-1"))
	assert.Equal(t, "cache:v3:*:smart:*", KeyPatternTier("smart"))
	assert.True(t, strings.HasPrefix(MakeKey("org-1", "smart", "abc123"), "cache:v3:org-1:"),
		"org pattern must match the current namespace layout")
}

func TestRedisStore_ComputePromptHash(t *testing.T) {
	h1 := ComputePromptHash([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
	h2 := ComputePromptHash([]byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	h3 := ComputePromptHash([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))

	assert.Len(t, h1, 64) // SHA-256 hex = 64 chars
	assert.NotEqual(t, h1, h2)
	assert.Equal(t, h1, h3) // same input = same hash
}

func TestRedisStore_PutAndGet(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()
	data := []byte(`{"id":"chat-1","choices":[{"message":{"content":"hello"}}]}`)

	err := store.Put(ctx, "org-1", "smart", "hash-abc", data)
	require.NoError(t, err)

	got, err := store.Get(ctx, "org-1", "smart", "hash-abc")
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestRedisStore_TenantKeysAreIsolated(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, time.Minute)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, "org-a", "smart", "same-prompt", []byte("answer-a")))
	require.NoError(t, store.Put(ctx, "org-b", "smart", "same-prompt", []byte("answer-b")))

	gotA, err := store.Get(ctx, "org-a", "smart", "same-prompt")
	require.NoError(t, err)
	assert.Equal(t, []byte("answer-a"), gotA)
	gotB, err := store.Get(ctx, "org-b", "smart", "same-prompt")
	require.NoError(t, err)
	assert.Equal(t, []byte("answer-b"), gotB)

	assert.NotEqual(t,
		MakeKey("org-a", "smart", "same-prompt"),
		MakeKey("org-b", "smart", "same-prompt"),
		"the same model and prompt hash must occupy distinct tenant keys")
}

func TestRedisStore_HasTrue(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()
	data := []byte(`{"id":"x","choices":[]}`)

	err := store.Put(ctx, "org-1", "cheap", "h1", data)
	require.NoError(t, err)

	exists, err := store.Has(ctx, "org-1", "cheap", "h1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisStore_HasFalse(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()

	exists, err := store.Has(ctx, "org-1", "cheap", "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestRedisStore_Delete(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()
	data := []byte(`{"id":"del","choices":[]}`)

	err := store.Put(ctx, "org-1", "smart", "to-delete", data)
	require.NoError(t, err)

	err = store.Delete(ctx, "org-1", "smart", "to-delete")
	require.NoError(t, err)

	exists, err := store.Has(ctx, "org-1", "smart", "to-delete")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestRedisStore_PutAndMiss(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()

	_, err := store.Get(ctx, "org-1", "cheap", "no-such-key")
	require.ErrorIs(t, err, redis.Nil)
}

func TestRedisStore_Stats(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Second)

	ctx := context.Background()

	// Initially empty.
	count, err := store.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Add some entries.
	for i := 0; i < 5; i++ {
		err := store.Put(ctx, "org-1", "smart", string(rune('a'+i)), []byte(`{"x":1}`))
		require.NoError(t, err)
	}

	count, err = store.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestRedisStore_TTLExpiry(t *testing.T) {
	rdb := redisContainer(t)
	// Use 1-second TTL for fast expiry test.
	store := NewRedisStore(rdb, 1*time.Second)

	ctx := context.Background()
	data := []byte(`{"id":"ttl","choices":[]}`)

	err := store.Put(ctx, "org-1", "cheap", "ttl-key", data)
	require.NoError(t, err)

	// Should be present.
	exists, _ := store.Has(ctx, "org-1", "cheap", "ttl-key")
	assert.True(t, exists)

	// Wait for expiry.
	time.Sleep(2 * time.Second)

	// Should be gone.
	exists, _ = store.Has(ctx, "org-1", "cheap", "ttl-key")
	assert.False(t, exists)
}

// TestRedisStore_PurgeExpired_KeepsPersistentAndLiveKeys verifies the purge
// honesty contract: only keys whose TTL actually expired are removed. A
// persistent key (TTL == -1, e.g. a legacy write without expiry) must survive
// a TTL purge, and live keys must be untouched.
func TestRedisStore_PurgeExpired_KeepsPersistentAndLiveKeys(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, time.Hour)

	ctx := context.Background()

	persistentKey := MakeKey("org-1", "smart", "persistent")
	require.NoError(t, rdb.Set(ctx, persistentKey, `{"id":"persistent"}`, 0).Err()) // 0 = no expiry
	require.NoError(t, rdb.Persist(ctx, persistentKey).Err())

	liveKey := MakeKey("org-1", "smart", "live")
	require.NoError(t, rdb.Set(ctx, liveKey, `{"id":"live"}`, time.Hour).Err())

	// A key whose TTL has fully elapsed (expired but possibly not yet reaped).
	expiredKey := MakeKey("org-1", "smart", "expired")
	require.NoError(t, rdb.Set(ctx, expiredKey, `{"id":"expired"}`, 50*time.Millisecond).Err())
	time.Sleep(200 * time.Millisecond)

	deleted, err := store.PurgeExpired(ctx)
	require.NoError(t, err)

	assert.LessOrEqual(t, deleted, 1, "at most the expired key may be deleted")

	exists, err := rdb.Exists(ctx, persistentKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists, "a persistent key (TTL == -1) must never be deleted by a TTL purge")

	exists, err = rdb.Exists(ctx, liveKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists, "a live key must not be deleted by a TTL purge")

	exists, err = rdb.Exists(ctx, expiredKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "an expired key must be gone after the purge")

	// A second purge must be a no-op over the survivors.
	deletedAgain, err := store.PurgeExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, deletedAgain)
}

// TestRedisStore_PurgeExpired_KeepsSubSecondLiveKey pins the PTTL fix
// (N03-P05-T03): the second-granular TTL command reports 0 for a sub-second
// remainder, which the purge used to read as "expired" — UNLINKing a
// still-live key up to half a second early. With millisecond-precision PTTL
// the purge must keep such a key and let it expire naturally.
func TestRedisStore_PurgeExpired_KeepsSubSecondLiveKey(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, time.Hour)

	ctx := context.Background()
	key := MakeKey("org-subsec", "smart", "live-subsecond")
	// 1.5s TTL, sampled after ~1.1s: the remainder (~0.4s) is sub-second, so
	// the legacy TTL command already reads 0 (it rounds <500ms down to 0)
	// while the key is still live — exactly the truncation window the fix
	// targets.
	require.NoError(t, rdb.Set(ctx, key, `{"id":"subsec"}`, 1500*time.Millisecond).Err())
	time.Sleep(1100 * time.Millisecond)

	// Premise: second-granular TTL reads 0 (sub-second remainder) while PTTL
	// still shows a live remainder. Guarded so a pathologically slow runner
	// that missed the ~0.5s window skips honestly instead of flaking.
	legacyTTL, err := rdb.TTL(ctx, key).Result()
	require.NoError(t, err)
	pttlRemainder, err := rdb.PTTL(ctx, key).Result()
	require.NoError(t, err)
	if legacyTTL != 0 || pttlRemainder <= 0 {
		t.Skipf("sub-second truncation window not reached on this runner (TTL=%v PTTL=%v)", legacyTTL, pttlRemainder)
	}

	deleted, err := store.PurgeExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted, "a key with a sub-second TTL remainder is still live and must not be purged")

	exists, err := rdb.Exists(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists, "live sub-second key must survive the purge")

	// It must still expire naturally right after the purge.
	deadline := time.Now().Add(2 * time.Second)
	for {
		exists, err = rdb.Exists(ctx, key).Result()
		require.NoError(t, err)
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live sub-second key did not expire naturally after the purge")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
