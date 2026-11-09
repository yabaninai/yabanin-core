package cache

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RT-05 container roundtrips (real Redis, testcontainers — skipped in
// -short like the rest of the Redis tests): write→lookup under the same
// route identity hits; every provenance mismatch degrades to a miss; a
// legacy raw value under a v2 key is never served.

func TestService_RouteIdentity_ExactRoundTrip(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)

	cold, err := cs.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	assert.Nil(t, cold, "cold lookup must miss")

	resp := []byte(`{"id":"c1","choices":[{"message":{"content":"ok"}}]}`)
	require.NoError(t, cs.Write(context.Background(), ri, body, resp, 1, 2))

	hit, err := cs.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.Equal(t, "exact", hit.SourceType)
	assert.Equal(t, "m-1", hit.ModelUsed, "hit must carry the provenance model used")
	assert.JSONEq(t, string(resp), string(hit.Data))
}

func TestService_RouteIdentity_ProvenanceMismatch_IsMiss(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)

	body := []byte(`{"messages":[{"role":"user","content":"mismatch"}]}`)
	resp := []byte(`{"id":"c2","choices":[{"message":{"content":"ok"}}]}`)
	require.NoError(t, cs.Write(context.Background(),
		RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}, body, resp, 1, 1))

	for name, ri := range map[string]RouteIdentity{
		"other org":        {OrgID: "org-2", Model: "m-1", GenParams: "high"},
		"other model":      {OrgID: "org-1", Model: "m-2", GenParams: "high"},
		"other gen params": {OrgID: "org-1", Model: "m-1", GenParams: "low"},
		"other namespace":  {OrgID: "org-1", Model: "m-1", GenParams: "high", Version: "v2"},
	} {
		hit, err := cs.LookupWithResult(context.Background(), ri, body)
		require.NoError(t, err)
		assert.Nil(t, hit, "%s must miss: provenance does not match the route", name)
	}
}

func TestService_LegacyNamespaceValue_IsMissAndRefillWithoutFlush(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"legacy"}]}`)
	resp := []byte(`{"id":"legacy","choices":[{"message":{"content":"old"}}]}`)

	// Seed a pre-RT-05 entry at the LEGACY key layout (no v2 segment, raw
	// payload — the namespace the affinity v2 transition left behind).
	legacyKey := "cache:" + ri.OrgID + ":" + ri.Model + ":" + ComputePromptHash(body)
	require.NoError(t, rdb.Set(context.Background(), legacyKey, resp, time.Hour).Err())

	hit, err := cs.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "a legacy-namespace entry must never be served")

	// Safe refill: the next write lands in the v2 namespace and is served.
	require.NoError(t, cs.Write(context.Background(), ri, body, []byte(`{"id":"fresh","choices":[{"message":{"content":"new"}}]}`), 1, 1))
	hit, err = cs.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, `{"id":"fresh","choices":[{"message":{"content":"new"}}]}`, string(hit.Data))

	// The legacy namespace is untouched by the transition: its bytes are
	// still there (never read, never deleted — they expire through their
	// own TTL). No FLUSHDB, no foreign-key deletion.
	old, err := rdb.Get(context.Background(), legacyKey).Result()
	require.NoError(t, err)
	assert.JSONEq(t, string(resp), old, "legacy namespace must not be deleted by new code")
}

func TestService_LegacyValueAtCurrentKey_IgnoredNotDeleted(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"legacy2"}]}`)
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(body))
	require.NoError(t, rdb.Set(context.Background(), key, []byte(`{"id":"raw-legacy"}`), time.Hour).Err())

	hit, err := cs.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit)

	val, err := rdb.Get(context.Background(), key).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, val, "the stale entry must be ignored, not deleted — refill overwrites it")
}

// newRoutedTestService builds a CacheService with the real Redis store and an
// in-memory always-enabled policy (no Postgres: semantic stays off through
// the policy, pg exact disabled). The async writer is born stopped — this
// suite targets the exact layer; Submit then records a dropped write instead
// of touching a nil pool.
func newRoutedTestService(rdb *redis.Client) *CacheService {
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slog.New(slog.DiscardHandler))
	w.StopWithTimeout(5 * time.Second) // born stopped: Submit then drops instead of touching a nil pool
	return &CacheService{
		exact:  NewRedisStore(rdb, 24*time.Hour),
		policy: pc,
		writer: w,
		log:    slog.New(slog.DiscardHandler),
	}
}
