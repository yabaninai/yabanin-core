package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// S02: key-revocation propagation bound. The resolver caches resolve results
// in Redis for cacheTTL seconds; there is no push-based invalidation, so a
// revoked api_key / agent_key stays resolvable for at most that TTL. These
// tests pin the bound with a fake clock: a TTL-aware Redis double whose
// entries expire as the injected now advances, and a DB double whose
// "active" flag flips to simulate revocation.

// clockedRedis is a RedisClient double with injectable time and real TTL
// semantics: Set stores value with expiry = now+ttl; Get returns it only
// while now < expiry.
type clockedRedis struct {
	now     time.Time
	values  map[string]string
	expires map[string]time.Time
	setTTLs []time.Duration // records every Set's ttl (the propagation bound)
}

func newClockedRedis(start time.Time) *clockedRedis {
	return &clockedRedis{
		now:     start,
		values:  map[string]string{},
		expires: map[string]time.Time{},
	}
}

func (c *clockedRedis) advance(d time.Duration) { c.now = c.now.Add(d) }

func (c *clockedRedis) Get(_ context.Context, key string) *redis.StringCmd {
	if exp, ok := c.expires[key]; ok && c.now.Before(exp) {
		return redis.NewStringResult(c.values[key], nil)
	}
	// Expired entries are invisible (matches real Redis TTL semantics).
	delete(c.values, key)
	delete(c.expires, key)
	return redis.NewStringResult("", errors.New("redis: nil"))
}

func (c *clockedRedis) Set(_ context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	c.setTTLs = append(c.setTTLs, ttl)
	c.values[key] = value.(string)
	c.expires[key] = c.now.Add(ttl)
	return redis.NewStatusResult("", nil)
}

// revocablePool is a DBPool double for the api_keys path: it reports the key
// as active until revoke() is called; afterwards every lookup misses
// (active=false). queries counts DB hits — a cache hit must NOT reach the DB.
type revocablePool struct {
	active  bool
	queries int
}

func (p *revocablePool) QueryRow(_ context.Context, query string, _ ...interface{}) pgx.Row {
	p.queries++
	if !p.active {
		return staticRow{err: pgx.ErrNoRows}
	}
	return staticRow{vals: []string{"key-1", "org-1", "team-1"}}
}

// apiMissAgentHitPool serves the agent_keys row (G1 principals) while the
// api_keys lookup misses, and flips to all-miss on revoke.
type apiMissAgentHitPool struct {
	active bool
}

func (p *apiMissAgentHitPool) QueryRow(_ context.Context, query string, _ ...interface{}) pgx.Row {
	if containsSub(query, "api_keys") {
		return staticRow{err: pgx.ErrNoRows}
	}
	if !p.active {
		return staticRow{err: pgx.ErrNoRows}
	}
	return staticRow{vals: []string{"agent-1", "org-1"}}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// staticRow scans string values positionally into *string destinations.
type staticRow struct {
	vals []string
	err  error
}

func (r staticRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	i := 0
	for _, d := range dest {
		s, ok := d.(*string)
		if !ok {
			continue
		}
		if i < len(r.vals) {
			*s = r.vals[i]
		}
		i++
	}
	return nil
}

func TestRevocation_APIKey_BoundIsTTL(t *testing.T) {
	t0 := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rdb := newClockedRedis(t0)
	pool := &revocablePool{active: true}
	const ttl int64 = 300
	r := auth.NewResolver(pool, rdb, ttl, nil)
	ctx := context.Background()

	// t0: first resolve hits the DB and caches.
	res, err := r.Resolve(ctx, "sk-test-key")
	require.NoError(t, err)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Equal(t, "key-1", res.APIKeyID)
	require.Len(t, rdb.setTTLs, 1)
	assert.Equal(t, time.Duration(ttl)*time.Second, rdb.setTTLs[0],
		"the cache entry TTL is the documented propagation bound")

	// Revoke: DB now reports the key inactive.
	pool.active = false

	// t0+299s (just inside the bound): the cached identity still resolves —
	// this IS the documented stale window.
	rdb.advance(299 * time.Second)
	_, err = r.Resolve(ctx, "sk-test-key")
	require.NoError(t, err, "inside the TTL the revoked key still resolves (documented bound)")
	assert.Equal(t, 1, pool.queries, "no DB re-check while the cache entry is alive")

	// t0+300s (bound reached): the entry expired, the DB is consulted and
	// denies the revoked key.
	rdb.advance(1 * time.Second)
	_, err = r.Resolve(ctx, "sk-test-key")
	require.Error(t, err, "at TTL expiry the revoked key must be denied")
}

func TestRevocation_AgentKey_BoundIsTTL(t *testing.T) {
	t0 := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rdb := newClockedRedis(t0)
	pool := &apiMissAgentHitPool{active: true}
	const ttl int64 = 60
	r := auth.NewResolver(pool, rdb, ttl, nil)
	ctx := context.Background()

	// The api_keys lookup misses; the agent_keys lookup hits.
	res, err := r.Resolve(ctx, "yag-test-agent-key")
	require.NoError(t, err)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Equal(t, "agent-1", res.AgentID)
	require.Len(t, rdb.setTTLs, 1)
	assert.Equal(t, time.Duration(ttl)*time.Second, rdb.setTTLs[0])

	// Revoke the agent key.
	pool.active = false

	// Inside the bound: still resolves from cache.
	rdb.advance(time.Duration(ttl-1) * time.Second)
	res, err = r.Resolve(ctx, "yag-test-agent-key")
	require.NoError(t, err)
	assert.Equal(t, "agent-1", res.AgentID)

	// At the bound: denied.
	rdb.advance(1 * time.Second)
	_, err = r.Resolve(ctx, "yag-test-agent-key")
	require.Error(t, err)
}

func TestRevocation_TTLPropagatesToCache(t *testing.T) {
	t0 := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rdb := newClockedRedis(t0)
	pool := &revocablePool{active: true}
	r := auth.NewResolver(pool, rdb, 42, nil)

	_, err := r.Resolve(context.Background(), "sk-test-key")
	require.NoError(t, err)
	require.Len(t, rdb.setTTLs, 1)
	assert.Equal(t, 42*time.Second, rdb.setTTLs[0],
		"a deployment tightening YABANIN_ORG_RESOLVER_TTL tightens the revocation bound")
}
