package rulestore

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RT-06 regression tests: the empty-rules cache contract.
//
//   - empty rule sets are cached with the store TTL (no DB query per request);
//   - a DB error is never cached — neither as "[]" nor as a refresh of the
//     previous value;
//   - Invalidate (the admin create/update/delete contract) makes mutations
//     visible without waiting for the TTL;
//   - a load that races an invalidate may repopulate the pre-mutation value —
//     the documented staleness bound is the TTL; the store itself keeps no
//     local state (no local mutex masquerading as cross-replica invalidation).

// rt06MemCache is an in-memory cacheOps double with TTL semantics shared by
// the tests below.
type rt06MemCache struct {
	mu   sync.RWMutex
	vals map[string][]byte
}

func newRT06MemCache() *rt06MemCache { return &rt06MemCache{vals: map[string][]byte{}} }

func (c *rt06MemCache) Get(_ context.Context, key string) *redis.StringCmd {
	c.mu.RLock()
	v, ok := c.vals[key]
	c.mu.RUnlock()
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(string(v), nil)
}

func (c *rt06MemCache) Set(_ context.Context, key string, val interface{}, _ time.Duration) *redis.StatusCmd {
	var data []byte
	switch v := val.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		data = []byte("???")
	}
	c.mu.Lock()
	c.vals[key] = data
	c.mu.Unlock()
	return redis.NewStatusResult("OK", nil)
}

func (c *rt06MemCache) Del(_ context.Context, keys ...string) *redis.IntCmd {
	c.mu.Lock()
	n := int64(0)
	for _, k := range keys {
		if _, ok := c.vals[k]; ok {
			delete(c.vals, k)
			n++
		}
	}
	c.mu.Unlock()
	return redis.NewIntResult(n, nil)
}

// rt06RuleDB serves rules per org from a mutable map and counts queries.
type rt06RuleDB struct {
	mu      sync.RWMutex
	rules   map[string][]evaluator.Rule
	err     error
	queries atomic.Int64
}

func (d *rt06RuleDB) Query(_ context.Context, _ string, args ...interface{}) (pgx.Rows, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	d.queries.Add(1)
	if d.err != nil {
		return nil, d.err
	}
	orgID, _ := args[0].(string)
	rows := &mockPGXRows{}
	for _, r := range d.rules[orgID] {
		rows.data = append(rows.data, []interface{}{r.ID, r.OrgID, r.MatchExpr, r.TargetModel, r.Priority, r.Enabled})
	}
	return rows, nil
}

func (d *rt06RuleDB) setRules(orgID string, rules []evaluator.Rule) {
	d.mu.Lock()
	d.rules[orgID] = rules
	d.mu.Unlock()
}

func (d *rt06RuleDB) queryCount() int64 { return d.queries.Load() }

func rt06OneRule(org string) []evaluator.Rule {
	return []evaluator.Rule{{ID: "r1", OrgID: org, MatchExpr: "org_id == '" + org + "'", TargetModel: "m1", Priority: 10, Enabled: true}}
}

func TestRT06_EmptyRulesCachedThroughTTLAndInvalidatedOnCreate(t *testing.T) {
	ctx := context.Background()
	org := "rt06-org"
	db := &rt06RuleDB{rules: map[string][]evaluator.Rule{}}
	cache := newRT06MemCache()
	store := New(db, cache, time.Hour, nil, slog.New(slog.DiscardHandler))

	// 1. First load: empty rules from the DB, cached as "[]".
	rules, err := store.GetByOrg(ctx, org)
	require.NoError(t, err)
	assert.Empty(t, rules)
	require.EqualValues(t, 1, db.queryCount())

	// 2. Warm path: repeated reads stay off the DB until the TTL.
	for i := 0; i < 10; i++ {
		rules, err = store.GetByOrg(ctx, org)
		require.NoError(t, err)
		assert.Empty(t, rules)
	}
	assert.EqualValues(t, 1, db.queryCount(), "empty rules must not re-query the DB before the TTL")

	// 3. Admin create: the DB gains a rule and the mutation invalidates.
	db.setRules(org, rt06OneRule(org))
	store.Invalidate(ctx, org)

	rules, err = store.GetByOrg(ctx, org)
	require.NoError(t, err)
	require.Len(t, rules, 1, "new rules must be visible right after create+invalidate")
	assert.Equal(t, "m1", rules[0].TargetModel)
	assert.EqualValues(t, 2, db.queryCount())

	// 4. The new (non-empty) value is now warm too.
	_, err = store.GetByOrg(ctx, org)
	require.NoError(t, err)
	assert.EqualValues(t, 2, db.queryCount())
}

func TestRT06_DBErrorNeverCachedAsNegative(t *testing.T) {
	ctx := context.Background()
	org := "rt06-org-err"
	db := &rt06RuleDB{rules: map[string][]evaluator.Rule{}}
	db.mu.Lock()
	db.err = errors.New("db connection refused")
	db.mu.Unlock()
	cache := newRT06MemCache()
	store := New(db, cache, time.Hour, nil, slog.New(slog.DiscardHandler))

	_, err := store.GetByOrg(ctx, org)
	require.Error(t, err)
	_, ok := cache.vals[cacheKeyPrefix+org]
	assert.False(t, ok, "a DB failure must not be written into the cache in any form")

	// Recovery: the same request path now succeeds and caches.
	db.mu.Lock()
	db.err = nil
	db.mu.Unlock()
	rules, err := store.GetByOrg(ctx, org)
	require.NoError(t, err)
	assert.Empty(t, rules)
	assert.EqualValues(t, 2, db.queryCount(), "the failed lookup was retried, not served from cache")
}

func TestRT06_DBErrorDoesNotClobberCachedValue(t *testing.T) {
	ctx := context.Background()
	org := "rt06-org-keep"
	db := &rt06RuleDB{rules: map[string][]evaluator.Rule{org: rt06OneRule(org)}}
	cache := newRT06MemCache()
	store := New(db, cache, time.Hour, nil, slog.New(slog.DiscardHandler))

	rules, err := store.GetByOrg(ctx, org)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	queries := db.queryCount()

	// DB outage while a warm value exists: the cache shields the request and
	// the outage does not touch the cached entry.
	db.mu.Lock()
	db.err = errors.New("db down")
	db.mu.Unlock()
	rules, err = store.GetByOrg(ctx, org)
	require.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, queries, db.queryCount(), "warm value served without a DB call")

	cached, ok := cache.vals[cacheKeyPrefix+org]
	require.True(t, ok)
	assert.Contains(t, string(cached), "m1", "the outage must not clobber the cached value")

	// After invalidation the outage becomes visible as an explicit error —
	// never as a negative or empty result.
	store.Invalidate(ctx, org)
	_, err = store.GetByOrg(ctx, org)
	require.Error(t, err)

	db.mu.Lock()
	db.err = nil
	db.mu.Unlock()
	rules, err = store.GetByOrg(ctx, org)
	require.NoError(t, err)
	assert.Len(t, rules, 1)
}

func TestRT06_InvalidateRaceWithLoad_BoundedStaleness(t *testing.T) {
	ctx := context.Background()
	org := "rt06-org-race"
	db := &rt06RuleDB{rules: map[string][]evaluator.Rule{}}
	cache := newRT06MemCache()
	store := New(db, cache, time.Hour, nil, slog.New(slog.DiscardHandler))

	// Warm the empty set.
	_, err := store.GetByOrg(ctx, org)
	require.NoError(t, err)

	// Concurrent load/invalidate storm while the DB flips empty → rule → empty.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	db.setRules(org, rt06OneRule(org))
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = store.GetByOrg(ctx, org) // race-storm readers: outcome asserted after settle
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			store.Invalidate(ctx, org)
		}
	}()
	// Flip the DB state under the storm, then settle.
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			db.setRules(org, rt06OneRule(org))
		} else {
			db.setRules(org, nil)
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	// After the storm settles, a sequential read must return exactly what
	// the DB has now (the documented contract: no torn state, no error
	// swallowed into a cached negative).
	db.setRules(org, rt06OneRule(org))
	store.Invalidate(ctx, org)
	rules, err := store.GetByOrg(ctx, org)
	require.NoError(t, err)
	require.Len(t, rules, 1)
}

// rt06StallDB blocks Query for chosen orgs until released.
type rt06StallDB struct {
	mu       sync.Mutex
	blocked  map[string]chan struct{}
	rules    map[string][]evaluator.Rule
	queries  atomic.Int64
	stallOrg string
}

func (d *rt06StallDB) Query(_ context.Context, _ string, args ...interface{}) (pgx.Rows, error) {
	orgID, _ := args[0].(string)
	if orgID == d.stallOrg {
		ch := make(chan struct{})
		d.mu.Lock()
		d.blocked[orgID] = ch
		d.mu.Unlock()
		<-ch
	}
	d.queries.Add(1)
	d.mu.Lock()
	rules := d.rules[orgID]
	d.mu.Unlock()
	rows := &mockPGXRows{}
	for _, r := range rules {
		rows.data = append(rows.data, []interface{}{r.ID, r.OrgID, r.MatchExpr, r.TargetModel, r.Priority, r.Enabled})
	}
	return rows, nil
}

func (d *rt06StallDB) release(orgID string) {
	d.mu.Lock()
	ch, ok := d.blocked[orgID]
	delete(d.blocked, orgID)
	d.mu.Unlock()
	if ok {
		close(ch)
	}
}

func TestRT06_MixedOrgs_StalledLoadDoesNotBlockWarmHit(t *testing.T) {
	ctx := context.Background()
	db := &rt06StallDB{
		blocked:  make(map[string]chan struct{}),
		rules:    map[string][]evaluator.Rule{},
		stallOrg: "org-b",
	}
	db.rules["org-a"] = rt06OneRule("org-a")
	cache := newRT06MemCache()
	store := New(db, cache, time.Hour, nil, slog.New(slog.DiscardHandler))

	// Warm org-a's cache entry first.
	rules, err := store.GetByOrg(ctx, "org-a")
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// Park a cold org-b load inside the DB call.
	orgBStarted := make(chan struct{})
	go func() {
		close(orgBStarted)
		_, _ = store.GetByOrg(ctx, "org-b") // stalled on purpose; released below
	}()
	<-orgBStarted
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		db.mu.Lock()
		_, parked := db.blocked["org-b"]
		db.mu.Unlock()
		if parked {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// org-a's warm read must complete while org-b's load is stalled: the
	// store holds no global lock during I/O (RT-06 acceptance).
	done := make(chan struct{})
	go func() {
		defer close(done)
		rules, err := store.GetByOrg(ctx, "org-a")
		assert.NoError(t, err)
		assert.Len(t, rules, 1)
		assert.Equal(t, "m1", rules[0].TargetModel)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a stalled cold load must not block an unrelated warm org hit")
	}

	db.release("org-b")
}
