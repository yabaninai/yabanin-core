package rulestore

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
)

// RT-06 benchmarks: rulestore DB call counts on warm and empty rule sets.
// dbq/op reports DB queries per GetByOrg call over the whole benchmark run —
// identical fixtures for baseline and post-change runs. The empty-rules set is
// the RT-06 optimization target (cached "[]" with TTL instead of a DB query
// per request).

// rt06BenchCache is a minimal in-memory cacheOps double with TTL semantics.
type rt06BenchCache struct {
	mu     sync.RWMutex
	vals   map[string]rt06BenchEntry
	hits   atomic.Int64
	misses atomic.Int64
}

type rt06BenchEntry struct {
	val interface{}
	exp time.Time
}

func newRT06BenchCache() *rt06BenchCache {
	return &rt06BenchCache{vals: map[string]rt06BenchEntry{}}
}

func (c *rt06BenchCache) Get(_ context.Context, key string) *redis.StringCmd {
	c.mu.RLock()
	e, ok := c.vals[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		c.misses.Add(1)
		return redis.NewStringResult("", redis.Nil)
	}
	c.hits.Add(1)
	switch v := e.val.(type) {
	case string:
		return redis.NewStringResult(v, nil)
	case []byte:
		return redis.NewStringResult(string(v), nil)
	}
	return redis.NewStringResult("", redis.Nil)
}

func (c *rt06BenchCache) Set(_ context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd {
	c.mu.Lock()
	c.vals[key] = rt06BenchEntry{val: val, exp: time.Now().Add(ttl)}
	c.mu.Unlock()
	return redis.NewStatusResult("OK", nil)
}

func (c *rt06BenchCache) Del(_ context.Context, keys ...string) *redis.IntCmd {
	c.mu.Lock()
	for _, k := range keys {
		delete(c.vals, k)
	}
	c.mu.Unlock()
	return redis.NewIntResult(1, nil)
}

// rt06BenchDB counts routing_rules queries and returns the configured rows.
type rt06BenchDB struct {
	queries atomic.Int64
	rules   [][]interface{}
}

func (d *rt06BenchDB) Query(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
	d.queries.Add(1)
	return &mockPGXRows{data: d.rules}, nil
}

func rt06BenchRules(n int, org string) []evaluator.Rule {
	rules := make([]evaluator.Rule, n)
	for i := range rules {
		rules[i] = evaluator.Rule{
			ID:          fmt.Sprintf("r%d", i),
			OrgID:       org,
			MatchExpr:   fmt.Sprintf(`session_id == "s%d"`, i),
			TargetModel: fmt.Sprintf("m%d", i),
			Priority:    i,
			Enabled:     true,
		}
	}
	return rules
}

func rt06BenchRowsFor(rules []evaluator.Rule) [][]interface{} {
	rows := make([][]interface{}, 0, len(rules))
	for _, r := range rules {
		rows = append(rows, []interface{}{r.ID, r.OrgID, r.MatchExpr, r.TargetModel, r.Priority, r.Enabled})
	}
	return rows
}

func rt06BenchGetByOrg(b *testing.B, n int) {
	b.Helper()
	org := fmt.Sprintf("bench-org-%d", n)
	db := &rt06BenchDB{rules: rt06BenchRowsFor(rt06BenchRules(n, org))}
	store := New(db, newRT06BenchCache(), 5*time.Minute, nil, slog.New(slog.DiscardHandler))
	ctx := context.Background()

	base := db.queries.Load()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.GetByOrg(ctx, org); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(db.queries.Load()-base)/float64(b.N), "dbq/op")
}

func BenchmarkRT06_GetByOrg_EmptyRules_Warm(b *testing.B) { rt06BenchGetByOrg(b, 0) }
func BenchmarkRT06_GetByOrg_10Rules_Warm(b *testing.B)    { rt06BenchGetByOrg(b, 10) }
