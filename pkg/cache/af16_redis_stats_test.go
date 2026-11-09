package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-16: Stats must never issue the blocking KEYS command. The count comes
// from an incremental bounded SCAN, ignores foreign namespaces, and reports
// a partial (lower-bound) count with ErrStatsIncomplete when its budget is
// exhausted.
func TestAF16_Stats_BoundedScanCountsOnlyCachePrefix(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Minute)
	ctx := context.Background()

	// 1200 cache keys + foreign-namespace noise.
	pipe := rdb.Pipeline()
	for i := 0; i < 1200; i++ {
		pipe.Set(ctx, MakeKey("org-af16", "smart", fmt.Sprintf("h%04d", i)), []byte(`{}`), time.Minute)
	}
	for i := 0; i < 10; i++ {
		pipe.Set(ctx, fmt.Sprintf("other:%d", i), []byte(`{}`), time.Minute)
	}
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)

	count, err := store.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1200), count, "exact count in a stable keyspace, foreign keys excluded")
}

func TestAF16_Stats_PartialCountOnBudgetExhaustion(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Minute)
	store.statsBatch = 10
	store.statsMaxBatches = 3
	store.statsMaxDuration = time.Minute
	ctx := context.Background()

	pipe := rdb.Pipeline()
	for i := 0; i < 1000; i++ {
		pipe.Set(ctx, MakeKey("org-af16", "smart", fmt.Sprintf("h%04d", i)), []byte(`{}`), time.Minute)
	}
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)

	count, err := store.Stats(ctx)
	require.ErrorIs(t, err, ErrStatsIncomplete, "budget exhaustion must be reported as ErrStatsIncomplete")
	assert.Positive(t, count)
	// SCAN COUNT is a hint (a batch may cover whole hash buckets), so the
	// exact ceiling is fuzzy; the load-bearing property is that the count is
	// strictly partial and the budget is reported.
	assert.Less(t, count, int64(500), "partial count must not claim the full 1000-key keyspace")
}

func TestAF16_Stats_NoKeysCommandInSlowlog(t *testing.T) {
	rdb := redisContainer(t)
	store := NewRedisStore(rdb, 5*time.Minute)
	ctx := context.Background()

	pipe := rdb.Pipeline()
	for i := 0; i < 20000; i++ {
		pipe.Set(ctx, MakeKey("org-af16", "smart", fmt.Sprintf("h%05d", i)), []byte(`{}`), time.Minute)
	}
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)

	setSlowlog := func(us int) {
		require.NoError(t, rdb.Do(ctx, "CONFIG", "SET", "slowlog-log-slower-than", us).Err())
	}
	t.Cleanup(func() {
		_ = rdb.Do(context.Background(), "CONFIG", "SET", "slowlog-log-slower-than", 10000).Err()
		_ = rdb.Do(context.Background(), "SLOWLOG", "RESET").Err()
	})

	// Contrast evidence first (the audited defect) at a 1ms threshold: one
	// direct KEYS call IS logged as a slow, whole-keyspace blocking command
	// on this data volume — this also proves the slowlog mechanism collects.
	setSlowlog(1000)
	require.NoError(t, rdb.Do(ctx, "SLOWLOG", "RESET").Err())
	_, err = rdb.Keys(ctx, "cache:*").Result()
	require.NoError(t, err)
	keysLogged := slowlogCommands(t, ctx, rdb)
	assert.Contains(t, keysLogged, "keys",
		"KEYS over 20k keys exceeds 1ms — this is the blocking operation Stats no longer performs")

	// The fixed Stats path: no KEYS, and no single SCAN batch may reach the
	// 10ms "large blocking operation" threshold. (A 500-key SCAN batch is
	// sub-millisecond on quiet hardware — see artifacts/agent-lanes/af16/
	// longrun.log for the 1ms-level evidence at 10k/100k/1M keys; the 10ms
	// bound here stays robust under full-suite machine load, where one
	// batch may legitimately wait on a contended event loop.)
	setSlowlog(10000)
	require.NoError(t, rdb.Do(ctx, "SLOWLOG", "RESET").Err())
	start := time.Now()
	count, err := store.Stats(ctx)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, int64(20000), count)
	assert.Empty(t, slowlogCommands(t, ctx, rdb),
		"Stats must issue neither KEYS nor any SCAN batch exceeding the 10ms large-blocking-op threshold")

	t.Logf("AF16 stats scan of 20000 keys took %s (batched, non-blocking; slowlog clean)", elapsed)
}

func slowlogCommands(t *testing.T, ctx context.Context, rdb *redis.Client) []string {
	t.Helper()
	res, err := rdb.Do(ctx, "SLOWLOG", "GET", "128").Result()
	require.NoError(t, err)
	entries, ok := res.([]interface{})
	require.True(t, ok, "unexpected SLOWLOG GET shape: %T", res)
	var cmds []string
	for _, e := range entries {
		entry, ok := e.([]interface{})
		if !ok || len(entry) < 3 {
			continue
		}
		cmd, ok := entry[3].([]interface{})
		if !ok || len(cmd) == 0 {
			continue
		}
		if name, ok := cmd[0].(string); ok {
			cmds = append(cmds, name)
		}
	}
	return cmds
}
