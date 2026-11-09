package cache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-16 long-run evidence (not part of the regular suite):
//
//	AF16_LONGRUN=1 go test -v -count=1 -run 'TestAF16Longrun' ./pkg/cache
//
// Phase A — org/model churn over the in-memory analytics and the policy
// cache: heap/RSS before/after, live cache sizes vs caps, and the
// cache_hits_total series cardinality (must stay fixed at the type enum,
// with no per-org labels).
// Phase B — Redis keyspace scaling (10k/100k/1M keys): Stats latency
// percentiles, slowlog cleanliness (no blocking command), and the KEYS
// contrast measurement demonstrating the audited blocking behavior.
func TestAF16Longrun_OrgModelChurnAndRedisKeyScaling(t *testing.T) {
	if os.Getenv("AF16_LONGRUN") == "" {
		t.Skip("long-run evidence test; set AF16_LONGRUN=1 to run (needs Docker)")
	}

	t.Logf("AF16 phase A: in-memory churn")
	measureChurn(t)

	t.Logf("AF16 phase B: redis keyspace scaling")
	rdb := redisContainer(t)
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		measureRedisScale(t, context.Background(), rdb, n)
	}
}

func measureChurn(t *testing.T) {
	t.Helper()

	const orgs = 50_000
	policy := NewPolicyCache(time.Minute)
	loader := func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	rssBefore := rssKB(t)

	for i := 0; i < orgs; i++ {
		org := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		model := fmt.Sprintf("model-%d", i%7)
		switch i % 3 {
		case 0:
			RecordGlobalHit(org, model, "exact", i%100)
			RecordHit("exact")
		case 1:
			RecordGlobalMiss(org, model)
			RecordMiss()
		default:
			RecordGlobalHit(org, model, "semantic", i%100)
			RecordHit("semantic")
		}
		policy.Get(context.Background(), org, loader)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// The production path records into the global singleton.
	globalAnalytics.mu.RLock()
	liveOrgs, tiers, misses := len(globalAnalytics.orgStats), len(globalAnalytics.tierStats), len(globalAnalytics.misses)
	globalAnalytics.mu.RUnlock()
	policy.mu.Lock()
	policies, generations := len(policy.policies), len(policy.generations)
	policy.mu.Unlock()

	t.Logf("AF16 churn: orgs=%d heap_before=%dKiB heap_after=%dKiB heap_delta=%dKiB rss_before=%s rss_after=%s",
		orgs, before.HeapAlloc/1024, after.HeapAlloc/1024,
		(after.HeapAlloc-before.HeapAlloc)/1024, rssBefore, rssKB(t))
	t.Logf("AF16 churn sizes: analytics orgs=%d (cap %d) tiers=%d (cap %d) misses=%d; policy entries=%d generations=%d (cap %d)",
		liveOrgs, defaultMaxOrgEntries, tiers, defaultMaxTierEntries, misses,
		policies, generations, maxPolicyCacheEntries)

	card := metricCardinality(t, "cache_hits_total")
	t.Logf("AF16 metric cardinality: cache_hits_total children=%d (type enum: exact|semantic|miss)", card)

	assert.LessOrEqual(t, liveOrgs, defaultMaxOrgEntries, "analytics org map stays at cap under churn")
	assert.LessOrEqual(t, tiers, defaultMaxTierEntries)
	assert.LessOrEqual(t, misses, defaultMaxTierEntries)
	assert.LessOrEqual(t, policies, maxPolicyCacheEntries, "policy cache stays at cap under churn")
	assert.LessOrEqual(t, generations, maxPolicyCacheEntries)
	assert.GreaterOrEqual(t, card, 3, "hit/miss types are all present")
	assert.LessOrEqual(t, card, 3, "no per-org labels: cardinality is fixed at the 3-value type enum")
}

func measureRedisScale(t *testing.T, ctx context.Context, rdb *redis.Client, n int) {
	t.Helper()

	pipe := rdb.Pipeline()
	filled := 0
	for i := 0; i < n; i++ {
		pipe.Set(ctx, MakeKey("org-longrun", "smart", fmt.Sprintf("%064x", i)), []byte(strings.Repeat("x", 64)), 24*time.Hour)
		filled++
		if filled%1000 == 0 {
			_, err := pipe.Exec(ctx)
			require.NoError(t, err)
		}
	}
	if _, err := pipe.Exec(ctx); err != nil {
		require.NoError(t, err)
	}

	// Warm-up + latency sample of the bounded-scan Stats.
	const samples = 30
	require.NoError(t, rdb.Do(ctx, "SLOWLOG", "RESET").Err())
	var durs []time.Duration
	var count int64
	for i := 0; i <= samples; i++ {
		start := time.Now()
		c, err := NewRedisStore(rdb, time.Hour).Stats(ctx)
		durs = append(durs, time.Since(start))
		require.NoError(t, err)
		if i == 0 {
			count = c // warm-up result; exact in a quiescent keyspace
		}
	}
	durs = durs[1:] // drop warm-up
	p50, p95, max := percentiles(durs)
	t.Logf("AF16 redis scale n=%d: stats_count=%d p50=%s p95=%s max=%s over %d samples", n, count, p50, p95, max, samples)

	// No blocking command from the Stats path may reach the slowlog (1ms).
	slow := slowlogCommands(t, ctx, rdb)
	assert.Empty(t, slow, "n=%d: no Stats command (KEYS, SCAN batch) may exceed the 1ms slowlog threshold", n)

	// Contrast evidence: one direct KEYS call, the audited defect.
	start := time.Now()
	keys, err := rdb.Keys(ctx, "cache:*").Result()
	keysDur := time.Since(start)
	require.NoError(t, err)
	t.Logf("AF16 redis scale n=%d: KEYS contrast: %d keys in %s (blocking, whole keyspace in one command)", n, len(keys), keysDur)
	keysSlow := slowlogCommands(t, ctx, rdb)
	slowKeys := false
	for _, cmd := range keysSlow {
		if cmd == "keys" {
			slowKeys = true
		}
	}
	t.Logf("AF16 redis scale n=%d: KEYS reached the 1ms slowlog: %v", n, slowKeys)
	require.NoError(t, rdb.Do(ctx, "SLOWLOG", "RESET").Err())
}

func metricCardinality(t *testing.T, family string) int {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == family {
			return len(mf.Metric)
		}
	}
	return 0
}

// rssKB reports the current process RSS in KiB (/proc on Linux, ps elsewhere).
func rssKB(t *testing.T) string {
	t.Helper()
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return fmt.Sprintf("%dKiB", pages*4096/1024)
			}
		}
	}
	//nolint:gosec // the pid argument is the current test process itself, not external input
	out, err := exec.CommandContext(context.Background(), "ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out)) + "KiB"
}

func percentiles(durs []time.Duration) (p50, p95, max time.Duration) {
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	pick := func(q float64) time.Duration {
		if len(durs) == 0 {
			return 0
		}
		return durs[int(q*float64(len(durs)-1))]
	}
	return pick(0.50), pick(0.95), durs[len(durs)-1]
}
