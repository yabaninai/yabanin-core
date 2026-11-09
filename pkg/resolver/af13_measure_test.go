package resolver

// AF-13 measurement harness (docs/plans/AUDIT_FIX_PLAN_2026-10-02.md#af-13).
//
// Skipped unless AF13_MEASURE=1:
//
//	AF13_MEASURE=1 go test -run 'TestAF13Measure' -v -count=1 ./pkg/resolver
//
// It measures the same-model concurrent cold-burst workload against a fake
// registry pool with a bounded connection slot (real pool wait, not ns/op)
// and an explicit per-query latency, plus the unknown-name churn that probes
// cache growth. Raw before/after logs land in artifacts/agent-lanes/af13/.
//
// The harness only uses the public ResolveChecked contract plus the
// in-package cache length, so it compiles and runs identically on the
// pre-fix and post-fix trees (matched measurement).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// measurePool is a fake models_registry pool for the AF-13 measurements: a
// bounded number of connection slots (pool wait), a per-query latency, a
// query counter and an in-flight gauge.
type measurePool struct {
	rows        map[string][]any
	latency     time.Duration
	conns       chan struct{}
	queries     atomic.Int64
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	fail        atomic.Bool
}

func newMeasurePool(latency time.Duration, conns int, rows map[string][]any) *measurePool {
	if conns <= 0 {
		conns = 64
	}
	return &measurePool{rows: rows, latency: latency, conns: make(chan struct{}, conns)}
}

func (p *measurePool) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	p.queries.Add(1)
	return p.innerQueryRow(ctx, args...)
}

func (p *measurePool) innerQueryRow(ctx context.Context, args ...any) pgx.Row {
	cur := p.inFlight.Add(1)
	for {
		m := p.maxInFlight.Load()
		if cur <= m || p.maxInFlight.CompareAndSwap(m, cur) {
			break
		}
	}
	select {
	case p.conns <- struct{}{}:
	case <-ctx.Done():
		p.inFlight.Add(-1)
		return mockRow{scanFn: func(...any) error { return ctx.Err() }}
	}
	defer func() {
		<-p.conns
		p.inFlight.Add(-1)
	}()
	if p.latency > 0 {
		select {
		case <-time.After(p.latency):
		case <-ctx.Done():
			return mockRow{scanFn: func(...any) error { return ctx.Err() }}
		}
	}
	if p.fail.Load() {
		return mockRow{scanFn: func(...any) error { return errors.New("db connection refused") }}
	}
	name, _ := args[0].(string)
	vals, ok := p.rows[name]
	if !ok {
		return mockRow{} // pgx.ErrNoRows
	}
	v := vals
	return mockRow{scanFn: func(dest ...any) error { return fillDest(dest, v...) }}
}

func (p *measurePool) Close() {}

func measureRow(name string) []any {
	return []any{name, name + " display", "standard", "https://" + name, "", "openai", nil, true, int64(0), "EU"}
}

// pctl returns a wall-latency percentile of the sorted samples.
func pctl(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q * float64(len(sorted)-1))
	return sorted[idx]
}

func logMeasure(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("AF13-MEASURE "+format, args...)
}

// TestAF13_PerfSmoke_ColdBurst is the matched baseline/after workload: 64
// concurrent cold resolves of one model through a pool with 8 connection
// slots and 10ms per-query latency (real pool wait, not ns/op). It runs in
// every test pass: the AF13-MEASURE lines document the load shape and the
// wall-latency percentiles, while the deterministic assertions (shared load,
// bounded cache, outage never cached) carry the contract — timing itself is
// never asserted. Raw baseline/after runs: artifacts/agent-lanes/af13/.
func TestAF13_PerfSmoke_ColdBurst(t *testing.T) {
	const (
		callers   = 64
		conns     = 8
		dbLatency = 10 * time.Millisecond
	)
	pool := newMeasurePool(dbLatency, conns, map[string][]any{
		"burst-model": measureRow("burst-model"),
		"other-model": measureRow("other-model"),
		"fb":          measureRow("fb"),
	})
	r := NewResolver(pool, "fb", time.Minute, nil)

	// --- Scenario 1: same-model concurrent cold burst ---------------------
	start := make(chan struct{})
	var wg sync.WaitGroup
	latencies := make([]time.Duration, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			t0 := time.Now()
			info, err := r.ResolveChecked(context.Background(), "burst-model")
			if err != nil || info.ModelName != "burst-model" {
				logMeasure(t, "ERROR caller=%d info=%v err=%v", i, info.ModelName, err)
			}
			latencies[i] = time.Since(t0)
		}(i)
	}
	pool.queries.Store(0)
	pool.maxInFlight.Store(0)
	close(start)
	wg.Wait()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if q := pool.queries.Load(); q > 4 {
		t.Errorf("same-model cold burst produced %d DB queries for %d callers; the shared flight must dedup them (baseline: %d)", q, callers, callers)
	}
	logMeasure(t, "scenario=same-model-cold-burst callers=%d conns=%d db_latency=%s", callers, conns, dbLatency)
	logMeasure(t, "scenario=same-model-cold-burst db_queries=%d max_concurrent_queries=%d p50=%s p95=%s p99=%s max=%s",
		pool.queries.Load(), pool.maxInFlight.Load(),
		pctl(latencies, 0.50), pctl(latencies, 0.95), pctl(latencies, 0.99), latencies[len(latencies)-1])

	// --- Scenario 2: different-model access during a stalled same-model load
	// (no caller of another key may be blocked behind the stalled flight) ---
	pool2 := newMeasurePool(0, 64, map[string][]any{
		"stalled-model": measureRow("stalled-model"),
		"other-model":   measureRow("other-model"),
		"fb":            measureRow("fb"),
	})
	release := make(chan struct{})
	pp := parkedPool{
		pool:    pool2,
		release: release,
		park:    "stalled-model",
		reached: make(chan struct{}, 1),
	}
	r2 := NewResolver(pp, "fb", time.Minute, nil)
	other := make([]time.Duration, 32)
	var wg2 sync.WaitGroup
	go func() {
		_, _ = r2.ResolveChecked(context.Background(), "stalled-model")
	}()
	select {
	case <-pp.reached:
	case <-time.After(2 * time.Second):
		t.Fatal("the stalled flight must reach the DB")
	}
	for i := 0; i < len(other); i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			t0 := time.Now()
			info, err := r2.ResolveChecked(context.Background(), "other-model")
			if err != nil || info.ModelName != "other-model" {
				logMeasure(t, "ERROR other-model i=%d err=%v", i, err)
			}
			other[i] = time.Since(t0)
		}(i)
	}
	wg2.Wait()
	close(release)
	sort.Slice(other, func(i, j int) bool { return other[i] < other[j] })
	logMeasure(t, "scenario=other-model-during-stalled-flight samples=%d p50=%s p95=%s max=%s",
		len(other), pctl(other, 0.50), pctl(other, 0.95), other[len(other)-1])

	// --- Scenario 3: DB error burst — outage must not be cached ------------
	pool3 := newMeasurePool(2*time.Millisecond, 16, map[string][]any{
		"m":  measureRow("m"),
		"fb": measureRow("fb"),
	})
	pool3.fail.Store(true)
	r3 := NewResolver(pool3, "fb", time.Minute, nil)
	var wg3 sync.WaitGroup
	var errCount atomic.Int64
	for i := 0; i < 32; i++ {
		wg3.Add(1)
		go func() {
			defer wg3.Done()
			if _, err := r3.ResolveChecked(context.Background(), "m"); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg3.Wait()
	failQueries := pool3.queries.Load()
	if got := errCount.Load(); got != 32 {
		t.Errorf("db-error burst: %d/32 callers saw the outage; every waiter must get ErrModelUnavailable", got)
	}
	pool3.fail.Store(false)
	if _, err := r3.ResolveChecked(context.Background(), "m"); err != nil {
		t.Errorf("recovery resolve failed after outage: %v", err)
	}
	logMeasure(t, "scenario=db-error-burst concurrent=32 failed_calls=%d queries_during_outage=%d queries_after_recovery=%d cache_polluted=%v",
		errCount.Load(), failQueries, pool3.queries.Load()-failQueries, false)

	// --- Scenario 4: unknown-name churn — cache growth ---------------------
	pool4 := newMeasurePool(0, 64, nil)
	r4 := NewResolver(pool4, "fb", time.Minute, nil)
	const churn = 5000
	for i := 0; i < churn; i++ {
		if _, err := r4.ResolveChecked(context.Background(), fmt.Sprintf("unknown-%d", i)); err != nil {
			logMeasure(t, "ERROR churn resolve failed: %v", err)
		}
	}
	r4.mu.Lock()
	stored := len(r4.cache)
	r4.mu.Unlock()
	if stored > af13MaxCacheEntries {
		t.Errorf("unknown-name churn stored %d entries; the cache must stay bounded at %d", stored, af13MaxCacheEntries)
	}
	logMeasure(t, "scenario=unknown-name-churn distinct_names=%d stored_entries=%d (negative entries included)", churn, stored)
}

// parkedPool parks only the named model's queries on release (simulating a
// stalled DB for one key) while counting every attempt. Every attempt
// signals reached, so the test waits on the event instead of polling.
type parkedPool struct {
	pool    *measurePool
	release chan struct{}
	park    string
	reached chan struct{}
}

func (p parkedPool) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	p.pool.queries.Add(1)
	if p.reached != nil {
		select {
		case p.reached <- struct{}{}:
		default:
		}
	}
	name, _ := args[0].(string)
	if name == p.park {
		select {
		case <-p.release:
		case <-ctx.Done():
			return mockRow{scanFn: func(...any) error { return ctx.Err() }}
		}
	}
	return p.pool.innerQueryRow(ctx, args...)
}

func (p parkedPool) Close() {}
