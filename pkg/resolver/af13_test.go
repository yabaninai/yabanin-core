package resolver

// AF-13 regressions (docs/plans/AUDIT_FIX_PLAN_2026-10-02.md#af-13):
// bounded model cache and miss dedup without losing cancel/errors.
//
// Contract under test, on top of RT-06/AF-03 (outage ≠ not-found ≠ cancel):
//   - concurrent cold misses of one model key share a single DB load
//     (DB call count ≈ 1 per flight);
//   - every waiter waits within its OWN context: a cancelled/deadline
//     waiter gets its context error and neither aborts the shared load for
//     the others nor corrupts their results;
//   - DB errors are shared as ErrModelUnavailable by the whole flight and
//     are never cached in either direction;
//   - Invalidate/InvalidateAll bump a generation: a load that started
//     before the invalidation publishes nothing — not to the cache, not to
//     fresh waiters;
//   - the cache is bounded (LRU) and negative entries (genuine not-found
//     substitutions) expire at a shorter horizon, so arbitrary unknown
//     names cannot grow the map without bound.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// af13GatePool parks every query on release (a stalled registry DB) while
// counting attempts, then answers from the wrapped pool. Every attempt also
// signals reached, so tests synchronize on the event instead of polling.
type af13GatePool struct {
	inner   *mockPool
	release chan struct{}
	queries atomic.Int64
	reached chan struct{}
}

func (p *af13GatePool) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	p.queries.Add(1)
	select {
	case p.reached <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
	case <-ctx.Done():
		return mockRow{scanFn: func(...any) error { return ctx.Err() }}
	}
	return p.inner.QueryRow(ctx, q, args...)
}

func (p *af13GatePool) Close() {}

// af13GatedMutablePool parks queries on release but CAPTURES the row value
// before parking, so a test can prove that a load which started before an
// invalidation settles with pre-invalidation data. The captured channel
// signals that the capture (and the park) was reached.
type af13GatedMutablePool struct {
	mu       sync.Mutex
	rows     map[string][]any
	release  chan struct{}
	queries  atomic.Int64
	captured chan struct{}
}

func (p *af13GatedMutablePool) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	p.queries.Add(1)
	p.mu.Lock()
	vals, ok := p.rows[args[0].(string)]
	p.mu.Unlock()
	var found mockRow
	if ok {
		v := vals
		found = mockRow{scanFn: func(dest ...any) error { return fillDest(dest, v...) }}
	} else {
		found = mockRow{} // pgx.ErrNoRows
	}
	select {
	case p.captured <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
	case <-ctx.Done():
		return mockRow{scanFn: func(...any) error { return ctx.Err() }}
	}
	return found
}

func (p *af13GatedMutablePool) set(name string, row []any) {
	p.mu.Lock()
	p.rows[name] = row
	p.mu.Unlock()
}

func (p *af13GatedMutablePool) Close() {}

func af13Row(name string) []any {
	return []any{name, name + " display", "standard", "https://" + name, "", "openai", nil, true, int64(0), "EU"}
}

// af13WaitForQuery waits (bounded) for the flight's first DB attempt: the
// gate pool signals every query, so no polling or fixed sleeps are needed.
func af13WaitForQuery(t *testing.T, reached <-chan struct{}) {
	t.Helper()
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("the flight must have reached the DB")
	}
}

func TestAF13_ConcurrentColdMiss_SingleSharedLoad(t *testing.T) {
	release := make(chan struct{})
	pool := &af13GatePool{
		inner:   &mockPool{rows: map[string][]any{"m": af13Row("m")}},
		release: release,
		reached: make(chan struct{}, 1),
	}
	r := NewResolver(pool, "fb", time.Minute, nil)

	const callers = 48
	var wg sync.WaitGroup
	results := make(chan ModelInfo, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := r.ResolveChecked(context.Background(), "m")
			if err != nil {
				t.Errorf("resolve failed: %v", err)
				return
			}
			results <- info
		}()
	}

	// The flight leader is parked at the (gated) DB layer: the flight is
	// shared. Release it; wg.Wait is the sync point that proves the count —
	// every caller has settled, so a broken dedup could not hide an extra
	// query behind scheduling delays.
	af13WaitForQuery(t, pool.reached)
	close(release)
	wg.Wait()
	close(results)
	for info := range results {
		assert.Equal(t, "m", info.ModelName)
		assert.False(t, info.Fallback)
	}
	assert.Equal(t, int64(1), pool.queries.Load(),
		"concurrent cold misses of one key must share a single DB load, "+
			"and nothing after the shared flight may re-query a warm entry")
}

func TestAF13_CancelledWaiterDoesNotBreakSharedLoad(t *testing.T) {
	release := make(chan struct{})
	pool := &af13GatePool{
		inner:   &mockPool{rows: map[string][]any{"m": af13Row("m")}},
		release: release,
		reached: make(chan struct{}, 1),
	}
	r := NewResolver(pool, "fb", time.Minute, nil)

	done := make(chan ModelInfo, 1)
	go func() {
		info, err := r.ResolveChecked(context.Background(), "m")
		if err != nil {
			t.Errorf("resolve failed: %v", err)
			return
		}
		done <- info
	}()
	af13WaitForQuery(t, pool.reached)

	// A cancelled waiter gets its own context error and leaves the shared
	// load (and the other waiters) untouched. The waiter signals its start,
	// so cancel() lands while the waiter is inside ResolveChecked; the
	// outcome is identical for every interleaving, because waiting is
	// bounded by the waiter's OWN context.
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan error, 1)
	entered := make(chan struct{})
	go func() {
		close(entered)
		_, err := r.ResolveChecked(ctx, "m")
		cancelled <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the second waiter never started")
	}
	cancel()
	select {
	case err := <-cancelled:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter was not bounded by its own context")
	}

	close(release)
	select {
	case info := <-done:
		assert.Equal(t, "m", info.ModelName)
	case <-time.After(2 * time.Second):
		t.Fatal("the shared load must complete for the remaining waiter")
	}
	assert.Equal(t, int64(1), pool.queries.Load(),
		"the cancelled waiter must not have triggered a second load")
}

func TestAF13_DeadlineWaiterGetsOwnErrorOthersSucceed(t *testing.T) {
	release := make(chan struct{})
	pool := &af13GatePool{
		inner:   &mockPool{rows: map[string][]any{"m": af13Row("m")}},
		release: release,
		reached: make(chan struct{}, 1),
	}
	r := NewResolver(pool, "fb", time.Minute, nil)

	var wg sync.WaitGroup
	done := make(chan ModelInfo, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		info, err := r.ResolveChecked(context.Background(), "m")
		if err != nil {
			t.Errorf("resolve failed: %v", err)
			return
		}
		done <- info
	}()
	af13WaitForQuery(t, pool.reached)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.ResolveChecked(ctx, "m")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second, "a deadline waiter must not wait for the stalled load")

	close(release)
	wg.Wait()
	info := <-done
	assert.Equal(t, "m", info.ModelName)
}

// af13OutagePool parks queries on release and fails (or, after recovery,
// reports not-found) once released. Every attempt signals reached.
type af13OutagePool struct {
	release chan struct{}
	fail    atomic.Bool
	queries atomic.Int64
	reached chan struct{}
}

func (p *af13OutagePool) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	p.queries.Add(1)
	select {
	case p.reached <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
	case <-ctx.Done():
		return mockRow{scanFn: func(...any) error { return ctx.Err() }}
	}
	if p.fail.Load() {
		return mockRow{scanFn: func(...any) error { return errors.New("db connection refused") }}
	}
	return mockRow{} // pgx.ErrNoRows → RM-09 path
}

func (p *af13OutagePool) Close() {}

func TestAF13_OutageSharedByFlightAndNeverCached(t *testing.T) {
	release := make(chan struct{})
	pool := &af13OutagePool{release: release, reached: make(chan struct{}, 1)}
	pool.fail.Store(true)
	r := NewResolver(pool, "fb", time.Minute, nil)

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.ResolveChecked(context.Background(), "m")
			errs <- err
		}()
	}
	// The flight leader is parked inside the single (failing) flight. From
	// the moment the leader parked, its flight is registered, so every other
	// caller joins it instead of querying: the query count is frozen until
	// the flight settles — no fixed wait is needed to judge it.
	af13WaitForQuery(t, pool.reached)
	assert.Equal(t, int64(1), pool.queries.Load(),
		"the whole flight shares one DB call even when it fails")

	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.ErrorIs(t, err, ErrModelUnavailable,
			"an outage must reach every waiter of the flight as unavailable")
	}

	// Recovery: nothing from the outage was cached in either direction.
	pool.fail.Store(false)
	info, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback)
}

func TestAF13_LoaderIsBoundedByItsTimeout(t *testing.T) {
	pool := &af13GatePool{
		inner:   &mockPool{rows: map[string][]any{"m": af13Row("m")}},
		release: make(chan struct{}),
	}
	t.Cleanup(func() { close(pool.release) }) // unblock anything left parked
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.loadTimeout = 50 * time.Millisecond

	start := time.Now()
	_, err := r.ResolveChecked(context.Background(), "m")
	require.Error(t, err, "a hung registry must surface as unavailable, not hang")
	require.ErrorIs(t, err, ErrModelUnavailable)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, int64(1), pool.queries.Load(), "the bounded flight must not retry per caller")
}

func TestAF13_InvalidateDuringFlightNeverPublishesStaleResult(t *testing.T) {
	release := make(chan struct{})
	pool := &af13GatedMutablePool{
		rows:     map[string][]any{"m": af13Row("m-v1")},
		release:  release,
		captured: make(chan struct{}, 1),
	}
	r := NewResolver(pool, "fb", time.Minute, nil)

	type outcome struct {
		info ModelInfo
		err  error
	}
	done := make(chan outcome, 2)
	go func() {
		info, err := r.ResolveChecked(context.Background(), "m")
		done <- outcome{info: info, err: err}
	}()
	// The flight captured the pre-invalidation row (v1) and is parked: the
	// invalidation below is now strictly ordered after the capture.
	select {
	case <-pool.captured:
	case <-time.After(2 * time.Second):
		t.Fatal("the flight must capture its row before parking")
	}

	// Invalidate while the pre-invalidation load (v1) is parked in flight,
	// then change the registry and release the load with its stale capture.
	r.Invalidate("m")
	pool.set("m", af13Row("m-v2"))
	// A caller arriving after the invalidation must never receive the
	// pre-invalidation row either.
	go func() {
		info, err := r.ResolveChecked(context.Background(), "m")
		done <- outcome{info: info, err: err}
	}()
	close(release)

	for i := 0; i < 2; i++ {
		select {
		case out := <-done:
			require.NoError(t, out.err)
			assert.Equal(t, "m-v2", out.info.ModelName,
				"no caller may be served the pre-invalidation row")
		case <-time.After(2 * time.Second):
			t.Fatal("waiters of the invalidated flight were not re-served")
		}
	}
	require.GreaterOrEqual(t, pool.queries.Load(), int64(2),
		"the discarded pre-invalidation load must be replaced by a fresh one")

	// The republished entry is the fresh row and stays cached.
	before := pool.queries.Load()
	info, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	assert.Equal(t, "m-v2", info.ModelName)
	assert.Equal(t, before, pool.queries.Load(), "the fresh row must be cached")
}

func TestAF13_InvalidateAllDropsEntriesAndInvalidatesFlights(t *testing.T) {
	pool := &af13MutableRowPool{rows: map[string][]any{
		"m": af13Row("m-v1"),
		"b": af13Row("b-v1"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	_, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	_, err = r.ResolveChecked(context.Background(), "b")
	require.NoError(t, err)

	r.InvalidateAll()

	pool.set("m", af13Row("m-v2"))
	info, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	assert.Equal(t, "m-v2", info.ModelName, "InvalidateAll must drop the cached row")
	info, err = r.ResolveChecked(context.Background(), "b")
	require.NoError(t, err)
	assert.Equal(t, "b-v1", info.ModelName, "b was re-queried, not served from a dropped entry")
	assert.Equal(t, int64(4), pool.queries.Load(), "2 initial + 2 post-invalidation queries")
}

// af13MutableRowPool answers from swappable rows without gating (used where
// no mid-flight race has to be controlled).
type af13MutableRowPool struct {
	mu      sync.Mutex
	rows    map[string][]any
	queries atomic.Int64
}

func (p *af13MutableRowPool) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	p.queries.Add(1)
	p.mu.Lock()
	vals, ok := p.rows[args[0].(string)]
	p.mu.Unlock()
	if !ok {
		return mockRow{}
	}
	v := vals
	return mockRow{scanFn: func(dest ...any) error { return fillDest(dest, v...) }}
}

func (p *af13MutableRowPool) set(name string, row []any) {
	p.mu.Lock()
	p.rows[name] = row
	p.mu.Unlock()
}

func (p *af13MutableRowPool) Close() {}

func TestAF13_NegativeEntriesExpireAtShorterHorizon(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"fb": af13Row("fb"),
		"m":  af13Row("m"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.negativeTTL = 20 * time.Millisecond

	// Negative (genuine not-found) is cached — briefly.
	info, err := r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.True(t, info.Fallback)
	_, err = r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	negQueries := pool.queries.Load() // ghost + fb rows
	assert.Equal(t, int64(2), negQueries, "the negative must be cached within its horizon")

	// A positive entry loaded at the same moment is NOT expired by the
	// short negative horizon.
	_, err = r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	base := pool.queries.Load() // ghost + fb + m

	time.Sleep(40 * time.Millisecond)

	_, err = r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.Equal(t, base+1, pool.queries.Load(),
		"the negative entry must expire at the shorter horizon and re-query")
	_, err = r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	assert.Equal(t, base+1, pool.queries.Load(),
		"the positive entry must keep the full TTL")
}

func TestAF13_CacheIsBoundedLRU(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{"fb": af13Row("fb")}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.maxEntries = 3

	for i := 0; i < 10; i++ {
		_, err := r.ResolveChecked(context.Background(), fmt.Sprintf("unknown-%d", i))
		require.NoError(t, err)
	}
	r.mu.Lock()
	stored := len(r.cache)
	r.mu.Unlock()
	assert.LessOrEqual(t, stored, 3,
		"arbitrary unknown names must not grow the cache beyond the cap")

	for i := 10; i < 20; i++ {
		_, err := r.ResolveChecked(context.Background(), fmt.Sprintf("unknown-%d", i))
		require.NoError(t, err)
	}
	r.mu.Lock()
	stored = len(r.cache)
	r.mu.Unlock()
	assert.LessOrEqual(t, stored, 3, "the bound must hold under churn")

	_, err := r.ResolveChecked(context.Background(), "fb")
	require.NoError(t, err)
}

// af13SelectiveGatePool parks only the named key's queries; other keys flow
// straight through.
type af13SelectiveGatePool struct {
	gated   *af13GatePool
	park    string
	through *mockPool
}

func (p *af13SelectiveGatePool) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if name, _ := args[0].(string); name == p.park {
		return p.gated.QueryRow(ctx, q, args...)
	}
	return p.through.QueryRow(ctx, q, args...)
}

func (p *af13SelectiveGatePool) Close() {}

func TestAF13_DifferentKeyIsNeverBlockedByAStalledFlight(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	pool := &af13SelectiveGatePool{
		gated: &af13GatePool{
			inner:   &mockPool{rows: map[string][]any{"a": af13Row("a")}},
			release: release,
			reached: make(chan struct{}, 1),
		},
		park: "a",
		through: &mockPool{rows: map[string][]any{
			"b": af13Row("b"),
		}},
	}
	r := NewResolver(pool, "fb", time.Minute, nil)

	go func() {
		_, _ = r.ResolveChecked(context.Background(), "a") // parks until cleanup
	}()
	af13WaitForQuery(t, pool.gated.reached)

	start := time.Now()
	info, err := r.ResolveChecked(context.Background(), "b")
	require.NoError(t, err)
	assert.Equal(t, "b", info.ModelName)
	assert.Less(t, time.Since(start), time.Second,
		"a stalled load of one key must not block a different key")
}

func TestAF13_FlightResultCarriesAuthoritativeShape(t *testing.T) {
	// The dedup layer must not change the published value: a genuine
	// not-found substitution stays a negative (Fallback=true), a registry
	// hit stays positive, and the cached negative must not leak alias
	// provenance into a fresh resolve.
	pool := &mockPool{rows: map[string][]any{
		"hit": af13Row("hit"),
		"fb":  af13Row("fb"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.UseAliases(NewAliasBook(time.Hour, func(context.Context) (map[string]string, error) {
		return map[string]string{"alias-hit": "hit"}, nil
	}, nil))
	// Warm the alias book first: this test targets the resolver's miss-dedup
	// shape, not the alias book's cold-load rounds. A cold instant-load book
	// can (rarely, under heavy scheduling contention) legitimately report a
	// bounded unavailable to a late cold caller that burns its wait rounds
	// inside the winner's announce window — AF-03 contract-safe, but noise
	// here.
	if _, err := r.ResolveChecked(context.Background(), "alias-hit"); err != nil {
		t.Fatalf("warm alias lookup failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := r.ResolveChecked(context.Background(), "alias-hit")
			if err != nil {
				t.Errorf("resolve failed: %v", err)
				return
			}
			assert.Equal(t, "hit", info.ModelName)
			assert.Equal(t, "alias-hit", info.Alias)
			assert.False(t, info.Fallback)
		}()
	}
	wg.Wait()

	info, err := r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.True(t, info.Fallback)
	assert.Empty(t, info.Alias, "the cached negative must not leak alias provenance")
}
