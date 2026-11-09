package resolver

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RT-06 alias-book refresh contract, with the initial-load policy revised by
// AF-03.
//
// Warm reads never block on DB I/O: a slow or stalled reload cannot stall a
// warm lookup (and never a *different* request's lookup). Refreshes are
// bounded, single-flight per TTL window via TryLock (NOT a
// cancellation-ignoring global singleflight: each caller keeps its own
// context and stale reads), and a failed/timed-out refresh keeps the last
// snapshot and backs off one TTL.
//
// AF-03 revision: while the book is COLD, lookups share the in-flight
// initial load and wait for it — each bounded by its own context, the load
// itself detached from any single caller (a cancelled caller gets an
// explicit unavailable instead of aborting the load or fabricating an
// authoritative miss).

// signalLoad records one alias load attempt without ever blocking the loader
// (detached loads must never stall on a test channel).
func signalLoad(calls chan<- struct{}) {
	select {
	case calls <- struct{}{}:
	default:
	}
}

// awaitLoadCalls waits (bounded) for the next n load-attempt signals: alias
// loads run detached from their triggering caller, so tests synchronize on
// the load closure's events instead of polling counters or sleeping fixed
// amounts.
func awaitLoadCalls(t *testing.T, calls <-chan struct{}, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-calls:
		case <-time.After(30 * time.Second): // detached refresh: 10s still starves under full-suite parallel load (W-0B-hotfix #2)
			t.Fatalf("alias load attempt %d of %d never ran", i+1, n)
		}
	}
}

// fakeClock is a race-safe injectable AliasBook clock: loads run detached,
// so the injected now func is read from other goroutines and the underlying
// value must be atomic.
type fakeClock struct {
	ns atomic.Int64
}

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}

func (c *fakeClock) now() time.Time { return time.Unix(0, c.ns.Load()) }

func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func TestAF03_AliasBook_ColdCallersShareFirstLoadBoundedByOwnContext(t *testing.T) {
	release := make(chan struct{})
	var (
		loads     atomic.Int64
		loadCalls = make(chan struct{}, 8)
	)
	book := NewAliasBook(time.Hour, func(ctx context.Context) (map[string]string, error) {
		loads.Add(1)
		signalLoad(loadCalls)
		<-release
		return map[string]string{"a": "target-a"}, ctx.Err()
	}, slog.New(slog.DiscardHandler))

	// Trigger the first (parked) load.
	go func() { _, _ = book.Lookup(context.Background(), "a") }()
	awaitLoadCalls(t, loadCalls, 1)

	// A concurrent cold caller waits for the shared load (AF-03) instead of
	// returning an authoritative-looking miss: while the load is parked it
	// must not complete.
	type lookupResult struct {
		target string
		err    error
	}
	done := make(chan lookupResult, 1)
	go func() {
		target, err := book.Lookup(context.Background(), "a")
		done <- lookupResult{target: target, err: err}
	}()
	select {
	case res := <-done:
		t.Fatalf("cold caller completed while the shared load was parked: (%q, %v)", res.target, res.err)
	case <-time.After(100 * time.Millisecond):
	}

	// A cold caller whose context is already dead must not wait for the
	// shared load — bounded by its own context, never unblocking the load.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := book.Lookup(ctx, "a")
	require.ErrorIs(t, err, ErrAliasesUnavailable)
	assert.Less(t, time.Since(start), time.Second, "a dead caller must not wait for the shared load")

	close(release)
	select {
	case res := <-done:
		require.NoError(t, res.err, "the completed shared load must serve cold callers")
		assert.Equal(t, "target-a", res.target)
	case <-time.After(10 * time.Second): // detached refresh: 2s starves under full-suite parallel load
		t.Fatal("cold caller not served after the shared load completed")
	}

	// Warm lookups still never reload within the TTL.
	for i := 0; i < 50; i++ {
		target, err := book.Lookup(context.Background(), "a")
		require.NoError(t, err)
		assert.Equal(t, "target-a", target)
	}
	assert.EqualValues(t, 1, loads.Load(), "warm lookups within the TTL must not re-query")
}

func TestRT06_AliasBook_WarmHitsDoNotReload(t *testing.T) {
	var loads atomic.Int64
	book := NewAliasBook(time.Hour, func(context.Context) (map[string]string, error) {
		loads.Add(1)
		return map[string]string{"a": "target-a"}, nil
	}, slog.New(slog.DiscardHandler))
	book.now = func() time.Time { return time.Now() } // default clock

	_, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		target, err := book.Lookup(context.Background(), "a")
		require.NoError(t, err)
		assert.Equal(t, "target-a", target)
	}
	assert.EqualValues(t, 1, loads.Load(), "warm lookups within the TTL must not re-query")
}

func TestRT06_AliasBook_TTLExpiryTriggersSingleRefresh(t *testing.T) {
	var (
		clock     = newFakeClock()
		loads     atomic.Int64
		loadCalls = make(chan struct{}, 8)
	)
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		loads.Add(1)
		signalLoad(loadCalls)
		return map[string]string{"a": "target-a"}, nil
	}, slog.New(slog.DiscardHandler))
	book.now = clock.now

	_, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err)

	// Advance past the TTL and hammer the book concurrently: exactly one
	// refresh may run for this (single) TTL window.
	clock.advance(2 * time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = book.Lookup(context.Background(), "a")
		}()
	}
	wg.Wait()
	// The refresh runs detached; settle it before judging the attempt count.
	awaitLoadCalls(t, loadCalls, 2)
	assert.EqualValues(t, 2, loads.Load(), "TTL expiry must trigger exactly one bounded refresh")

	// Still warm afterwards.
	clock.advance(30 * time.Second)
	_, err = book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	assert.EqualValues(t, 2, loads.Load())
}

func TestRT06_AliasBook_RefreshFailureKeepsStaleAndBacksOff(t *testing.T) {
	var (
		clock     = newFakeClock()
		fail      atomic.Bool
		loads     atomic.Int64
		loadCalls = make(chan struct{}, 8)
	)
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		loads.Add(1)
		signalLoad(loadCalls)
		if fail.Load() {
			return nil, errors.New("db down")
		}
		return map[string]string{"a": "target-a"}, nil
	}, slog.New(slog.DiscardHandler))
	book.now = clock.now
	// Deterministic under full-suite load: run the load inline so this test
	// never depends on detached-goroutine scheduling (see runLoadSync).
	book.runLoadSync = true

	_, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	awaitLoadCalls(t, loadCalls, 1)

	// TTL expires while the DB is down: the stale snapshot keeps serving
	// (and stays authoritative — it is a real, previously loaded state).
	fail.Store(true)
	clock.advance(2 * time.Minute)
	target, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err, "a failed refresh must keep the last known aliases (stale-while-error)")
	assert.Equal(t, "target-a", target)
	// The refresh runs detached: let it settle before advancing the fake
	// clock, so its refreshed loadedAt is anchored to this window.
	awaitLoadCalls(t, loadCalls, 1)

	// Backoff: further lookups within the TTL do not retry the DB.
	clock.advance(30 * time.Second)
	_, _ = book.Lookup(context.Background(), "a")
	assert.EqualValues(t, 2, loads.Load(), "error policy must back off until the next TTL")

	// After the backoff AND recovery, the refresh succeeds again.
	fail.Store(false)
	clock.advance(2 * time.Minute)
	_, err = book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	awaitLoadCalls(t, loadCalls, 1)
	target, err = book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	assert.Equal(t, "target-a", target)
	assert.EqualValues(t, 3, loads.Load())
}

func TestAF03_AliasBook_CancelledCallerDoesNotAbortOrPoisonSharedLoad(t *testing.T) {
	var (
		clock     = newFakeClock()
		loads     atomic.Int64
		loadCalls = make(chan struct{}, 8)
	)
	book := NewAliasBook(time.Minute, func(ctx context.Context) (map[string]string, error) {
		loads.Add(1)
		signalLoad(loadCalls)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return map[string]string{"a": "target-a"}, nil
	}, slog.New(slog.DiscardHandler))
	book.now = clock.now

	// A cancelled request triggers the shared load but cannot abort it: the
	// load runs detached (its context is not the caller's), completes, and
	// the cancelled caller itself is never served.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := book.Lookup(ctx, "a")
	require.ErrorIs(t, err, ErrAliasesUnavailable, "a cancelled caller is never served")
	awaitLoadCalls(t, loadCalls, 1)

	// The snapshot the cancelled caller triggered is intact: a fresh caller
	// is served with no extra load, and the backoff/warm contract holds.
	target, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	assert.Equal(t, "target-a", target)
	_, _ = book.Lookup(context.Background(), "a")
	assert.EqualValues(t, 1, loads.Load(), "no per-request retry after the load settled")
}

func TestAF03_AliasBook_ColdOutageOneAttemptPerTTLWindow(t *testing.T) {
	var (
		clock = newFakeClock()
		loads atomic.Int64
	)
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		loads.Add(1)
		return nil, errors.New("db down")
	}, slog.New(slog.DiscardHandler))
	book.now = clock.now

	// Cold outage: lookups are explicitly unavailable, never an
	// authoritative "no aliases" (which the resolver would route into a
	// default-model fallback).
	for i := 0; i < 5; i++ {
		_, err := book.Lookup(context.Background(), "a")
		require.ErrorIs(t, err, ErrAliasesUnavailable)
	}
	assert.EqualValues(t, 1, loads.Load(),
		"a failing cold load must back off one TTL, not retry per lookup")

	// Recovery: the next TTL window retries and the book serves normally.
	clock.advance(2 * time.Minute)
	book.load = func(context.Context) (map[string]string, error) {
		loads.Add(1)
		return map[string]string{"a": "target-a"}, nil
	}
	target, err := book.Lookup(context.Background(), "a")
	require.NoError(t, err)
	assert.Equal(t, "target-a", target)
	assert.EqualValues(t, 2, loads.Load())
}

func TestRT06_AliasBook_ConcurrentCallersNoRaceNoDeadlock(t *testing.T) {
	var loads atomic.Int64
	book := NewAliasBook(time.Millisecond, func(context.Context) (map[string]string, error) {
		loads.Add(1)
		return map[string]string{"a": "target-a"}, nil
	}, slog.New(slog.DiscardHandler))

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				_, _ = book.Lookup(context.Background(), "a")
			}
		}()
	}
	wg.Wait()
	require.Positive(t, loads.Load(), "expired TTL must keep refreshing")
}
