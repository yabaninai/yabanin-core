package cache

// N03-P05-T07 boundary corpus (part 1): invalidation × cancellation
// classification boundaries on the Redis sweep path.
//
// T06 established the ctx-aware classification pattern (partition.go /
// service.go): go-redis surfaces a STORE-side dial/read timeout as a
// context.DeadlineExceeded-wrapped error while the caller's own context is
// still live. The sweep path must apply the same distinction:
//
//   - live caller + deadline-exceeded-wrapped SCAN death → the sweep is a
//     store failure: keys enumerated so far are still deleted, the error is
//     an *InvalidationError (ErrInvalidationIncomplete, ScanIncomplete) and
//     IsRetryable(ctx, err) is true — re-running the sweep can make progress;
//   - a caller that is really gone (ctx.Err() != nil) remains the
//     cancellation class: sweep stops immediately, never retryable.
//
// Before the fix, redisSweep classified ANY deadline-exceeded-shaped error
// as a caller cancellation and returned a plain "canceled" error — skipping
// the DEL of already-enumerated keys (the exact residue the FIX-04 contract
// forbids) and hiding a transient store timeout from retry decisions.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN03P5T07_SweepStoreTimeoutLiveCaller_IsIncompleteAndRetries pins the
// sweep boundary: a store-side timeout (DeadlineExceeded wrap, LIVE caller)
// must behave exactly like the mid-page transport death pinned by
// TestInvalidateOrgAll_ScanDiesMidPage — delete-what-was-enumerated, report
// ScanIncomplete — and must classify as retryable for a caller whose own
// deadline is still live.
func TestN03P5T07_SweepStoreTimeoutLiveCaller_IsIncompleteAndRetries(t *testing.T) {
	rdb := redisContainer(t)
	org := "org-t07-sweeptimeout"
	keys := seedKeys(t, rdb, org, "smart", 1200)

	// Same injection point as the mid-page death, but the injected error is
	// a DeadlineExceeded wrap — what go-redis produces when the STORE times
	// out, not the caller.
	hook := newInjectHook(fmt.Errorf("injected: store read timeout: %w", context.DeadlineExceeded))
	hook.failScanNonZeroCur = true
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	ctx := context.Background() // caller stays live throughout

	err := inv.InvalidateOrgAll(ctx, org)
	require.Error(t, err, "a store-timeout scan death must never return nil")
	require.ErrorIs(t, err, ErrInvalidationIncomplete,
		"store-side timeout with a live caller must classify incomplete, got: %v", err)

	var invErr *InvalidationError
	require.ErrorAs(t, err, &invErr, "failure must be an *InvalidationError")
	assert.True(t, invErr.ScanIncomplete, "got: %v", err)
	assert.Positive(t, invErr.Deleted, "keys enumerated before the store timeout must have been deleted")
	assert.Equal(t, int64(len(keys)-invErr.Deleted), countExisting(t, rdb, keys),
		"deleted count must account exactly for the surviving keys")

	assert.True(t, IsRetryable(ctx, err),
		"store timeout with a live caller is retryable (the caller's own deadline is not spent), got: %v", err)
}

// TestN03P5T07_SweepCallerCancelStillStopsImmediately is the negative pin:
// the ctx-aware retryable verdict must not over-correct. A caller whose
// context is REALLY cancelled stops the sweep immediately and the failure
// stays non-retryable — no keys are chased after cancellation.
func TestN03P5T07_SweepCallerCancelStillStopsImmediately(t *testing.T) {
	rdb := redisContainer(t)
	org := "org-t07-sweepcancel"
	keys := seedKeys(t, rdb, org, "smart", 1200)

	hook := newInjectHook(errors.New("injected: post-cancel scan"))
	hook.failScanNonZeroCur = true
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller gone before the sweep started

	err := inv.InvalidateOrgAll(ctx, org)
	require.Error(t, err, "a cancelled caller must never be reported as success")
	assert.True(t, IsCancellation(err), "got: %v", err)
	assert.False(t, IsRetryable(ctx, err), "a cancelled caller is never retryable")

	// Residue check: a pre-cancelled sweep enumerates nothing, deletes
	// nothing and leaves every key in place (the bounded-TTL stale window
	// the org accepted by disabling cache — cancellation must not widen it
	// by deleting half a namespace either).
	assert.Equal(t, int64(len(keys)), countExisting(t, rdb, keys),
		"pre-cancelled sweep must not touch keys")
}

// --- N03-P05-T07 part 2: embedding flight table at the stampede ceiling -----

// t07FlightFn builds a flight fn for one hash: it counts its own invocations
// (upstream calls), signals entry exactly once and blocks until released.
type t07FlightFn struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	once    sync.Once
	release chan struct{}
	val     []float32
}

func newT07FlightFn(val []float32) *t07FlightFn {
	return &t07FlightFn{entered: make(chan struct{}), release: make(chan struct{}), val: val}
}

func (p *t07FlightFn) fn(context.Context) ([]float32, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.val, nil
}

func (p *t07FlightFn) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestN03P5T07_EmbedFlightTableFull_DuplicateJoinsNewHashDegrades pins the
// stampede ceiling boundary in BOTH directions (card acceptance: "Штампеде
// не умножает upstream calls сверх заданного лимита"):
//
//   - with the table FULL, a duplicate of an IN-FLIGHT hash still joins the
//     shared load (coalescing never breaks at the limit — a busy verdict for
//     a duplicate would push every crowd member to its own upstream call);
//   - a NEW distinct hash at the limit degrades to ErrEmbedFlightBusy with
//     NO upstream call (the pre-T07 overflow behavior, re-pinned here);
//   - a cancelled duplicate returns only its own ctx error and never aborts
//     the shared load other callers joined (the packet's negative scenario);
//   - after all loads complete, no flight-table residue remains.
func TestN03P5T07_EmbedFlightTableFull_DuplicateJoinsNewHashDegrades(t *testing.T) {
	ef := newEmbedFlights(2, 5*time.Second)
	ctx := context.Background()

	fn1 := newT07FlightFn([]float32{1, 1})
	fn2 := newT07FlightFn([]float32{2, 2})
	fn3 := newT07FlightFn([]float32{3, 3})

	// Fill the table to the limit with two distinct in-flight hashes.
	res1 := make(chan t07FlightResult, 1)
	res2 := make(chan t07FlightResult, 1)
	go func() { v, err := ef.do(ctx, "h1", fn1.fn); res1 <- t07FlightResult{v, err} }()
	go func() { v, err := ef.do(ctx, "h2", fn2.fn); res2 <- t07FlightResult{v, err} }()
	<-fn1.entered
	<-fn2.entered
	require.Equal(t, 2, ef.active(), "table must be at its limit")

	// Duplicate of an in-flight hash while FULL: joins, never busy.
	dup1 := make(chan t07FlightResult, 1)
	go func() { v, err := ef.do(ctx, "h1", newT07FlightFn(nil).fn); dup1 <- t07FlightResult{v, err} }()
	require.Eventually(t, func() bool { return ef.waiting("h1") == 1 },
		5*time.Second, 2*time.Millisecond, "duplicate never joined the in-flight flight")
	assert.Equal(t, 1, fn1.callCount(), "joining must not start a second upstream call")
	assert.Equal(t, 2, ef.active(), "a join must not consume a new table slot")

	// NEW distinct hash while FULL: degrades busy, fn3 never runs.
	v3, err3 := ef.do(ctx, "h3", fn3.fn)
	assert.Nil(t, v3)
	require.ErrorIs(t, err3, ErrEmbedFlightBusy, "overflow of a new hash must degrade busy")
	assert.Zero(t, fn3.callCount(), "busy degradation must make no upstream call")

	// Cancelled duplicate of the other in-flight hash: only its own ctx
	// error; the shared load keeps running for the callers still joined.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, errDup2 := ef.do(cancelledCtx, "h2", newT07FlightFn(nil).fn)
	require.ErrorIs(t, errDup2, context.Canceled, "a cancelled caller gets only its own miss")

	// Release both loads: every joined caller is served by the single call.
	close(fn1.release)
	r1 := <-res1
	d1 := <-dup1
	require.NoError(t, r1.err)
	require.NoError(t, d1.err)
	assert.Equal(t, fn1.val, d1.vec, "duplicate must be served by the shared t07FlightResult")
	close(fn2.release)
	<-res2

	// Upstream call ceiling held: exactly one call per in-flight hash, none
	// for the busy hash, none for any duplicate.
	assert.Equal(t, 1, fn1.callCount())
	assert.Equal(t, 1, fn2.callCount())
	assert.Zero(t, fn3.callCount())

	// No lock/table residue after completion.
	require.Eventually(t, func() bool { return ef.active() == 0 },
		5*time.Second, 2*time.Millisecond, "flight table must drain completely")
}

// t07FlightResult mirrors the (vec, err) pair across goroutines.
type t07FlightResult struct {
	vec []float32
	err error
}
