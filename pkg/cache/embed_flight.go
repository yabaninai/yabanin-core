// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxEmbedFlights bounds concurrent upstream embedding calls issued by
	// cache lookups (N03-P05 stampede limit). Concurrent identical misses
	// share one call per prompt hash, and at most maxEmbedFlights DISTINCT
	// hashes load at the same time; lookups arriving beyond the limit
	// degrade to a cache miss WITHOUT an upstream call. The semantic layer
	// is best-effort and must never amplify provider load.
	maxEmbedFlights = 32

	// embedFlightTimeout bounds one shared embedding load: it is detached
	// from every caller's context, so only this deadline (or an embedder
	// error) can end a load that no caller is waiting for anymore. The
	// deadline also releases the flight's TABLE SLOT even when the embedder
	// ignores its context (a wedged upstream must not consume a concurrency
	// slot forever); the abandoned load keeps running to completion.
	embedFlightTimeout = 30 * time.Second
)

// ErrEmbedFlightBusy reports that the embedding flight table is at its
// concurrency limit: the caller was NOT served by a shared load and made NO
// upstream call. Callers degrade it to a cache miss (nil, nil).
var ErrEmbedFlightBusy = errors.New("cache: embedding flight limit reached")

// embedFlight is one shared embedding load for one prompt hash. done is
// closed exactly once after vec and err are set, so reading them after
// <-done is race-free.
type embedFlight struct {
	done chan struct{}
	// waiters counts callers currently joined and waiting on done
	// (diagnostics for the stampede guard, mirrors callout.InFlight).
	waiters atomic.Int64
	vec     []float32
	err     error
}

// embedFlights deduplicates concurrent identical embedding lookups per
// prompt hash and bounds the total number of concurrent upstream embedding
// calls (singleflight with a hard limit; N03-P05-T02). Sequential repeats
// are served by EmbedCache; embedFlights covers the concurrent window.
//
// Cancellation semantics (the packet's negative scenario): the shared load
// runs on a context detached from every caller (context.WithoutCancel plus
// a timeout), so
//   - a caller's cancellation returns ONLY that caller a miss — it never
//     aborts a load other callers joined, and
//   - a completed flight removes its table entry, and the deadline removes
//     it even when the embedder ignores its context, so no flight/lock
//     state outlives the load by more than the timeout.
//
// A nil *embedFlights degrades to a direct call with the caller's context:
// a CacheService constructed without the group (partial unit-test
// constructions) keeps the pre-T02 behavior instead of panicking.
type embedFlights struct {
	mu      sync.Mutex
	flights map[string]*embedFlight
	limit   int
	timeout time.Duration
}

func newEmbedFlights(limit int, timeout time.Duration) *embedFlights {
	if limit <= 0 {
		limit = maxEmbedFlights
	}
	if timeout <= 0 {
		timeout = embedFlightTimeout
	}
	return &embedFlights{
		flights: make(map[string]*embedFlight),
		limit:   limit,
		timeout: timeout,
	}
}

// do returns the embedding for hash. Concurrent callers with the same hash
// share one fn run; fn itself runs on a detached, timeout-bounded context.
// Distinct hashes are admitted up to the limit of concurrent flights; beyond
// it do returns ErrEmbedFlightBusy without calling fn.
func (ef *embedFlights) do(ctx context.Context, hash string, fn func(context.Context) ([]float32, error)) ([]float32, error) {
	if ef == nil {
		return fn(ctx)
	}

	ef.mu.Lock()
	if f, ok := ef.flights[hash]; ok {
		ef.mu.Unlock()
		f.waiters.Add(1)
		defer f.waiters.Add(-1)
		select {
		case <-f.done:
			return f.vec, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(ef.flights) >= ef.limit {
		ef.mu.Unlock()
		return nil, ErrEmbedFlightBusy
	}
	f := &embedFlight{done: make(chan struct{})}
	ef.flights[hash] = f
	ef.mu.Unlock()

	go func() {
		defer close(f.done)
		// Detached bounded load: no caller's cancellation can abort a
		// shared load others joined; a hung embedder still ends here.
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ef.timeout)
		defer cancel()

		// The table slot must never outlive the load deadline, even when fn
		// ignores its context (a wedged embedder must not shrink the flight
		// table forever): the deadline releases the entry, and the
		// completion release below is a guarded no-op afterwards. Callers
		// already joined on this flight keep their own context escape; the
		// release only unblocks NEW admissions (including a fresh flight
		// for the same hash — the identity check never deletes it).
		release := func() {
			ef.mu.Lock()
			if ef.flights[hash] == f {
				delete(ef.flights, hash)
			}
			ef.mu.Unlock()
		}
		deadlineRelease := time.AfterFunc(ef.timeout, release)
		defer deadlineRelease.Stop()

		f.vec, f.err = fn(loadCtx)

		deadlineRelease.Stop()
		release()
	}()

	select {
	case <-f.done:
		return f.vec, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// waiting reports how many callers are currently joined on hash's flight.
// Diagnostics for tests and the stampede guard.
func (ef *embedFlights) waiting(hash string) int64 {
	if ef == nil {
		return 0
	}
	ef.mu.Lock()
	f := ef.flights[hash]
	ef.mu.Unlock()
	if f == nil {
		return 0
	}
	return f.waiters.Load()
}

// active reports the number of in-flight embedding loads. Diagnostics.
func (ef *embedFlights) active() int {
	if ef == nil {
		return 0
	}
	ef.mu.Lock()
	defer ef.mu.Unlock()
	return len(ef.flights)
}
