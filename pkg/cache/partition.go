// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis-partition bounded fallback (N03-P05-T04).
//
// When the exact layer's Redis is partitioned or down, every lookup used to
// degrade to an independent miss, so a stampede of N identical requests was
// multiplied into N upstream calls. The guard below keeps the degradation
// bounded instead:
//
//   - Classification: an exact-layer error that is neither redis.Nil (an
//     ordinary miss) nor the caller's own cancellation marks the partition
//     (redisUnavailable). The first classification also arms a short cooldown
//     during which later lookups skip the doomed Redis round-trip entirely
//     (re-probed when the cooldown expires — recovery is delayed by at most
//     partitionCooldown).
//
//   - Coalescing: per-key in-process singleflight with a strict table cap.
//     The first caller of a key becomes the LEADER: it returns a miss
//     immediately (no added latency) and proceeds through the remaining
//     layers/upstream exactly as before the guard existed. Concurrent
//     identical callers become WAITERS: each blocks until
//     a) the response is published (the gateway's cache.Write after the
//     upstream call, or an earlier hit on the pg-exact/semantic layer)
//     — the waiter is served the payload as an exact hit, or
//     b) a lease window (partitionLease) hands the waiter the leadership
//     mandate — at most ONE mandate per key per window, so the upstream
//     attempt rate per hot key is bounded at 1/window, or
//     c) the waiter's own context is done — a local miss that leaves the
//     flight and all other waiters untouched.
//
//   - Bounds: at most maxPartitionFlights distinct keys coalesce at once
//     (overflow callers fail open exactly as before the guard — bounded by
//     the cap); one leadership mandate per key per partitionLease; a flight
//     with no published payload dissolves after partitionFlightTTL, waking
//     its waiters into the same bounded fall-through.
//
// Scope honesty: the table is per-process (like embedFlights). Invalidation
// racing a partition flight can leave a published payload servable for at
// most partitionFlightTTL — the same class as the documented redisSweep
// warm-up resurrection (T03), self-healing through misses after the TTL.
const (
	// maxPartitionFlights bounds the number of distinct keys that coalesce
	// concurrently. Beyond the cap, lookups fail open (miss, legacy path)
	// instead of queueing — the stampede bound stays strict while key
	// diversity cannot grow the table without bound.
	maxPartitionFlights = 64

	// partitionLease is the leadership window: at most one waiter per key
	// per window receives the mandate to attempt the upstream call, so a
	// hot key produces at most one upstream attempt per window while its
	// flight has no published payload.
	partitionLease = 5 * time.Second

	// partitionFlightTTL dissolves a never-published flight: the leader's
	// upstream attempt is presumed dead, the flight leaves the table and a
	// fresh lookup may become the new leader.
	partitionFlightTTL = 60 * time.Second

	// partitionCooldown is how long a classified Redis outage skips the
	// exact-layer round-trip (and its dial/read timeout) before the next
	// lookup re-probes the backend.
	partitionCooldown = 5 * time.Second
)

// redisUnavailable classifies an exact-layer error for one lookup: everything
// except an ordinary miss (redis.Nil) and the caller's own cancellation means
// the backend or the network to it is unavailable. The caller context decides
// cancellation: with a live caller context a deadline-exceeded error comes
// from the store's own dial, read or pool timeout — a partition signal that
// must coalesce, not an abort that bypasses the stampede guard. It
// deliberately errs toward "unavailable": coalescing is harmless whenever
// Redis would have served a miss anyway.
func redisUnavailable(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, redis.Nil) {
		return false
	}
	if ctx.Err() != nil {
		// The caller is gone; whether the backend also erred is moot and
		// the lookup will be dropped by its own cancellation checks.
		return false
	}
	return !errors.Is(err, context.Canceled)
}

// partitionFlight is one in-process coalescing point for one exact-cache key
// while Redis is partitioned. done is closed exactly once (publish or
// dissolve); payload/published are written before that close under the group
// mutex, so waiters read them race-free after <-done (or under the mutex).
type partitionFlight struct {
	key string
	// done is closed exactly once: publish (hit) or dissolve (TTL).
	done chan struct{}
	// lease carries leadership mandates: at most one buffered token, one
	// sent per lease window while the flight is unpublished.
	lease   chan struct{}
	waiters atomic.Int64
	// published/payload/finished are guarded by partitionFlights.mu and
	// frozen before done closes.
	published bool
	payload   []byte
	finished  bool // done already closed (guard against double close)
}

// partitionFlights is the bounded per-key flight table (the partition-mode
// stampede guard). A nil *partitionFlights degrades to the legacy unguarded
// behavior: every caller proceeds independently (partial CacheService
// constructions, pre-T04 semantics).
type partitionFlights struct {
	mu          sync.Mutex
	flights     map[string]*partitionFlight
	limit       int
	leaseWindow time.Duration
	ttl         time.Duration
}

func newPartitionFlights(limit int, leaseWindow, ttl time.Duration) *partitionFlights {
	if limit <= 0 {
		limit = maxPartitionFlights
	}
	if leaseWindow <= 0 {
		leaseWindow = partitionLease
	}
	if ttl <= 0 {
		ttl = partitionFlightTTL
	}
	return &partitionFlights{
		flights:     make(map[string]*partitionFlight),
		limit:       limit,
		leaseWindow: leaseWindow,
		ttl:         ttl,
	}
}

// await joins (or, as the first caller, creates) the key's flight.
//
// Returns (payload, true) when a response was published while this caller
// waited — the caller serves it after its own provenance verification. All
// other outcomes return (nil, false): the caller either holds the leadership
// mandate (creator or lease) or is degraded to a plain miss (overflow,
// dissolved flight, own cancellation). The distinction is resolved by
// CacheService.partitionLookup.
func (p *partitionFlights) await(ctx context.Context, key string) ([]byte, bool) {
	if p == nil {
		return nil, false
	}

	p.mu.Lock()
	f, ok := p.flights[key]
	if !ok {
		if len(p.flights) >= p.limit {
			p.mu.Unlock()
			RecordPartitionOverflow()
			return nil, false // overflow: bounded fail-open, legacy behavior
		}
		f = &partitionFlight{
			key:   key,
			done:  make(chan struct{}),
			lease: make(chan struct{}, 1),
		}
		p.flights[key] = f
		go p.runLease(f)
		p.mu.Unlock()
		return nil, false // the creator is the leader: proceed immediately
	}
	p.mu.Unlock()

	f.waiters.Add(1)
	defer f.waiters.Add(-1)
	select {
	case <-f.done:
		p.mu.Lock()
		published, payload := f.published, f.payload
		p.mu.Unlock()
		if published {
			RecordPartitionCoalesced()
			return payload, true
		}
		return nil, false // dissolved at TTL without a payload
	case <-f.lease:
		RecordPartitionLease()
		return nil, false // this caller now holds the upstream mandate
	case <-ctx.Done():
		return nil, false // caller abort: the shared flight is untouched
	}
}

// runLease hands out at most one leadership mandate per lease window until
// the flight is published (done closes) or dissolved at its TTL. The TTL is
// enforced by its own timer — not by checking the deadline on lease ticks —
// so a never-published flight dissolves within partitionFlightTTL even when
// the TTL is shorter than one lease window.
func (p *partitionFlights) runLease(f *partitionFlight) {
	ticker := time.NewTicker(p.leaseWindow)
	defer ticker.Stop()
	timer := time.NewTimer(p.ttl)
	defer timer.Stop()
	for {
		select {
		case <-ticker.C:
			// Non-blocking send: exactly one mandate is outstanding per
			// window; an unclaimed token is not stockpiled.
			select {
			case f.lease <- struct{}{}:
			default:
			}
		case <-timer.C:
			p.dissolve(f)
			return
		case <-f.done:
			return
		}
	}
}

// publish stores the sealed payload and wakes every waiter as a hit. It is a
// no-op without an active flight for the key (healthy Redis, unknown key) —
// the hot paths of Write and the hit layers pay one mutex-guarded map lookup.
func (p *partitionFlights) publish(key string, sealed []byte) {
	if p == nil || sealed == nil {
		return
	}
	p.mu.Lock()
	f, ok := p.flights[key]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.flights, key)
	f.payload = sealed
	f.published = true
	p.closeLocked(f)
	p.mu.Unlock()
}

// dissolve wakes a never-published flight's waiters (they proceed under the
// bounded fall-through) and frees the table slot. The identity check keeps a
// stale dissolve from touching a flight freshly recreated for the same key.
// A dissolve that loses the publish race (runLease picked timer.C after
// publish closed done) must leave the frozen published/payload pair intact:
// waiters waking on <-done read it race-free and must still see the hit.
// The pair is never reset here — a never-published flight already has
// published == false, so any reset would only corrupt a raced publish.
func (p *partitionFlights) dissolve(f *partitionFlight) {
	p.mu.Lock()
	if p.flights[f.key] == f {
		delete(p.flights, f.key)
	}
	p.closeLocked(f)
	p.mu.Unlock()
}

// closeLocked closes f.done exactly once; callers must hold p.mu. Closing
// under the mutex is safe: waiters waking from <-done only queue on the
// mutex to read the frozen published/payload pair.
func (p *partitionFlights) closeLocked(f *partitionFlight) {
	if f.finished {
		return
	}
	f.finished = true
	close(f.done)
}

// waiting reports how many callers are currently joined on key's flight.
// Diagnostics for tests and the stampede guard.
func (p *partitionFlights) waiting(key string) int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	f := p.flights[key]
	p.mu.Unlock()
	if f == nil {
		return 0
	}
	return f.waiters.Load()
}

// active reports the number of live partition flights. Diagnostics.
func (p *partitionFlights) active() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.flights)
}
