package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

const aliasReloadEvery = 30 * time.Second

// ErrAliasesUnavailable reports that the alias table could not be consulted:
// the book has no loaded snapshot (initial load still in flight, or the last
// load failed and is backing off), or the calling request ran out of time or
// was cancelled while waiting for the shared load. It wraps
// ErrModelUnavailable so the gateway's terminal unavailable mapping applies
// unchanged. AF-03: a cold or outaged alias book is not an authoritative
// miss — treating it as one would route the request into the registry lookup
// of the requested name, where a genuine not-found turns the outage into a
// successful call on the default model.
var ErrAliasesUnavailable = fmt.Errorf("%w: alias table unavailable", ErrModelUnavailable)

// aliasQuerier is the read side of the alias table. *pgxpool.Pool satisfies it.
type aliasQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// aliasSnapshot is an immutable alias → target mapping. Readers work on one
// snapshot pointer and never block on a reload: a refresh atomically replaces
// the pointer, so warm lookups are pure in-memory map reads (RT-06: no DB I/O
// can be reached while holding a lock the read path needs).
type aliasSnapshot struct {
	exact    map[string]string
	prefixes []aliasPrefix
	loadedAt time.Time
}

// AliasBook caches alias → target mappings and reloads them at most once per
// TTL.
//
// Lookup contract (RT-06, revised for the initial load by AF-03):
//   - warm reads never block on I/O: a lookup serves the current snapshot
//     and, when it is expired, triggers a bounded non-blocking refresh —
//     at most one refresh runs at a time (refreshMu.TryLock), a caller that
//     arrives while a refresh is in flight serves the current (possibly
//     stale) snapshot (stale-while-refresh);
//   - a failed (or timed out) refresh keeps the previous snapshot and backs
//     off until the next TTL, so a failing load is not retried per request.
//     This is a deliberate staleness/error policy, NOT a cross-replica
//     guarantee: each replica refreshes on its own TTL;
//   - while the book has never loaded (cold), lookups share the in-flight
//     initial load and wait for it, each bounded by its OWN context: a
//     cancelled/expired caller gets ErrAliasesUnavailable without aborting
//     the shared load for everybody else, and no caller waits unbounded
//     (the load itself is detached from any single caller and bounded by
//     the load timeout below);
//   - if the initial load fails, the book has no authoritative answer to
//     give: lookups report ErrAliasesUnavailable until the next TTL window
//     retries the load (recovery), instead of fabricating an authoritative
//     "no aliases" miss (the pre-AF-03 defect that turned an outage into a
//     successful default-model fallback).
type AliasBook struct {
	ttl       time.Duration
	load      func(ctx context.Context) (map[string]string, error)
	log       *slog.Logger
	refreshMu sync.Mutex
	snap      atomic.Pointer[aliasSnapshot]
	now       func() time.Time // injectable for tests
	// loadTimeout bounds a detached shared load. A load that exceeds it is
	// treated like a failed load (stale/backoff policy above); it exists so
	// a hung alias DB cannot keep the book cold (or the refresh slot) forever.
	loadTimeout time.Duration
	// loadDone is the settle-channel of the most recent load attempt: swapped
	// in (under the refresh slot) when the attempt is announced and closed
	// when it settles (success, failure, or skip). Cold callers wait on
	// whatever channel they observe, each under its own context and the load
	// timeout — every announced attempt closes its own channel, and the
	// pre-announcement channel is born closed, so an observed channel always
	// settles and a failed attempt surfaces as an explicit unavailable.
	loadDone atomic.Pointer[chan struct{}]
	// failAt is the unix-nano timestamp of the last failed load while no
	// snapshot existed to serve (0 = none). It enforces one load attempt per
	// TTL window for a cold book during an outage, without fabricating an
	// authoritative empty snapshot.
	failAt atomic.Int64
	// runLoadSync runs load attempts inline instead of spawning a goroutine.
	// Production leaves it false (loads are detached by design, AF-03); tests
	// that assert load sequencing set it to stay deterministic under heavy
	// suite load, where a detached goroutine's first slice can be delayed
	// arbitrarily by OS scheduling.
	runLoadSync bool
}

type aliasPrefix struct {
	prefix string
	target string
}

// NewAliasBook reloads aliases from load at most once per ttl.
func NewAliasBook(ttl time.Duration, load func(ctx context.Context) (map[string]string, error), log *slog.Logger) *AliasBook {
	if ttl <= 0 {
		ttl = aliasReloadEvery
	}
	ready := make(chan struct{})
	close(ready) // no attempt announced yet: cold waiters fall through to refresh
	b := &AliasBook{
		ttl:         ttl,
		load:        load,
		log:         log,
		now:         time.Now,
		loadTimeout: aliasReloadEvery,
	}
	b.loadDone.Store(&ready)
	return b
}

// QueryAliases reads the alias table. A missing table is reported to the caller.
func QueryAliases(ctx context.Context, q aliasQuerier) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT alias, target_model FROM model_aliases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var alias, target string
		if err := rows.Scan(&alias, &target); err != nil {
			return nil, err
		}
		out[alias] = target
	}
	return out, rows.Err()
}

// Lookup returns the target model for an exact alias or the longest matching
// trailing-star prefix. The outcome is explicit (AF-03):
//
//   - (target, nil): the name is an alias for target;
//   - ("", nil): the book is loaded and the name is authoritatively not an
//     alias — the caller may proceed with its own lookup;
//   - ("", err): the book cannot answer authoritatively (cold load in
//     flight/backing off, or this caller's context ended while waiting).
//     err wraps ErrAliasesUnavailable; the caller must not treat it as a miss.
//
// The request context bounds THIS caller's wait for the shared initial load
// and flows into a triggered refresh only as the trigger identity: the load
// itself runs detached (a cancelled request must not abort the shared load
// for others, AF-03) and bounded by the load timeout.
func (b *AliasBook) Lookup(ctx context.Context, name string) (string, error) {
	if b == nil || name == "" {
		return "", nil
	}
	if snap := b.snap.Load(); snap != nil && b.now().Sub(snap.loadedAt) < b.ttl {
		return lookupSnapshot(snap, name), nil
	}
	// Cold or stale: the book cannot answer from memory. Warm callers (an
	// expired snapshot exists) serve it stale without waiting (RT-06
	// stale-while-refresh); cold callers wait below for the shared load.
	for range aliasLoadAttempts {
		b.refresh(ctx)
		if b.snap.Load() == nil {
			// Cold book: wait for the most recent announced attempt. A caller
			// that lost the TryLock may race the winner's announcement
			// window: until the winner's swap it sees the (closed)
			// pre-announcement channel, falls through immediately, and
			// retries the next round — it never waits on a channel that no
			// attempt will settle, and never blocks on the refresh slot
			// (which would ignore this caller's context).
			b.waitAttempt(ctx, b.currentLoadDone())
		}
		if err := ctx.Err(); err != nil {
			// A cancelled/expired caller is never served, even if the shared
			// load completed meanwhile; the book stays loaded for the others.
			return "", fmt.Errorf("%w: %v", ErrAliasesUnavailable, err)
		}
		if snap := b.snap.Load(); snap != nil {
			return lookupSnapshot(snap, name), nil
		}
		// The attempt settled without a snapshot. Inside the failure backoff
		// window this is the explicit unavailable outcome; otherwise (our
		// piggyback raced a slot holder that could not announce, or the wait
		// watchdog fired) one more round is tried before giving up — bounded,
		// never a busy loop.
		if b.backoffActive() {
			break
		}
	}
	// No snapshot after the attempt(s) settled: the alias table is
	// unreachable and we are inside its backoff window. Explicit
	// unavailable — never a fabricated authoritative miss.
	return "", fmt.Errorf("%w: alias load failed; backing off until the next TTL", ErrAliasesUnavailable)
}

// aliasLoadAttempts bounds the refresh/wait rounds of a single Lookup: the
// first round covers the normal cold/retry path, the extra rounds only absorb
// races with a still-settling attempt or a lost announcement.
const aliasLoadAttempts = 4

// aliasWaitSlack extends the per-attempt wait beyond the load timeout: an
// announced attempt always settles within loadTimeout (its own context
// deadline), so a longer wait means the attempt was lost and the caller
// retries the announcement instead of waiting forever (AF-03: no request
// waits unbounded, even with a background context).
const aliasWaitSlack = 5 * time.Second

// waitAttempt waits for one load attempt to settle, bounded by the caller's
// context and by a watchdog slightly longer than the load timeout.
func (b *AliasBook) waitAttempt(ctx context.Context, done chan struct{}) {
	timer := time.NewTimer(b.loadTimeout + aliasWaitSlack)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}
}

func lookupSnapshot(snap *aliasSnapshot, name string) string {
	if target, ok := snap.exact[name]; ok {
		return target
	}
	for _, p := range snap.prefixes {
		if strings.HasPrefix(name, p.prefix) {
			return p.target
		}
	}
	return ""
}

// refresh triggers a reload outside of any read-path lock. Only one load runs
// at a time; concurrent callers are not queued behind it (warm callers keep
// serving the current snapshot, cold callers share the in-flight first load —
// see Lookup). The load runs detached from the triggering request's context
// so that one cancelled caller cannot abort the shared load for everybody
// else, and bounded by loadTimeout so a hung alias DB cannot hold the refresh
// slot forever. The bool result reports whether a new attempt was announced.
func (b *AliasBook) refresh(ctx context.Context) bool {
	if b.load == nil || b.backoffActive() {
		return false
	}
	if !b.refreshMu.TryLock() {
		return false
	}
	// Re-check under the lock BEFORE announcing: a concurrent attempt may
	// have landed a fresh snapshot between the caller's stale check and here.
	// This keeps a hot stale-read path from announcing (and spawning) an
	// attempt per lookup.
	if snap := b.snap.Load(); snap != nil && b.now().Sub(snap.loadedAt) < b.ttl {
		b.refreshMu.Unlock()
		return false
	}
	// Announce this attempt (under the refresh slot we hold) before spawning
	// so lookups that find no snapshot wait on THIS attempt rather than on an
	// already-settled older one.
	done := make(chan struct{})
	b.loadDone.Store(&done)
	if b.runLoadSync {
		b.runLoad(ctx, done)
	} else {
		go b.runLoad(ctx, done)
	}
	return true
}

// runLoad owns refreshMu for the duration of one load attempt (the lock was
// acquired by refresh) and always settles its done channel.
func (b *AliasBook) runLoad(trigger context.Context, done chan struct{}) {
	defer b.refreshMu.Unlock()
	defer close(done)

	// Double-check under the lock: a concurrent refresh may have completed a
	// fresh load between the stale check and the TryLock.
	now := b.now()
	if snap := b.snap.Load(); snap != nil && now.Sub(snap.loadedAt) < b.ttl {
		return
	}
	// Backoff: a cold book whose last load failed is not retried per request —
	// one attempt per TTL window (the warm-book variant of this policy reuses
	// the previous snapshot's refreshed loadedAt below).
	if b.backoffActive() {
		return
	}

	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(trigger), b.loadTimeout)
	defer cancel()

	rows, err := b.load(loadCtx)
	if err != nil {
		if b.log != nil {
			b.log.Warn("model alias reload failed", "error", err)
		}
		// Error policy: keep serving the previous snapshot (if any) and back
		// off until the next TTL; a first load that failed leaves the book
		// without a snapshot, so lookups report an explicit unavailable until
		// the next TTL retries the load (AF-03) — an outage must never look
		// like an authoritative "no aliases".
		if cur := b.snap.Load(); cur != nil {
			b.snap.Store(&aliasSnapshot{exact: cur.exact, prefixes: cur.prefixes, loadedAt: b.now()})
		} else {
			b.failAt.Store(b.now().UnixNano())
		}
		return
	}
	b.failAt.Store(0)
	exact, prefixes := compileAliases(rows)
	b.snap.Store(&aliasSnapshot{exact: exact, prefixes: prefixes, loadedAt: b.now()})
}

// currentLoadDone returns the settle-channel of the most recent observed load
// attempt. The atomic pointer makes the read race-free: every channel ever
// observable here is closed by its own attempt (or born closed), so waiting
// on it is always bounded.
func (b *AliasBook) currentLoadDone() chan struct{} {
	return *b.loadDone.Load()
}

// backoffActive reports whether the last failed cold load is still inside its
// one-attempt-per-TTL backoff window.
func (b *AliasBook) backoffActive() bool {
	failAt := b.failAt.Load()
	return failAt != 0 && b.now().Sub(time.Unix(0, failAt)) < b.ttl
}

func compileAliases(rows map[string]string) (map[string]string, []aliasPrefix) {
	exact := make(map[string]string, len(rows))
	var prefixes []aliasPrefix
	for alias, target := range rows {
		if strings.HasSuffix(alias, "*") && len(alias) > 1 {
			prefixes = append(prefixes, aliasPrefix{prefix: strings.TrimSuffix(alias, "*"), target: target})
			continue
		}
		exact[alias] = target
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i].prefix) > len(prefixes[j].prefix)
	})
	return exact, prefixes
}

// UseAliases attaches an alias book. Nil disables alias rewriting.
func (r *Resolver) UseAliases(book *AliasBook) {
	if r == nil {
		return
	}
	r.aliases = book
}
