package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// testLogger routes slog records into t.Log, so writer-pipeline failures
// surface in the test output instead of being swallowed by a discard logger.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(&testLogWriter{t: t}, nil))
}

type testLogWriter struct{ t *testing.T }

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

var _ io.Writer = (*testLogWriter)(nil)

// N03-P05-T05: negative-path acceptance for the Redis-partition guard.
//
//   - CANCEL ISOLATION: one client's cancellation (or abandonment) never
//     cancels another client's in-flight request and never leaves a stuck
//     flight/lock behind — extended from the flight level (T04) through the
//     full lookup path including the pg-exact layer.
//   - INVALIDATION×STAMPEDE: org-wide invalidation racing a stampede must
//     keep the upstream attempt count bounded (one leader per round), while
//     every served caller receives its own round's payload.
//   - T04-review follow-ups: the mismatched-waiter fall-through burst is
//     quantified (bounded by distinct route identities, never a foreign
//     payload), and a recovered exact backend serves hits as soon as the
//     classification cooldown expires.

// gatedPgStore simulates the pgvector exact layer: the first GetExact call
// signals entered and blocks on gate (the leader mid-load), then returns the
// prepared entry; every later call returns immediately as a plain miss and
// is counted — the burst gauge for mismatched fall-through identities.
type gatedPgStore struct {
	calls   atomic.Int64
	gate    chan struct{}
	entered chan struct{}
	entry   *Entry
	once    sync.Once
}

func (s *gatedPgStore) GetExact(context.Context, string, string, string, string) (*Entry, error) {
	s.calls.Add(1)
	s.once.Do(func() {
		if s.entered != nil {
			close(s.entered)
		}
		<-s.gate
	})
	if s.entry != nil && s.calls.Load() == 1 {
		return s.entry, nil
	}
	//nolint:nilnil // mirrors Store.GetExact contract: nil,nil = miss
	return nil, nil
}

func (s *gatedPgStore) PurgeExpired(context.Context) (int, error) { return 0, nil }

func (s *gatedPgStore) PurgeExpiredWithLock(context.Context) (int, bool, error) {
	return 0, false, nil
}

// newPartitionPgGateService is newPartitionTestService with the pg-exact
// layer enabled (semantic disabled: the pg-exact layer decides first).
func newPartitionPgGateService(t *testing.T, store BackendStore, partition *partitionFlights) *CacheService {
	t.Helper()
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slogDiscard())
	w.Stop()
	return &CacheService{
		exact:          NewRedisStore(refusedRedis(), 24*time.Hour),
		store:          store,
		policy:         pc,
		embedder:       failingEmbedder{},
		embedFlight:    newEmbedFlights(4, 5*time.Second),
		partition:      partition,
		writer:         w,
		pgExactEnabled: true,
		log:            slogDiscard(),
	}
}

// Flight level, negative: the leader abandons the flight (its load dies
// without ever publishing — the leader-side equivalent of a client walking
// away mid-request). The flight must not wedge the key: waiters receive the
// leadership mandate at the bounded rate (one per lease window), the zombie
// dissolves at its TTL, and a fresh flight for the key is creatable and
// publishable afterwards.
func TestPartitionFlights_LeaderAbandonedFlightWaitersBoundedNoStuck(t *testing.T) {
	p := newPartitionFlights(8, 60*time.Millisecond, 400*time.Millisecond)
	const key = "k"

	// The leader creates the flight and never publishes.
	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}

	type outcome struct {
		payload   []byte
		published bool
		elapsed   time.Duration
	}
	const waiters = 3
	results := make(chan outcome, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			start := time.Now()
			payload, published := p.await(context.Background(), key)
			results <- outcome{payload, published, time.Since(start)}
		}()
	}
	waitFor(t, func() bool { return p.waiting(key) == waiters }, 2*time.Second)

	// Every waiter proceeds within a bounded horizon (one mandate per
	// 60ms window; three waiters must all drain well before 3 windows
	// plus scheduler slack) — no waiter is left stuck on the abandoned
	// flight.
	bound := 3*p.leaseWindow + 300*time.Millisecond
	for i := 0; i < waiters; i++ {
		select {
		case r := <-results:
			if r.published || r.payload != nil {
				t.Fatalf("waiter %d: payload=%q published=%v, want nil false (mandate fall-through)", i, r.payload, r.published)
			}
			if r.elapsed > bound {
				t.Fatalf("waiter %d blocked for %v, want <%v (bounded fall-through)", i, r.elapsed, bound)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d is stuck on the abandoned flight", i)
		}
	}

	// The zombie flight dissolves at its TTL and frees the slot.
	waitFor(t, func() bool { return p.active() == 0 }, 3*time.Second)

	// No lock left behind: a fresh flight for the same key works normally.
	if _, published := p.await(context.Background(), key); published {
		t.Fatal("fresh creator must not be reported as published")
	}
	p.publish(key, []byte("fresh"))
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)
}

// Flight level, negative: when EVERY caller cancels (leader included — the
// leader's context is irrelevant to the flight after creation), no payload
// is ever published, the waiters return promptly on their own contexts, and
// the flight still dissolves at its TTL — no stuck lock.
func TestPartitionFlights_AllCallersCancelledDissolvesAtTTL(t *testing.T) {
	p := newPartitionFlights(4, 10*time.Second, 150*time.Millisecond)
	const key = "k"

	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}

	const waiters = 2
	returned := make(chan struct{}, waiters)
	ctxB, cancelB := context.WithCancel(context.Background())
	ctxC, cancelC := context.WithCancel(context.Background())
	go func() { _, _ = p.await(ctxB, key); returned <- struct{}{} }()
	go func() { _, _ = p.await(ctxC, key); returned <- struct{}{} }()
	waitFor(t, func() bool { return p.waiting(key) == waiters }, 2*time.Second)

	// Both waiters walk away: they must return immediately (the lease
	// window is 10s — waiting for a mandate would blow this deadline).
	cancelB()
	cancelC()
	for i := 0; i < waiters; i++ {
		select {
		case <-returned:
		case <-time.After(1 * time.Second):
			t.Fatalf("cancelled waiter %d did not return promptly on its own context", i)
		}
	}

	// The never-published flight dissolves at its TTL.
	waitFor(t, func() bool { return p.active() == 0 }, 3*time.Second)

	if _, published := p.await(context.Background(), key); published {
		t.Fatal("fresh creator must not be reported as published")
	}
	p.publish(key, []byte("after"))
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)
}

// Service level, negative: a leader whose load dies without publishing (the
// upstream intent failed) leaves the flight zombified only for its TTL; the
// coalesced waiters drain through the bounded lease mandates (one per
// window), each degrading to a plain miss, and a fresh lookup afterwards
// becomes the new leader. No caller is stuck and none errors.
func TestCacheService_PartitionLeaderAbandonWaitersDrainBounded(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe")}
	// Lease 60ms so mandates drain the waiters quickly; TTL 400ms bounds
	// the zombie lifetime.
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 60*time.Millisecond, 400*time.Millisecond))

	ri := RouteIdentity{OrgID: "org-abandon", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))

	type outcome struct {
		hit *CacheHit
		err error
	}
	leaderDone := make(chan outcome, 1)
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
		leaderDone <- outcome{hit, err}
	}()
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 2*time.Second)

	const waiters = 3
	results := make(chan outcome, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
			results <- outcome{hit, err}
		}()
	}
	waitFor(t, func() bool { return cs.partition.waiting(key) == waiters }, 2*time.Second)

	// The leader's intent already failed (probe error) — it must be a
	// prompt miss, and the waiters must drain via the lease mandates
	// rather than hanging on the zombie flight.
	select {
	case r := <-leaderDone:
		if r.err != nil || r.hit != nil {
			t.Fatalf("leader: hit=%v err=%v, want nil nil", r.hit, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return after its failed load")
	}

	bound := 3*60*time.Millisecond + 500*time.Millisecond
	start := time.Now()
	for i := 0; i < waiters; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("waiter %d: unexpected error %v", i, r.err)
			}
			if r.hit != nil {
				t.Fatalf("waiter %d: hit %v, want a plain miss (nothing was ever published)", i, r.hit)
			}
		case <-time.After(bound):
			t.Fatalf("waiter %d is stuck on the zombie flight (bound %v)", i, bound)
		}
	}
	if elapsed := time.Since(start); elapsed > bound {
		t.Fatalf("waiters drained in %v, want <%v", elapsed, bound)
	}

	// The zombie dissolves at its TTL and the key is immediately reusable.
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
	if _, published := cs.partition.await(context.Background(), key); published {
		t.Fatal("fresh flight creator must not be reported as published")
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("fresh flight: active = %d, want 1 (no stuck lock)", got)
	}
	cs.partition.publish(key, []byte("cleanup"))
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// Service level, negative, through the full lookup path: a coalesced waiter's
// cancellation is local. The leader keeps loading through the REAL pg-exact
// layer (a gated BackendStore stub), publishes its hit, and the surviving
// waiter is served — the cancelled one gets a plain local miss. The shared
// pg load is never cancelled and no lock is left behind.
func TestCacheService_PartitionWaiterCancelIsolatedThroughPgExact(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-cancel", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	pgResponse := []byte(`{"answer":"from-pg-exact"}`)
	sealed, err := SealEntry(pgResponse, ri)
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	store := &gatedPgStore{
		gate:    make(chan struct{}),
		entered: make(chan struct{}),
		entry: &Entry{
			OrgID:      ri.OrgID,
			ModelTier:  ri.Model,
			PromptHash: ComputePromptHash(normalizeForCache(prompt)),
			ModelVer:   ri.Version,
			Response:   sealed,
		},
	}
	cs := newPartitionPgGateService(t, store, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))

	type outcome struct {
		hit *CacheHit
		err error
	}
	leaderDone := make(chan outcome, 1)
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
		leaderDone <- outcome{hit, err}
	}()
	// The leader is inside the gated pg-exact load.
	select {
	case <-store.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("leader never reached the pg-exact layer")
	}

	cancelledDone := make(chan outcome, 1)
	survivorDone := make(chan outcome, 1)
	ctxB, cancelB := context.WithCancel(context.Background())
	go func() { hit, err := cs.LookupWithResult(ctxB, ri, prompt); cancelledDone <- outcome{hit, err} }()
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
		survivorDone <- outcome{hit, err}
	}()
	waitFor(t, func() bool { return cs.partition.waiting(key) == 2 }, 2*time.Second)

	// One client walks away while the leader is mid-load: local, prompt,
	// and invisible to everyone else.
	start := time.Now()
	cancelB()
	select {
	case r := <-cancelledDone:
		if r.err != nil || r.hit != nil {
			t.Fatalf("cancelled waiter: hit=%v err=%v, want nil nil (local miss)", r.hit, r.err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("cancelled waiter did not return after its own cancellation")
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Fatalf("cancelled waiter took %v, want ≪ the 10s lease window", elapsed)
	}
	if got := cs.partition.waiting(key); got != 1 {
		t.Fatalf("waiters = %d after the cancellation, want 1 (shared flight untouched)", got)
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("active flights = %d after the cancellation, want 1 (no lock left behind)", got)
	}

	// The leader's shared load completes unaffected and publishes.
	close(store.gate)
	select {
	case r := <-leaderDone:
		if r.err != nil {
			t.Fatalf("leader: unexpected error %v", r.err)
		}
		if r.hit == nil || r.hit.SourceType != "pg_exact" || !bytes.Equal(r.hit.Data, pgResponse) {
			t.Fatalf("leader: hit=%v, want the pg_exact payload", r.hit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader was not served by the pg-exact layer")
	}

	// The surviving waiter is served by the publication.
	select {
	case r := <-survivorDone:
		if r.err != nil {
			t.Fatalf("surviving waiter: unexpected error %v", r.err)
		}
		if r.hit == nil || r.hit.SourceType != "exact" || !bytes.Equal(r.hit.Data, pgResponse) {
			t.Fatalf("surviving waiter: hit=%v, want the published payload as exact", r.hit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("surviving waiter was not served by the publication")
	}

	if got := store.calls.Load(); got != 1 {
		t.Fatalf("pg-exact store calls = %d, want 1 (waiters never duplicated the load)", got)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// THE invalidation×stampede acceptance: R rounds of an N-caller stampede,
// each round racing an org-wide invalidation, keep the upstream embedding
// attempts at exactly R (one leader per round). Invalidation neither
// multiplies the leaders nor wedges the flights, and every served caller
// receives its OWN round's payload — never a previous round's.
func TestCacheService_PartitionInvalidationChurnBoundsEmbedCalls(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe")}
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	inv := NewInvalidator(cs.exact, nil, refusedRedis())

	ri := RouteIdentity{OrgID: "org-churn", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))

	const rounds = 3
	const callers = 12
	roundLetter := []rune{'a', 'b', 'c'}

	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))

	type outcome struct {
		hit *CacheHit
		err error
	}
	for round := 0; round < rounds; round++ {
		response := []byte(`{"answer":"round-` + string(roundLetter[round]) + `"}`)

		results := make(chan outcome, callers)
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
				results <- outcome{hit, err}
			}()
		}

		// The round's leader is upstream; everyone else coalesced.
		waitFor(t, func() bool { return emb.calls.Load() == int64(round+1) }, 2*time.Second)
		waitFor(t, func() bool { return cs.partition.waiting(key) == callers-1 }, 2*time.Second)

		// Org-wide invalidation racing the stampede. Under the partition
		// the Redis sweep cannot complete; it must be reported as
		// incomplete — never as success.
		invErr := make(chan error, 1)
		go func() { invErr <- inv.InvalidateOrgAll(context.Background(), ri.OrgID) }()

		// The gateway's write-back publishes this round's payload to the
		// coalesced waiters (synchronously, before the doomed Redis Put).
		_ = cs.Write(context.Background(), ri, prompt, response, 1, 2)

		var hits, misses int
		for i := 0; i < callers; i++ {
			select {
			case r := <-results:
				if r.err != nil {
					t.Fatalf("round %d caller %d: unexpected error %v", round, i, r.err)
				}
				switch {
				case r.hit == nil:
					misses++
				case r.hit.SourceType == "exact" && bytes.Equal(r.hit.Data, response):
					hits++
				default:
					t.Fatalf("round %d caller %d: payload %q (source %q), want this round's %q",
						round, i, r.hit.Data, r.hit.SourceType, response)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("round %d caller %d did not return (wedged by the racing invalidation?)", round, i)
			}
		}
		if misses != 1 || hits != callers-1 {
			t.Fatalf("round %d: misses=%d hits=%d, want 1/%d (one leader, coalesced waiters)", round, misses, hits, callers-1)
		}

		select {
		case err := <-invErr:
			if !errors.Is(err, ErrInvalidationIncomplete) {
				t.Fatalf("round %d: invalidation error %v, want ErrInvalidationIncomplete under the partition", round, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: invalidation did not finish", round)
		}

		wg.Wait()
		waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
	}

	if got := emb.calls.Load(); got != rounds {
		t.Fatalf("upstream embedding calls = %d after %d rounds of N=%d lookups with racing invalidations, want exactly %d (bounded by churn, not by crowd)",
			got, rounds, callers, rounds)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+rounds {
		t.Fatalf("misses = %v, want +%d (one leader per round)", got, rounds)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+rounds*(callers-1) {
		t.Fatalf("coalesced hits = %v, want +%d", got, rounds*(callers-1))
	}
}

// T04-review follow-up (a), quantified: the flight's collapse key is coarser
// than the route identity, so a published payload for identity A falls
// through for every CONCURRENTLY waiting mismatched identity — one
// legacy-style full attempt per distinct identity (here visible as one
// pg-exact store call each), never a served foreign payload, and never an
// amplification beyond the distinct identities themselves. This burst is the
// documented disposition (record §Limitations): bounded by identity
// diversity, unchanged from the pre-guard legacy semantics.
func TestCacheService_PartitionMismatchedIdentityFallThroughBurstBounded(t *testing.T) {
	riA := RouteIdentity{OrgID: "org-burst", Model: "gpt-4o", GenParams: "reasoning_effort=low"}.Resolved()
	prompt := stampedePrompt()
	pgResponse := []byte(`{"answer":"effort-low-only"}`)
	sealed, err := SealEntry(pgResponse, riA)
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	store := &gatedPgStore{
		gate:    make(chan struct{}),
		entered: make(chan struct{}),
		entry: &Entry{
			OrgID:      riA.OrgID,
			ModelTier:  riA.Model,
			PromptHash: ComputePromptHash(normalizeForCache(prompt)),
			ModelVer:   riA.Version,
			Response:   sealed,
		},
	}
	cs := newPartitionPgGateService(t, store, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	key := MakeKey(riA.OrgID, riA.Model, ComputePromptHash(normalizeForCache(prompt)))

	foreignIdentities := []RouteIdentity{
		{OrgID: riA.OrgID, Model: riA.Model, GenParams: "reasoning_effort=medium"},
		{OrgID: riA.OrgID, Model: riA.Model, GenParams: "reasoning_effort=high"},
		{OrgID: riA.OrgID, Model: riA.Model, GenParams: "temperature=0.7"},
		{OrgID: riA.OrgID, Model: riA.Model, GenParams: "user=tenant-b"},
		{OrgID: riA.OrgID, Model: riA.Model, GenParams: "frequency_penalty=0.5"},
	}
	for i := range foreignIdentities {
		foreignIdentities[i] = foreignIdentities[i].Resolved()
		// Same org+model+prompt ⇒ same collapse key; different GenParams
		// ⇒ the sealed provenance can never match.
		if MakeKey(foreignIdentities[i].OrgID, foreignIdentities[i].Model, ComputePromptHash(normalizeForCache(prompt))) != key {
			t.Fatalf("foreign identity %d does not share the collapse key", i)
		}
	}

	type outcome struct {
		hit *CacheHit
		err error
	}
	leaderDone := make(chan outcome, 1)
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), riA, prompt)
		leaderDone <- outcome{hit, err}
	}()
	select {
	case <-store.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("leader never reached the pg-exact layer")
	}

	const foreign = 5
	results := make(chan outcome, foreign)
	for _, ri := range foreignIdentities {
		go func(ri RouteIdentity) {
			hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
			results <- outcome{hit, err}
		}(ri)
	}
	waitFor(t, func() bool { return cs.partition.waiting(key) == foreign }, 2*time.Second)

	// Release the leader: the A-payload is published and every mismatched
	// waiter falls through — exactly one legacy-style attempt each.
	close(store.gate)

	select {
	case r := <-leaderDone:
		if r.err != nil {
			t.Fatalf("leader: unexpected error %v", r.err)
		}
		if r.hit == nil || r.hit.SourceType != "pg_exact" || !bytes.Equal(r.hit.Data, pgResponse) {
			t.Fatalf("leader: hit=%v, want the pg_exact payload", r.hit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader was not served")
	}

	for i := 0; i < foreign; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("foreign waiter %d: unexpected error %v", i, r.err)
			}
			if r.hit != nil {
				t.Fatalf("foreign waiter %d: served %q (source %q) — a foreign payload must never serve", i, r.hit.Data, r.hit.SourceType)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("foreign waiter %d did not fall through", i)
		}
	}

	// The burst is exactly one full attempt per mismatched identity: the
	// leader's gated call plus one fall-through call each.
	if got := store.calls.Load(); got != 1+foreign {
		t.Fatalf("pg-exact store calls = %d, want %d (leader + one legacy attempt per distinct mismatched identity)", got, 1+foreign)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// T04-review follow-up (b), live (Redis container): a partition classified
// against a refused backend serves misses until the classification cooldown
// expires; as soon as it does, a RECOVERED exact backend is re-probed and its
// entries are served as exact hits again — with no upstream embedding call
// and without re-engaging the partition guard. Requires Docker; skipped in
// -short mode.
func TestCacheService_PartitionRecoveredExactHitServedAfterCooldownExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	rdb := redisContainer(t)

	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slogDiscard())
	w.Stop()
	emb := &flightEmbedder{err: errors.New("embedder probe")}
	cs := &CacheService{
		exact:       NewRedisStore(refusedRedis(), 24*time.Hour), // the partitioned layer
		policy:      pc,
		embedder:    emb,
		embedFlight: newEmbedFlights(4, 5*time.Second),
		partition:   newPartitionFlights(8, 30*time.Millisecond, 300*time.Millisecond),
		writer:      w,
		log:         slogDiscard(),
	}

	ri := RouteIdentity{OrgID: "org-recover", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	response := []byte(`{"answer":"recovered-exact"}`)

	partitionBefore := testutil.ToFloat64(CacheRedisPartitionTotal)

	// L1 against the refused backend: classified, cooldown armed, miss.
	if hit, err := cs.LookupWithResult(context.Background(), ri, prompt); hit != nil || err != nil {
		t.Fatalf("L1: hit=%v err=%v, want nil nil", hit, err)
	}
	if !cs.redisDown() {
		t.Fatal("cooldown not armed after the classification")
	}
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore+1 {
		t.Fatalf("partition counter = %v, want +1 after L1", got)
	}

	// Recovery: the exact layer comes back and the gateway writes through it.
	cs.exact = NewRedisStore(rdb, 24*time.Hour)
	if err := cs.Write(context.Background(), ri, prompt, response, 3, 5); err != nil {
		t.Fatalf("Write against the recovered backend: %v", err)
	}

	// The cooldown expires: the next lookup re-probes and is served from
	// the recovered exact layer — a real hit, not a partition fallback.
	cs.redisDownUntil.Store(1)
	if cs.redisDown() {
		t.Fatal("cooldown still armed after the deadline was reset")
	}
	hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
	if err != nil || hit == nil {
		t.Fatalf("L2: hit=%v err=%v, want the recovered exact hit", hit, err)
	}
	if hit.SourceType != "exact" || !bytes.Equal(hit.Data, response) {
		t.Fatalf("L2: source=%q data=%q, want the recovered exact payload", hit.SourceType, hit.Data)
	}
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore+1 {
		t.Fatalf("partition counter = %v, want unchanged by L2 (guard not re-engaged)", got)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("embedding calls = %d, want 1 (L1's miss only — the recovered hit short-circuits upstream)", got)
	}
	if got := cs.partition.active(); got != 0 {
		t.Fatalf("active flights = %d, want 0", got)
	}
}

// sameJSON reports byte equality first, then JSON-value equality: the
// pgvector response column is jsonb, so rows served from Postgres come back
// re-serialized (object members spaced) while publish-served sealed bytes are
// verbatim. Both forms are the same cached completion; a different round's
// payload fails both comparisons.
func sameJSON(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var va, vb interface{}
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// Live (Postgres container): the full real path — real semantic layer, real
// writer pipeline, real org-wide invalidation — under a Redis partition.
// Two rounds of a stampede with a racing invalidation between them and a
// cancelled waiter inside the second round: every served caller receives its
// own round's payload, the cancelled one degrades locally, the leaders stay
// bounded, and the invalidation provably removes the first round's entry.
// Requires Docker; skipped in -short mode.
func TestCacheService_PartitionCancelIsolationInvalidationChurn_LivePG(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	pool := newSemanticPGPool(t, nil)
	pgStore := NewStore(pool)

	emb1 := &flightEmbedder{vec: makeTestEmbedding(384, 0.01), gate: make(chan struct{})}
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	cs := &CacheService{
		exact:       NewRedisStore(refusedRedis(), 24*time.Hour), // the partitioned layer
		semantic:    NewSemanticCache(pool, 0, 0),
		store:       pgStore,
		writer:      NewWriter(context.Background(), pool, emb1, testLogger(t)),
		policy:      pc,
		embedder:    emb1,
		embedFlight: newEmbedFlights(4, 5*time.Second),
		partition:   newPartitionFlights(8, 10*time.Second, 10*time.Second),
		log:         testLogger(t),
	}
	t.Cleanup(func() { cs.writer.Stop() })
	inv := NewInvalidator(cs.exact, pgStore, refusedRedis())

	// The org must be a real UUID row: the pgvector writer path (the one this
	// test verifies lands a row) inserts org_id as uuid.
	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	ri := RouteIdentity{OrgID: orgID, Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"live-round-1"}`)
	resp2 := []byte(`{"answer":"live-round-2"}`)

	const callers = 6
	type outcome struct {
		hit *CacheHit
		err error
	}

	// ---- Round 1: stampede + write-back publication. ----
	results1 := make(chan outcome, callers)
	var wg1 sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
			results1 <- outcome{hit, err}
		}()
	}
	waitFor(t, func() bool { return emb1.calls.Load() == 1 }, 3*time.Second)
	waitFor(t, func() bool { return cs.partition.waiting(key) == callers-1 }, 3*time.Second)
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	close(emb1.gate) // release the leader (and the writer pipeline's embed)
	wg1.Wait()

	var r1Misses, r1Hits int
	for i := 0; i < callers; i++ {
		select {
		case r := <-results1:
			if r.err != nil {
				t.Fatalf("round 1 caller %d: unexpected error %v", i, r.err)
			}
			switch {
			case r.hit == nil:
				r1Misses++ // the leader (the sole fresh-compute caller of the round)
			case sameJSON(r.hit.Data, resp1):
				r1Hits++ // publish path (verbatim sealed bytes), the leader's own
				// semantic refill, or a pg-exact hit whose jsonb column
				// re-serialized the response document
			default:
				t.Fatalf("round 1 caller %d: payload %q (source %q), want round 1's %q", i, r.hit.Data, r.hit.SourceType, resp1)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round 1 caller %d did not return", i)
		}
	}
	// Only the leader may miss (fresh compute); every coalesced waiter is
	// served. The leader itself may legitimately be served its own fresh row:
	// after its embed resumes, the writer pipeline's Put may already have
	// landed, and the semantic search then finds it — still one upstream
	// embed, so this is a served caller, not an extra attempt.
	if r1Misses > 1 {
		t.Fatalf("round 1: %d callers missed, want at most the leader (served=%d)", r1Misses, r1Hits)
	}
	if r1Hits < callers-1 {
		t.Fatalf("round 1: served=%d, want ≥ %d (every non-leader caller must be served)", r1Hits, callers-1)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)

	// The writer pipeline lands round 1's row in pgvector.
	emb1Total := emb1.calls.Load()
	waitFor(t, func() bool {
		e, err := cs.store.GetExact(context.Background(), ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)), ri.Version)
		return err == nil && e != nil
	}, 10*time.Second)
	q, d, w := cs.WriterStats()
	f, s := cs.writer.OutcomeStats()
	t.Logf("writer outcomes after round-1 row: queued=%d dropped=%d written=%d failed=%d skipped=%d emb=%d",
		q, d, w, f, s, emb1.calls.Load())

	// ---- Invalidation: pg deletion must succeed; the Redis sweep fails
	// under the partition and must be reported incomplete, not success. ----
	if err := inv.InvalidateOrgAll(context.Background(), ri.OrgID); !errors.Is(err, ErrInvalidationIncomplete) {
		t.Fatalf("InvalidateOrgAll: err=%v, want ErrInvalidationIncomplete (redis side refuses under the partition)", err)
	}
	if e, err := cs.store.GetExact(context.Background(), ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)), ri.Version); err != nil || e != nil {
		t.Fatalf("post-invalidation GetExact: entry=%v err=%v, want the row deleted", e, err)
	}

	// ---- Round 2: stampede again, one waiter cancels mid-wait. ----
	emb2 := &flightEmbedder{vec: makeTestEmbedding(384, 0.02), gate: make(chan struct{})}
	cs.embedder = emb2 // fresh gate for the round-2 leader (the writer keeps emb1)

	results2 := make(chan outcome, callers)
	ctxs := make([]context.CancelFunc, callers)
	var wg2 sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg2.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = cancel
		go func(ctx context.Context) {
			defer wg2.Done()
			hit, err := cs.LookupWithResult(ctx, ri, prompt)
			results2 <- outcome{hit, err}
		}(ctx)
	}
	waitFor(t, func() bool { return emb2.calls.Load() == 1 }, 3*time.Second)
	waitFor(t, func() bool { return cs.partition.waiting(key) == callers-1 }, 3*time.Second)

	// One client walks away mid-round: local miss, prompt, and the round
	// completes for everyone else.
	start := time.Now()
	ctxs[callers-1]()
	var r2Cancelled bool
	select {
	case r := <-results2:
		if r.err != nil || r.hit != nil {
			t.Fatalf("cancelled waiter: hit=%v err=%v, want nil nil (local miss)", r.hit, r.err)
		}
		r2Cancelled = true
	case <-time.After(1 * time.Second):
		t.Fatal("cancelled round-2 waiter did not return promptly")
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Fatalf("cancelled waiter took %v, want ≪ the 10s lease window", elapsed)
	}

	_ = cs.Write(context.Background(), ri, prompt, resp2, 1, 2)
	close(emb2.gate)
	wg2.Wait()

	var r2Misses, r2Hits int
	for i := 0; i < callers-1; i++ { // the cancelled waiter's outcome was consumed above
		select {
		case r := <-results2:
			if r.err != nil {
				t.Fatalf("round 2 caller %d: unexpected error %v", i, r.err)
			}
			switch {
			case r.hit == nil:
				r2Misses++
			case sameJSON(r.hit.Data, resp2):
				r2Hits++
			default:
				t.Fatalf("round 2 caller %d: payload %q (source %q), want round 2's %q — a caller must never receive another round's payload", i, r.hit.Data, r.hit.SourceType, resp2)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round 2 caller %d did not return", i)
		}
	}
	if !r2Cancelled {
		t.Fatal("the cancelled waiter's outcome was not observed exactly once")
	}
	// Round 2 must serve every remaining waiter (publish path); among the
	// non-cancelled callers at most the leader may miss (same benign
	// Put/Search race as round 1), and nobody may receive a foreign payload.
	if r2Misses > 1 || r2Hits < callers-2 {
		t.Fatalf("round 2: served=%d missed=%d (+1 cancelled waiter), want every waiter served; at most the leader may miss", r2Hits, r2Misses)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)

	// Upstream bound: the two leaders plus the writer pipeline's embeds —
	// never one per caller, despite 2×%d lookups, a racing invalidation
	// and a cancellation.
	if total := emb1.calls.Load() + emb2.calls.Load(); total > emb1Total+4 {
		t.Fatalf("total embedding calls = %d, want ≤ %d (2 leaders + writer pipeline; crowd must not multiply upstream)", total, emb1Total+4)
	}
}
