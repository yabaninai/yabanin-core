package cache

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

// N03-P05-T04: bounded fallback for the exact layer under a Redis partition.
//
// Acceptance: a stampede of identical lookups must not multiply into a
// stampede of upstream calls — the first caller proceeds, the rest coalesce
// and are served by the write-back publication (or by the bounded lease
// mandate, at most one per window). Negative: one waiter's cancellation
// neither cancels the shared flight nor leaves a lock behind.

// refusedRedis returns a Redis client pointed at a port that refuses
// connections fast — the unit-level simulation of a partitioned backend.
// MaxRetries is zero so the refusal is a single immediate dial: with the
// default retry policy a concurrent stampede draws random backoffs of up to
// ~1.5s per lookup, which makes timing-sensitive stampede tests flaky.
func refusedRedis() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
		MaxRetries:  -1,
	})
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newPartitionTestService builds a CacheService wired with the partition
// guard, a refused exact backend and a writer that safely drops jobs (the
// gateway submits fire-and-forget; the write-back publication happens before
// the Redis Put inside Write).
func newPartitionTestService(t *testing.T, emb *flightEmbedder, partition *partitionFlights) *CacheService {
	t.Helper()
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slogDiscard())
	w.Stop() // jobs submitted afterwards are dropped, never processed
	return &CacheService{
		exact:       NewRedisStore(refusedRedis(), 24*time.Hour),
		policy:      pc,
		embedder:    emb,
		embedFlight: newEmbedFlights(4, 5*time.Second),
		partition:   partition,
		writer:      w,
		log:         slogDiscard(),
	}
}

func stampedePrompt() []byte {
	return []byte(`{"messages":[{"role":"user","content":"alpha"}]}`)
}

// Flight level: a published payload wakes every waiter exactly once and the
// table slot is freed; publishing without a flight is a safe no-op.
func TestPartitionFlights_PublishServesWaitersAndCleansUp(t *testing.T) {
	p := newPartitionFlights(8, 50*time.Millisecond, 5*time.Second)
	const key = "k"
	sealed := []byte("sealed-payload")

	if payload, published := p.await(context.Background(), key); published || payload != nil {
		t.Fatalf("creator: payload=%q published=%v, want nil false (creator is the leader)", payload, published)
	}
	if got := p.active(); got != 1 {
		t.Fatalf("active flights = %d, want 1 after the creator", got)
	}

	const waiters = 5
	type outcome struct {
		payload   []byte
		published bool
	}
	results := make(chan outcome, waiters)
	ctxs := make([]context.CancelFunc, 0, waiters)
	for i := 0; i < waiters; i++ {
		wctx, cancel := context.WithCancel(context.Background())
		ctxs = append(ctxs, cancel)
		go func() {
			payload, published := p.await(wctx, key)
			results <- outcome{payload, published}
		}()
	}
	waitFor(t, func() bool { return p.waiting(key) == waiters }, 2*time.Second)

	coalescedBefore := testutil.ToFloat64(CachePartitionCoalescedTotal)
	p.publish(key, sealed)
	for i := 0; i < waiters; i++ {
		select {
		case r := <-results:
			if !r.published || !bytes.Equal(r.payload, sealed) {
				t.Fatalf("waiter: payload=%q published=%v, want the published payload", r.payload, r.published)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d did not wake on publish", i)
		}
	}
	if got := testutil.ToFloat64(CachePartitionCoalescedTotal); got != coalescedBefore+waiters {
		t.Fatalf("coalesced counter = %v, want +%d", got, waiters)
	}
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)

	// Publishing again without a flight (or for an unknown key) is a no-op —
	// this is the healthy-backend hot path of Write.
	p.publish(key, sealed)
	p.publish("unknown-key", sealed)
	for _, cancel := range ctxs {
		cancel()
	}
}

// Flight level: while no payload is published, at most one leadership
// mandate is granted per lease window — the upstream attempt rate per hot
// key is bounded, not proportional to the waiting crowd.
func TestPartitionFlights_LeaseMandateBoundedOnePerWindow(t *testing.T) {
	p := newPartitionFlights(8, 100*time.Millisecond, 600*time.Millisecond)
	const key = "k"

	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}

	const waiters = 6
	mandates := make(chan struct{}, waiters)
	ctxs := make([]context.CancelFunc, 0, waiters)
	for i := 0; i < waiters; i++ {
		wctx, cancel := context.WithCancel(context.Background())
		ctxs = append(ctxs, cancel)
		go func() {
			payload, published := p.await(wctx, key)
			if payload != nil {
				t.Error("waiter got a payload although nothing was ever published")
			}
			if published {
				t.Error("waiter reported published although nothing was ever published")
			}
			mandates <- struct{}{}
		}()
	}
	waitFor(t, func() bool { return p.waiting(key) == waiters }, 2*time.Second)

	leaseBefore := testutil.ToFloat64(CachePartitionLeasesTotal)
	time.Sleep(450 * time.Millisecond) // ≈ 4 lease windows at 100ms
	mandateCount := testutil.ToFloat64(CachePartitionLeasesTotal) - leaseBefore
	if mandateCount < 1 {
		t.Fatalf("lease mandates = %v over 450ms, want at least 1", mandateCount)
	}
	if mandateCount > 5 {
		t.Fatalf("lease mandates = %v over 450ms at a 100ms window, want ≤ 5 (one per window)", mandateCount)
	}
	drained := len(mandates)
	if int64(drained) != int64(mandateCount) {
		t.Fatalf("returned waiters = %d, want == mandates %v", drained, mandateCount)
	}

	for _, cancel := range ctxs {
		cancel()
	}
	// The never-published flight dissolves at its TTL and frees the slot.
	waitFor(t, func() bool { return p.active() == 0 }, 3*time.Second)
}

// Negative acceptance: a cancelled waiter returns locally, the shared flight
// keeps serving the remaining waiters, and no lock is left behind — a fresh
// flight for the key works normally afterwards.
func TestPartitionFlights_WaiterCancelLeavesFlightIntactAndNoLock(t *testing.T) {
	p := newPartitionFlights(4, 50*time.Millisecond, 5*time.Second)
	const key = "k"
	sealed := []byte("payload")

	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}

	type outcome struct {
		payload   []byte
		published bool
	}
	served := make(chan outcome, 2)
	cancelled := make(chan outcome, 1)

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	ctxC, cancelC := context.WithCancel(context.Background())
	go func() { payload, published := p.await(ctxA, key); served <- outcome{payload, published} }()
	go func() { payload, published := p.await(ctxB, key); cancelled <- outcome{payload, published} }()
	go func() { payload, published := p.await(ctxC, key); served <- outcome{payload, published} }()
	waitFor(t, func() bool { return p.waiting(key) == 3 }, 2*time.Second)

	// One client walks away: it gets a local miss, promptly.
	cancelB()
	select {
	case r := <-cancelled:
		if r.published || r.payload != nil {
			t.Fatalf("cancelled waiter: payload=%q published=%v, want nil false", r.payload, r.published)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return after its own cancellation")
	}
	if got := p.waiting(key); got != 2 {
		t.Fatalf("waiters = %d after one cancellation, want 2 (shared flight untouched)", got)
	}
	if got := p.active(); got != 1 {
		t.Fatalf("active flights = %d after one cancellation, want 1 (no lock left behind)", got)
	}

	// The survivors are still served by the publication.
	p.publish(key, sealed)
	for i := 0; i < 2; i++ {
		select {
		case r := <-served:
			if !r.published || !bytes.Equal(r.payload, sealed) {
				t.Fatalf("surviving waiter: payload=%q published=%v, want the published payload", r.payload, r.published)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("surviving waiter was not served by the publication")
		}
	}
	cancelA()
	cancelC()
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)

	// No lock left: a fresh flight for the same key is creatable and
	// publishable.
	if _, published := p.await(context.Background(), key); published {
		t.Fatal("fresh creator must not be reported as published")
	}
	if got := p.active(); got != 1 {
		t.Fatalf("fresh flight: active = %d, want 1", got)
	}
	p.publish(key, []byte("second"))
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)
}

// The table cap is strict: beyond the limit, lookups fail open as
// independent misses (the pre-guard behavior) and no flight is created.
func TestPartitionFlights_OverflowFailsOpenBounded(t *testing.T) {
	p := newPartitionFlights(1, time.Second, 5*time.Second)

	if _, published := p.await(context.Background(), "key-a"); published {
		t.Fatal("creator must not be reported as published")
	}
	overflowBefore := testutil.ToFloat64(CachePartitionOverflowTotal)
	if _, published := p.await(context.Background(), "key-b"); published {
		t.Fatal("overflow caller must not be reported as published")
	}
	if got := testutil.ToFloat64(CachePartitionOverflowTotal); got != overflowBefore+1 {
		t.Fatalf("overflow counter = %v, want +1", got)
	}
	if got := p.active(); got != 1 {
		t.Fatalf("active flights = %d after overflow, want 1 (no flight for key-b)", got)
	}
	// key-a is still fully functional.
	p.publish("key-a", []byte("a"))
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)
}

// Dissolve and publish race on the single close of done: waiters observe
// exactly one outcome, stale publishes after a dissolve are no-ops, and the
// finished guard prevents double closes under -race.
func TestPartitionFlights_DissolvePublishRaceSingleClose(t *testing.T) {
	p := newPartitionFlights(8, 20*time.Millisecond, 50*time.Millisecond)
	const key = "k"

	// Round A: three concurrent publishes on one flight — exactly one wins
	// the close, the others are no-ops; no panic.
	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}
	var pubWG sync.WaitGroup
	for i := 0; i < 3; i++ {
		pubWG.Add(1)
		go func() {
			defer pubWG.Done()
			p.publish(key, []byte("payload"))
		}()
	}
	pubWG.Wait()
	waitFor(t, func() bool { return p.active() == 0 }, 2*time.Second)

	// Round B: a never-published flight dissolves at its TTL; afterwards
	// stale publishes are safe no-ops (the flight is already gone).
	if _, published := p.await(context.Background(), key); published {
		t.Fatal("creator must not be reported as published")
	}
	waitFor(t, func() bool { return p.active() == 0 }, 3*time.Second)
	p.publish(key, []byte("stale"))
	p.publish(key, []byte("stale"))

	// Round C: publish and the lease goroutine's dissolve race near the TTL
	// under -race; the finished guard must keep close() single-shot.
	for round := 0; round < 5; round++ {
		if _, published := p.await(context.Background(), key); published {
			t.Fatal("creator must not be reported as published")
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			time.Sleep(35 * time.Millisecond) // inside the 50ms TTL window
			p.publish(key, []byte("race"))
		}()
		<-done
		waitFor(t, func() bool { return p.active() == 0 }, 3*time.Second)
		time.Sleep(30 * time.Millisecond) // let the lease goroutine finish either way
	}
}

// THE acceptance: under a Redis partition, a stampede of N identical lookups
// produces exactly ONE upstream intent — the leader — while the N-1 waiters
// are served by the gateway's write-back publication (cache.Write), exactly
// as the healthy path would have served them from Redis.
func TestCacheService_PartitionStampedeWriteBackBoundsUpstream(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{}), entered: make(chan struct{})}
	// Lease far beyond the test horizon: this test proves coalescing +
	// write-back service; the lease bound has its own test above.
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 10*time.Second, 10*time.Second))

	ri := RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	response := []byte(`{"answer":"forty-two"}`)

	const callers = 50
	type outcome struct {
		hit *CacheHit
		err error
	}
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

	// The leader went to the gated embedder; everyone else coalesced on the
	// partition flight.
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 2*time.Second)
	waitFor(t, func() bool { return cs.partition.waiting(key) == callers-1 }, 2*time.Second)
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls before write-back = %d, want 1 (stampede multiplied upstream calls)", got)
	}

	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))

	// The gateway's fire-and-forget write-back: publishes to the waiters
	// BEFORE the Redis Put (which fails under the partition — the gateway
	// ignores the error, and the waiters are served regardless).
	if err := cs.Write(context.Background(), ri, prompt, response, 1, 2); err == nil {
		t.Log("redis Put unexpectedly succeeded; publication still precedes it by contract")
	}

	for i := 0; i < callers-1; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("waiter %d: unexpected error %v", i, r.err)
			}
			if r.hit == nil {
				t.Fatalf("waiter %d: nil hit, want the write-back payload", i)
			}
			if r.hit.SourceType != "exact" {
				t.Fatalf("waiter %d: source = %q, want exact", i, r.hit.SourceType)
			}
			if !bytes.Equal(r.hit.Data, response) {
				t.Fatalf("waiter %d: payload %q, want %q", i, r.hit.Data, response)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("waiter %d was not served by the write-back publication", i)
		}
	}

	// Release the leader: its embedder error degrades it to the single miss.
	close(emb.gate)
	wg.Wait()
	select {
	case r := <-results:
		if r.err != nil || r.hit != nil {
			t.Fatalf("leader: hit=%v err=%v, want nil nil (exactly one upstream intent)", r.hit, r.err)
		}
	default:
	}

	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+1 {
		t.Fatalf("misses = %v, want +%d (the leader is the single upstream intent; waiters are hits)", got, 1)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+callers-1 {
		t.Fatalf("exact hits = %v, want +%d (coalesced waiters)", got, callers-1)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream embedding calls = %d, want 1 (N=%d identical lookups)", got, callers)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// A flight shared across route identities serves only callers whose
// identity matches the published payload's provenance; the others fall
// through exactly as they would on a healthy backend.
func TestCacheService_PartitionForeignIdentityDoesNotServeForeignPayload(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 10*time.Second, 10*time.Second))

	riV1 := RouteIdentity{OrgID: "org-1", Model: "gpt-4o", Version: "v1"}.Resolved()
	riV2 := RouteIdentity{OrgID: "org-1", Model: "gpt-4o", Version: "v2"}.Resolved()
	prompt := stampedePrompt()
	response := []byte(`{"answer":"v1-only"}`)

	type outcome struct {
		hit *CacheHit
		err error
	}
	leaderDone := make(chan outcome, 1)
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), riV1, prompt)
		leaderDone <- outcome{hit, err}
	}()
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 2*time.Second)

	matched := make(chan outcome, 1)
	foreign := make(chan outcome, 1)
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), riV1, prompt)
		matched <- outcome{hit, err}
	}()
	go func() {
		hit, err := cs.LookupWithResult(context.Background(), riV2, prompt)
		foreign <- outcome{hit, err}
	}()
	waitFor(t, func() bool {
		return cs.partition.waiting(MakeKey(riV1.OrgID, riV1.Model, ComputePromptHash(normalizeForCache(prompt)))) == 2
	}, 2*time.Second)

	// Write-back under v1: the v1 waiter is served; the v2 waiter's
	// provenance verification rejects the foreign payload and falls through
	// to the (still gated) embedding stage together with the leader.
	_ = cs.Write(context.Background(), riV1, prompt, response, 1, 2)

	select {
	case r := <-matched:
		if r.err != nil || r.hit == nil || !bytes.Equal(r.hit.Data, response) {
			t.Fatalf("matching waiter: hit=%v err=%v, want the published payload", r.hit, r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("matching waiter was not served")
	}

	// Release the gate: the leader's embedder error degrades it to a miss,
	// and the foreign-identity fall-through misses the same way — it must
	// never be served the v1 payload.
	close(emb.gate)
	for name, ch := range map[string]chan outcome{"foreign-identity waiter": foreign, "leader": leaderDone} {
		select {
		case r := <-ch:
			if r.err != nil || r.hit != nil {
				t.Fatalf("%s: hit=%v err=%v, want nil nil (foreign payload must not serve)", name, r.hit, r.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not finish after the embedder gate was released", name)
		}
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// The cooldown arms on the first classified partition error, skips the
// doomed exact-layer round-trip for subsequent lookups, and re-probes the
// backend once it expires.
func TestCacheService_PartitionCooldownSkipsAndRecovers(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe")}
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 30*time.Millisecond, 300*time.Millisecond))

	ri := RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()

	partitionBefore := testutil.ToFloat64(CacheRedisPartitionTotal)

	// L1: the exact Get fails and is classified — the cooldown arms.
	if hit, err := cs.LookupWithResult(context.Background(), ri, prompt); hit != nil || err != nil {
		t.Fatalf("L1: hit=%v err=%v, want nil nil", hit, err)
	}
	if !cs.redisDown() {
		t.Fatal("cooldown not armed after a classified partition error")
	}
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore+1 {
		t.Fatalf("partition counter = %v, want +1 after classification", got)
	}

	// L2 (inside the cooldown): skips the Get and runs in partition mode.
	if hit, err := cs.LookupWithResult(context.Background(), ri, prompt); hit != nil || err != nil {
		t.Fatalf("L2: hit=%v err=%v, want nil nil", hit, err)
	}
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore+2 {
		t.Fatalf("partition counter = %v, want +2 (cooldown lookup still counted)", got)
	}

	// Expire the cooldown: the backend is re-probed and the failure
	// re-classified.
	cs.redisDownUntil.Store(1)
	if cs.redisDown() {
		t.Fatal("cooldown still armed after the deadline was reset")
	}
	if hit, err := cs.LookupWithResult(context.Background(), ri, prompt); hit != nil || err != nil {
		t.Fatalf("L3: hit=%v err=%v, want nil nil", hit, err)
	}
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore+3 {
		t.Fatalf("partition counter = %v, want +3 (re-probe reclassified)", got)
	}
	if !cs.redisDown() {
		t.Fatal("cooldown not re-armed by the re-probe failure")
	}
}

// Live (pgvector container): the full gateway loop under a Redis partition —
// the leader's miss runs through the REAL semantic layer against Postgres,
// the gateway's cache.Write publishes through the REAL writer pipeline, and
// the stampede is still served as one upstream intent plus N-1 coalesced
// hits. Requires Docker; skipped in -short mode.
func TestCacheService_PartitionStampede_LivePGWriteBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	pool := newSemanticPGPool(t, nil)

	// 384 dims to match the cache_entries embedding column: the leader's
	// semantic query and the worker's pgvector write are exercised for real.
	emb := &flightEmbedder{vec: makeTestEmbedding(384, 0.01), gate: make(chan struct{})}
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	cs := &CacheService{
		exact:       NewRedisStore(refusedRedis(), 24*time.Hour), // the partitioned layer
		semantic:    NewSemanticCache(pool, 0, 0),
		store:       NewStore(pool),
		writer:      NewWriter(context.Background(), pool, emb, slogDiscard()),
		policy:      pc,
		embedder:    emb,
		embedFlight: newEmbedFlights(4, 5*time.Second),
		partition:   newPartitionFlights(8, 10*time.Second, 10*time.Second),
		log:         slogDiscard(),
	}

	ri := RouteIdentity{OrgID: "org-live", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	response := []byte(`{"answer":"live-write-back"}`)

	const callers = 24
	type outcome struct {
		hit *CacheHit
		err error
	}
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
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 3*time.Second)
	waitFor(t, func() bool { return cs.partition.waiting(key) == callers-1 }, 3*time.Second)

	// The gateway's write-back: publishes to the waiters through Write even
	// though the Redis Put inside it fails (partitioned backend).
	_ = cs.Write(context.Background(), ri, prompt, response, 1, 2)

	// Release the leader: real semantic lookup on an empty table → the
	// single miss.
	close(emb.gate)
	wg.Wait()

	// Drain every caller exactly once: exactly one miss (the leader's
	// upstream intent) and callers-1 coalesced exact hits.
	misses, hits := 0, 0
	for i := 0; i < callers; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("caller %d: unexpected error %v", i, r.err)
			}
			switch {
			case r.hit == nil:
				misses++
			case r.hit.SourceType == "exact" && bytes.Equal(r.hit.Data, response):
				hits++
			default:
				t.Fatalf("caller %d: unexpected hit source=%q data=%q", i, r.hit.SourceType, r.hit.Data)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("caller %d did not return", i)
		}
	}
	if misses != 1 {
		t.Fatalf("misses = %d, want exactly 1 (N=%d identical lookups under a partition)", misses, callers)
	}
	if hits != callers-1 {
		t.Fatalf("coalesced hits = %d, want %d", hits, callers-1)
	}
	if got := emb.calls.Load(); got < 2 {
		t.Fatalf("embedding calls = %d, want at least 2 (lookup + writer pipeline)", got)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// Live (Redis container): on a healthy backend the guard never engages —
// no partition lookups, no flights, no cooldown.
func TestCacheService_HealthyRedisNeverEngagesPartition_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	rdb := redisContainer(t)
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		// Semantic disabled keeps the first (cold) lookup on the miss path
		// before the embedding stage — this test is about the exact layer.
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slogDiscard())
	w.Stop()
	cs := &CacheService{
		exact:       NewRedisStore(rdb, 24*time.Hour),
		policy:      pc,
		embedder:    &flightEmbedder{vec: []float32{0.1, 0.2, 0.3}},
		embedFlight: newEmbedFlights(4, 5*time.Second),
		partition:   newPartitionFlights(8, 10*time.Second, 10*time.Second),
		writer:      w,
		log:         slogDiscard(),
	}

	ri := RouteIdentity{OrgID: "org-live", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	response := []byte(`{"answer":"healthy"}`)

	partitionBefore := testutil.ToFloat64(CacheRedisPartitionTotal)

	if hit, err := cs.LookupWithResult(context.Background(), ri, prompt); hit != nil || err != nil {
		t.Fatalf("cold lookup: hit=%v err=%v, want nil nil", hit, err)
	}
	if err := cs.Write(context.Background(), ri, prompt, response, 1, 2); err != nil {
		t.Fatalf("healthy Write returned an error: %v", err)
	}
	hit, err := cs.LookupWithResult(context.Background(), ri, prompt)
	if err != nil || hit == nil {
		t.Fatalf("warm lookup: hit=%v err=%v, want the exact hit", hit, err)
	}
	if hit.SourceType != "exact" || !bytes.Equal(hit.Data, response) {
		t.Fatalf("warm lookup: source=%q data=%q, want the exact payload", hit.SourceType, hit.Data)
	}

	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != partitionBefore {
		t.Fatalf("partition counter = %v, want unchanged on a healthy backend", got)
	}
	if got := cs.partition.active(); got != 0 {
		t.Fatalf("active partition flights = %d, want 0 on a healthy backend", got)
	}
	if cs.redisDown() {
		t.Fatal("cooldown armed on a healthy backend")
	}
}
