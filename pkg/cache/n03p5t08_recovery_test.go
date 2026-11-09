package cache

// N03-P05-T08 — interruption/retry/resume recovery corpus.
//
// Distinct from the boundary corpus (T07) and the joint scenario (T06): this
// file pins the RECOVERY side of the packet contract — a participant that is
// interrupted mid-round and retries must rejoin without multiplying upstream
// calls or losing the shared result; lookups that resume after a completed
// invalidation must never be served the invalidated generation once the
// flight table has cleared; a Redis partition that ends mid-stampede must
// converge with bounded fallback and exactly one completing invalidation
// retry; and a cancelled leadership-mandate holder must leave the shared
// round, the other participants and the lock intact — proven by a fresh
// acquire.
//
// REAL Redis testcontainers are used for every service-level recovery pin
// (tests 3, 5, 6); the flight-level races run against the in-memory flights
// (tests 1, 4) exactly like T02/T04. Publication goes through cs.Write —
// the same seam the gateway's async writer uses (pkg/gateway/chat.go:1455) —
// so the pins cover LookupWithResult+Write orchestration, not test internals.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// t08Lookup is one LookupWithResult outcome collected from a goroutine.
type t08Lookup struct {
	hit *CacheHit
	err error
}

// t08RedisHook fails selected Redis commands a bounded number of times and
// counts how often each watched command ran, so tests can pin "exactly one
// sweep attempt" and "the recovered backend was really re-probed". Unlike
// injectHook it can be disarmed mid-test to model the backend coming back.
type t08RedisHook struct {
	mu        sync.Mutex
	remaining map[string]int
	scanCalls int
	getCalls  int
	injected  error
}

func (h *t08RedisHook) disarm() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.remaining = map[string]int{}
}

func (h *t08RedisHook) watched() (scans, gets int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.scanCalls, h.getCalls
}

func (h *t08RedisHook) check(cmd redis.Cmder) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch cmd.Name() {
	case "get":
		h.getCalls++
	case "scan":
		h.scanCalls++
	}
	if n, ok := h.remaining[cmd.Name()]; ok && n > 0 {
		h.remaining[cmd.Name()] = n - 1
		return h.injected
	}
	return nil
}

func (h *t08RedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *t08RedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if err := h.check(cmd); err != nil {
			return err
		}
		return next(ctx, cmd)
	}
}

func (h *t08RedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if err := h.check(cmd); err != nil {
				return err
			}
		}
		return next(ctx, cmds)
	}
}

// t08SequencedStore is the pg-exact seam stub: the first `gated` GetExact
// calls park on gate (each signals its own entered channel) honouring the
// CALLER's context — a cancelled mandate holder escapes on its own ctx while
// the leader's load continues — and later calls are plain misses. call#1
// returns entry when the gate (not the caller) releases it.
type t08SequencedStore struct {
	calls   atomic.Int64
	gated   int
	gate    chan struct{}
	entry   *Entry
	mu      sync.Mutex
	entered []chan struct{}
}

func (s *t08SequencedStore) enteredCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entered)
}

func (s *t08SequencedStore) GetExact(ctx context.Context, _, _, _, _ string) (*Entry, error) {
	n := s.calls.Add(1)
	s.mu.Lock()
	park := int(n) <= s.gated
	var entered chan struct{}
	if park {
		entered = make(chan struct{})
		s.entered = append(s.entered, entered)
	}
	entry := s.entry
	s.mu.Unlock()
	if !park {
		//nolint:nilnil // mirrors Store.GetExact contract: nil,nil = miss
		return nil, nil
	}
	close(entered)
	select {
	case <-s.gate:
		if entry != nil && n == 1 {
			return entry, nil
		}
		//nolint:nilnil // mirrors Store.GetExact contract: nil,nil = miss
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *t08SequencedStore) PurgeExpired(context.Context) (int, error) { return 0, nil }

func (s *t08SequencedStore) PurgeExpiredWithLock(context.Context) (int, bool, error) {
	return 0, false, nil
}

// t08Service is newPartitionPgGateService bound to a REAL (hooked) Redis
// client: same policy (enabled, semantic off), same seam layout.
func t08Service(t *testing.T, rdb *redis.Client, store BackendStore, leaseWindow, ttl time.Duration) *CacheService {
	t.Helper()
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slogDiscard())
	w.Stop() // Write() still publishes + Puts synchronously; queued jobs drop
	return &CacheService{
		exact:          NewRedisStore(rdb, 24*time.Hour),
		store:          store,
		policy:         pc,
		embedder:       failingEmbedder{}, // any embed call surfaces as an error result
		embedFlight:    newEmbedFlights(4, 5*time.Second),
		partition:      newPartitionFlights(8, leaseWindow, ttl),
		writer:         w,
		pgExactEnabled: true,
		log:            slogDiscard(),
	}
}

// t08FlightWaiters reports the open flight's waiter count, or -1 if absent.
func t08FlightWaiters(pf *partitionFlights, key string) int64 {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	f, ok := pf.flights[key]
	if !ok {
		return -1
	}
	return f.waiters.Load()
}

// t08GrantLease hands the flight's leadership mandate to whoever is parked,
// deterministically — no dependence on wall-clock lease ticks.
func t08GrantLease(t *testing.T, pf *partitionFlights, key string) {
	t.Helper()
	pf.mu.Lock()
	defer pf.mu.Unlock()
	f, ok := pf.flights[key]
	require.True(t, ok, "flight for key must exist")
	select {
	case f.lease <- struct{}{}:
	default:
		t.Fatal("lease slot already occupied")
	}
}

func t08RequireMiss(t *testing.T, r t08Lookup, label string) {
	t.Helper()
	require.NoError(t, r.err, label)
	require.Nil(t, r.hit, "%s: want a miss, got %+v", label, r.hit)
}

func t08RequireHit(t *testing.T, r t08Lookup, wantData json.RawMessage, wantSource, label string) {
	t.Helper()
	require.NoError(t, r.err, label)
	require.NotNil(t, r.hit, label)
	require.Equal(t, wantSource, r.hit.SourceType, label)
	require.JSONEq(t, string(wantData), string(r.hit.Data), label)
}

// ---------------------------------------------------------------------------
// Axis A (flight level): an interrupted singleflight participant loses
// nothing and multiplies nothing; its retry rejoins the still-open load.
// ---------------------------------------------------------------------------

func TestN03P5T08_EmbedFlightParticipantInterruptedRetrySharesLoad(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{0.5, 0.25}, gate: make(chan struct{}), entered: make(chan struct{})}
	ef := newEmbedFlights(4, 5*time.Second)
	const hash = "t08-embed-recovery-hash"

	type res struct {
		vec []float32
		err error
	}
	p1c, p2c, ac, rc := make(chan res, 1), make(chan res, 1), make(chan res, 1), make(chan res, 1)
	do := func(ctx context.Context, c chan res) {
		v, err := ef.do(ctx, hash, func(c context.Context) ([]float32, error) { return emb.Embed(c, "text") })
		c <- res{vec: v, err: err}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); do(context.Background(), p1c) }()
	go func() { defer wg.Done(); do(context.Background(), p2c) }()

	<-emb.entered // leader is inside the shared load
	waitFor(t, func() bool { return ef.waiting(hash) == 1 }, 2*time.Second)

	// Participant A joins, then is interrupted mid-round.
	actx, acancel := context.WithCancel(context.Background())
	var aLeft atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		do(actx, ac)
		aLeft.Store(true)
	}()
	waitFor(t, func() bool { return ef.waiting(hash) == 2 }, 2*time.Second)
	acancel()
	waitFor(t, func() bool { return aLeft.Load() }, 2*time.Second) // prompt local abort

	// A's retry (fresh context, same hash) rejoins the still-open load —
	// it must NOT trigger a second upstream call.
	wg.Add(1)
	go func() { defer wg.Done(); do(context.Background(), rc) }()
	waitFor(t, func() bool { return ef.waiting(hash) == 2 }, 2*time.Second)
	require.EqualValues(t, 1, emb.calls.Load(), "upstream calls while round open")

	close(emb.gate)
	wg.Wait()

	var p1, p2, retry res
	var a res
	for _, c := range []struct {
		ch   chan res
		out  *res
		name string
	}{{p1c, &p1, "p1"}, {p2c, &p2, "p2"}, {ac, &a, "interrupted"}, {rc, &retry, "retry"}} {
		select {
		case r := <-c.ch:
			*c.out = r
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no result", c.name)
		}
	}

	require.Equal(t, emb.vec, p1.vec)
	require.Equal(t, emb.vec, p2.vec)
	require.Equal(t, emb.vec, retry.vec)
	require.ErrorIs(t, a.err, context.Canceled)
	require.Nil(t, a.vec)
	require.EqualValues(t, 1, emb.calls.Load(), "interrupted participant + retry multiplied the upstream load")
	waitFor(t, func() bool { return ef.active() == 0 }, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Axis A+D (service level): a cancelled waiter's retry rejoins the same
// round; the round serves everyone from ONE upstream load.
// ---------------------------------------------------------------------------

func TestN03P5T08_WaiterCancelResumeRejoinsRoundNoExtraUpstream(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-t08-resume", Model: "gpt-4o"}.Resolved()
	body := stampedePrompt()
	hash := ComputePromptHash(normalizeForCache(body))
	key := MakeKey(ri.OrgID, ri.Model, hash)
	gen1 := json.RawMessage(`{"gen":"gen1"}`)
	sealed, err := SealEntry(gen1, ri)
	require.NoError(t, err)

	store := &t08SequencedStore{gated: 1, gate: make(chan struct{}), entry: &Entry{Response: sealed}}
	cs := newPartitionPgGateService(t, store, newPartitionFlights(8, 10*time.Second, 300*time.Millisecond))

	var wg sync.WaitGroup
	l1c, w1c, w1rc, w2c := make(chan t08Lookup, 1), make(chan t08Lookup, 1), make(chan t08Lookup, 1), make(chan t08Lookup, 1)
	lookup := func(ctx context.Context, c chan t08Lookup) {
		hit, err := cs.LookupWithResult(ctx, ri, body)
		c <- t08Lookup{hit: hit, err: err}
	}

	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), l1c) }()
	waitFor(t, func() bool { return store.enteredCount() == 1 }, 2*time.Second) // leader mid-load, cooldown armed

	// W1 joins, then is interrupted mid-wait: a prompt local miss.
	w1ctx, w1cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() { defer wg.Done(); lookup(w1ctx, w1c) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)
	w1cancel()

	// W1's retry resumes into the SAME round (fresh context, same key).
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w1rc) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)
	// W2 joins the same round.
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w2c) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 2 }, 2*time.Second)

	// The gateway's upstream answer lands: Write is the publication seam.
	// Publish precedes Put (T04 ordering): on a partitioned backend the Put
	// fails and Write reports it, yet the coalesced waiters are served.
	werr := cs.Write(context.Background(), ri, body, gen1, 10, 5)
	require.Error(t, werr, "Write against the refused backend must report the failed Put")
	// The leader's own pg-exact load completes after the publication.
	close(store.gate)
	wg.Wait()

	var l1, w1, w1r, w2 t08Lookup
	for _, c := range []struct {
		ch   chan t08Lookup
		out  *t08Lookup
		name string
	}{{l1c, &l1, "leader"}, {w1c, &w1, "interrupted waiter"}, {w1rc, &w1r, "resumed retry"}, {w2c, &w2, "waiter"}} {
		select {
		case r := <-c.ch:
			*c.out = r
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no result", c.name)
		}
	}

	t08RequireHit(t, l1, gen1, "pg_exact", "leader")
	t08RequireMiss(t, w1, "interrupted waiter")
	t08RequireHit(t, w1r, gen1, "exact", "resumed retry (round member)")
	t08RequireHit(t, w2, gen1, "exact", "waiter")
	require.EqualValues(t, 1, store.calls.Load(), "resume must not multiply the upstream load")
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second) // publish freed the slot

	// A fresh lookup after the round cleared starts a NEW bounded round —
	// it must not be served the already-published payload again.
	l2c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), l2c) }()
	var l2 t08Lookup
	select {
	case l2 = <-l2c:
	case <-time.After(2 * time.Second):
		t.Fatal("post-round lookup: no result")
	}
	wg.Wait()
	t08RequireMiss(t, l2, "fresh lookup after the round cleared")
	require.EqualValues(t, 2, store.calls.Load(), "exactly one new leadership load after the round cleared")
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 5*time.Second) // ttl dissolves the leaderless flight
}

// ---------------------------------------------------------------------------
// Axis B (REAL Redis): invalidation completing while a round is still open —
// round members may receive the published payload (documented bounded
// overlap), but after the table clears nothing serves the invalidated
// generation, and recovery re-probes the real backend.
// ---------------------------------------------------------------------------

func TestN03P5T08_InvalidationMidResumeNoStaleServeAfterTableClears(t *testing.T) {
	rdb := redisContainer(t)
	hook := &t08RedisHook{remaining: map[string]int{"get": 1}, injected: errors.New("t08 injected exact-layer outage")}
	rdb.AddHook(hook)

	ri := RouteIdentity{OrgID: "org-t08-inval-resume", Model: "gpt-4o"}.Resolved()
	body := stampedePrompt()
	hash := ComputePromptHash(normalizeForCache(body))
	key := MakeKey(ri.OrgID, ri.Model, hash)

	// The round key holds a stale generation: a sweep that fails to delete
	// it would surface as a stale recovery hit below.
	staleSealed, err := SealEntry(json.RawMessage(`{"gen":"stale-gen0"}`), ri)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(context.Background(), key, staleSealed, time.Minute).Err())
	extras := seedKeys(t, rdb, ri.OrgID, ri.Model, 2)

	store := &t08SequencedStore{} // every pg call is a miss: the leader misses, upstream answers via Write
	cs := t08Service(t, rdb, store, 10*time.Second, 2*time.Second)

	basePartitions := testutil.ToFloat64(CacheRedisPartitionTotal)
	baseCoalesced := testutil.ToFloat64(CachePartitionCoalescedTotal)

	var wg sync.WaitGroup
	lookup := func(ctx context.Context, c chan t08Lookup) {
		hit, err := cs.LookupWithResult(ctx, ri, body)
		c <- t08Lookup{hit: hit, err: err}
	}
	l1c, w1c, w2c, w2rc := make(chan t08Lookup, 1), make(chan t08Lookup, 1), make(chan t08Lookup, 1), make(chan t08Lookup, 1)

	// Round 1 under a partitioned exact layer (hook fails the first get).
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), l1c) }()
	waitFor(t, func() bool { return testutil.ToFloat64(CacheRedisPartitionTotal) > basePartitions }, 2*time.Second)
	// Deterministic cooldown for the rest of the scenario (in-package, same
	// manipulation the T05 tests use on redisDownUntil).
	cs.redisDownUntil.Store(time.Now().Add(30 * time.Second).UnixNano())

	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w1c) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)
	w2ctx, w2cancel := context.WithCancel(context.Background())
	var w2Left atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		lookup(w2ctx, w2c)
		w2Left.Store(true)
	}()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 2 }, 2*time.Second)
	w2cancel()
	waitFor(t, func() bool { return w2Left.Load() }, 2*time.Second)

	// W2's retry resumes while the round is still open — BEFORE any
	// invalidation: this is the interrupted→resumed participant.
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w2rc) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 2 }, 2*time.Second)

	// The invalidation completes mid-round: every stored generation for the
	// org (including the stale seed) is really gone from Redis.
	inv := NewInvalidator(cs.exact, nil, rdb)
	require.NoError(t, inv.InvalidateOrgAll(context.Background(), ri.OrgID))
	require.Zero(t, countExisting(t, rdb, append([]string{key}, extras...)), "completed invalidation left keys behind")
	scans, _ := hook.watched()
	require.Equal(t, 1, scans, "complete invalidation must need exactly one sweep")

	// The gateway's upstream answer lands AFTER the invalidation: Write
	// publishes to the round and re-stores the (now post-invalidation)
	// response — the documented put-after-invalidate class.
	gen1 := json.RawMessage(`{"gen":"gen1"}`)
	require.NoError(t, cs.Write(context.Background(), ri, body, gen1, 10, 5))
	wg.Wait()

	var l1, w1, w2, w2r t08Lookup
	for _, c := range []struct {
		ch   chan t08Lookup
		out  *t08Lookup
		name string
	}{{l1c, &l1, "leader"}, {w1c, &w1, "waiter"}, {w2c, &w2, "interrupted"}, {w2rc, &w2r, "resumed retry"}} {
		select {
		case r := <-c.ch:
			*c.out = r
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no result", c.name)
		}
	}
	t08RequireMiss(t, l1, "leader (upstream answer returned via Write)")
	t08RequireHit(t, w1, gen1, "exact", "round member served the round's payload")
	t08RequireMiss(t, w2, "interrupted participant")
	t08RequireHit(t, w2r, gen1, "exact", "resumed retry served its round's payload (documented bounded overlap)")

	require.EqualValues(t, 1, store.calls.Load(), "one leadership load for the whole round")
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second) // publish freed the slot

	// After the table cleared: a fresh partitioned round must NOT be served
	// the invalidated generation through any layer.
	w3c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w3c) }()
	var w3 t08Lookup
	select {
	case w3 = <-w3c:
	case <-time.After(2 * time.Second):
		t.Fatal("post-clear lookup: no result")
	}
	wg.Wait()
	t08RequireMiss(t, w3, "post-invalidation fresh round served the invalidated generation")
	require.EqualValues(t, 2, store.calls.Load())
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 5*time.Second)

	// Recovery: the cooldown expires, the real backend is re-probed. The
	// Write above legitimately re-stored gen1, so recovery serves exactly
	// what the backend holds — no invented payloads, no lost generations.
	cs.redisDownUntil.Store(1)
	w4c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w4c) }()
	var w4 t08Lookup
	select {
	case w4 = <-w4c:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery lookup: no result")
	}
	wg.Wait()
	t08RequireHit(t, w4, gen1, "exact", "recovered backend re-probe")
	require.EqualValues(t, 2, store.calls.Load(), "recovery re-probe must not re-enter the pg layer")

	// Recovery converges: the next invalidation really clears the
	// re-stored generation and the following lookup is a clean miss.
	require.NoError(t, inv.InvalidateOrgAll(context.Background(), ri.OrgID))
	require.Zero(t, countExisting(t, rdb, []string{key}))
	w5c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w5c) }()
	var w5 t08Lookup
	select {
	case w5 = <-w5c:
	case <-time.After(2 * time.Second):
		t.Fatal("post-recovery-invalidation lookup: no result")
	}
	wg.Wait()
	t08RequireMiss(t, w5, "recovery converged to a clean miss")
	require.EqualValues(t, 3, store.calls.Load())

	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != basePartitions+5 {
		t.Fatalf("partitioned lookups = %v, want 5 (leader + 3 round members + one fresh round)", got-basePartitions)
	}
	if got := testutil.ToFloat64(CachePartitionCoalescedTotal); got != baseCoalesced+2 {
		t.Fatalf("coalesced serves = %v, want 2 (waiter + resumed retry)", got-baseCoalesced)
	}
}

// ---------------------------------------------------------------------------
// Axis B (flight level): a retry arriving at the TTL-dissolve boundary never
// wedges and never resurrects a payload; the key stays acquirable.
// ---------------------------------------------------------------------------

func TestN03P5T08_FlightTTLBoundaryRetryHammerNoWedge(t *testing.T) {
	pf := newPartitionFlights(8, 25*time.Millisecond, 60*time.Millisecond)
	const rounds = 8

	await := func(key string) ([]byte, bool, error) {
		type out struct {
			payload []byte
			pub     bool
			err     error
		}
		c := make(chan out, 1)
		go func() {
			p, b := pf.await(context.Background(), key)
			c <- out{p, b, nil}
		}()
		select {
		case r := <-c:
			return r.payload, r.pub, r.err
		case <-time.After(3 * time.Second):
			return nil, false, fmt.Errorf("await(%s) wedged past the bounded window", key)
		}
	}

	retriesAsLeader := 0
	for r := 0; r < rounds; r++ {
		key := fmt.Sprintf("t08-ttl-round-%d", r)
		payload, published, err := await(key) // creator: the (abandoning) leader
		require.NoError(t, err)
		require.False(t, published)
		require.Nil(t, payload)

		// Retry arrives mid-TTL, before the dissolve: it must complete
		// promptly with either the mandate (proceed) or the dissolved miss
		// — never a payload (the leader never publishes), never an error,
		// never a wedge.
		rPayload, rPublished, rErr := await(key)
		require.NoError(t, rErr, "round %d: TTL-boundary retry errored", r)
		require.Nil(t, rPayload, "round %d: retry received a payload from a never-publishing leader", r)
		if rPublished {
			retriesAsLeader++
		}

		waitFor(t, func() bool { return pf.active() == 0 },
			3*time.Second) // the zombie dissolves at its TTL; the slot frees
	}
	require.LessOrEqual(t, retriesAsLeader, rounds, "mandates exceeded one per flight")

	// The lock is provably free: a fresh flight is creatable AND publishable.
	const finalKey = "t08-ttl-final"
	fPayload, fPublished, fErr := await(finalKey)
	require.NoError(t, fErr)
	require.False(t, fPublished)
	require.Nil(t, fPayload)

	waiterDone := make(chan []byte, 1)
	go func() {
		p, _ := pf.await(context.Background(), finalKey)
		waiterDone <- p
	}()
	waitFor(t, func() bool { return t08FlightWaiters(pf, finalKey) == 1 }, 2*time.Second)
	pf.publish(finalKey, []byte(`{"gen":"final"}`))
	select {
	case p := <-waiterDone:
		require.NotNil(t, p, "final waiter was not served the published payload")
		require.JSONEq(t, `{"gen":"final"}`, string(p))
	case <-time.After(2 * time.Second):
		t.Fatal("final waiter: no result")
	}
	waitFor(t, func() bool { return pf.active() == 0 }, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Axis C (REAL Redis): a partition that ends mid-stampede converges with a
// bounded fallback, one completing invalidation retry, and no lost result.
// ---------------------------------------------------------------------------

func TestN03P5T08_ReconnectDuringStampedeBoundedFallbackSingleInvalidationRetry(t *testing.T) {
	rdb := redisContainer(t)
	hook := &t08RedisHook{
		remaining: map[string]int{"get": 1, "scan": 1},
		injected:  errors.New("t08 injected partition flap"),
	}
	rdb.AddHook(hook)

	ri := RouteIdentity{OrgID: "org-t08-reconnect", Model: "gpt-4o"}.Resolved()
	body := stampedePrompt()
	hash := ComputePromptHash(normalizeForCache(body))
	key := MakeKey(ri.OrgID, ri.Model, hash)
	extras := seedKeys(t, rdb, ri.OrgID, ri.Model, 3)

	store := &t08SequencedStore{}
	cs := t08Service(t, rdb, store, 10*time.Second, 10*time.Second)

	basePartitions := testutil.ToFloat64(CacheRedisPartitionTotal)
	baseCoalesced := testutil.ToFloat64(CachePartitionCoalescedTotal)

	var wg sync.WaitGroup
	lookup := func(c chan t08Lookup) {
		hit, err := cs.LookupWithResult(context.Background(), ri, body)
		c <- t08Lookup{hit: hit, err: err}
	}

	// The stampede: one leader plus eleven coalesced identical lookups while
	// the exact layer is believed partitioned.
	const waiters = 11
	l1c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(l1c) }()
	waitFor(t, func() bool { return testutil.ToFloat64(CacheRedisPartitionTotal) > basePartitions }, 2*time.Second)

	wcs := make([]chan t08Lookup, waiters)
	for i := range wcs {
		wcs[i] = make(chan t08Lookup, 1)
		wg.Add(1)
		go func(c chan t08Lookup) { defer wg.Done(); lookup(c) }(wcs[i])
	}
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == waiters }, 2*time.Second)

	// The invalidation runs DURING the partition window; its first sweep
	// dies mid-SCAN (the flap) — the failure must be observable and retryable,
	// with nothing deleted and no silent success.
	inv := NewInvalidator(cs.exact, nil, rdb)
	err := inv.InvalidateOrgAll(context.Background(), ri.OrgID)
	require.Error(t, err)
	var ie *InvalidationError
	require.ErrorAs(t, err, &ie)
	require.True(t, ie.ScanIncomplete, "a mid-SCAN death must be reported as scan-incomplete")
	require.True(t, IsRetryable(context.Background(), err), "the flap must be classified retryable")
	all := append([]string{key}, extras...)
	// The flap died mid-SCAN: everything that existed before (the 3 seeds)
	// must still exist; the round key was never stored.
	require.EqualValues(t, len(extras), countExisting(t, rdb, all), "incomplete sweep deleted keys anyway")
	scans, _ := hook.watched()
	require.Equal(t, 1, scans)

	// The upstream answer lands: Write coalesces the whole round and re-stores
	// the response on the (already healthy again) backend.
	gen1 := json.RawMessage(`{"gen":"gen1"}`)
	require.NoError(t, cs.Write(context.Background(), ri, body, gen1, 10, 5))
	wg.Wait()

	var l1 t08Lookup
	select {
	case l1 = <-l1c:
	case <-time.After(2 * time.Second):
		t.Fatal("leader: no result")
	}
	t08RequireMiss(t, l1, "leader")
	for i, c := range wcs {
		select {
		case r := <-c:
			t08RequireHit(t, r, gen1, "exact", fmt.Sprintf("waiter %d", i))
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d: no result", i)
		}
	}
	require.EqualValues(t, 1, store.calls.Load(), "stampede of 12 must cost exactly one leadership load")
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != basePartitions+12 {
		t.Fatalf("partitioned lookups = %v, want 12 (leader + 11 waiters)", got-basePartitions)
	}
	if got := testutil.ToFloat64(CachePartitionCoalescedTotal); got != baseCoalesced+waiters {
		t.Fatalf("coalesced serves = %v, want %d", got-baseCoalesced, waiters)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)

	// Reconnect: ONE retry completes the invalidation — no storm, no residue.
	// The completing sweep legitimately deletes the gen1 that was written
	// before it (invalidation-after-write wins); recovery must reflect that.
	hook.disarm()
	require.NoError(t, inv.InvalidateOrgAll(context.Background(), ri.OrgID))
	require.Zero(t, countExisting(t, rdb, all), "completing retry left keys behind")
	scans, _ = hook.watched()
	require.Equal(t, 2, scans, "exactly one completing sweep retry — no invalidation storm")

	// Recovery re-probe with a result: the post-reconnect Write lands on the
	// healthy backend and the fresh lookup is served it with ZERO additional
	// upstream cost. A partitioned lookup could not serve gen2 (the pg layer
	// has no such entry), so the hit proves the real backend was re-probed.
	gen2 := json.RawMessage(`{"gen":"gen2"}`)
	require.NoError(t, cs.Write(context.Background(), ri, body, gen2, 10, 5))
	cs.redisDownUntil.Store(1)
	wrc := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(wrc) }()
	var wr t08Lookup
	select {
	case wr = <-wrc:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery lookup: no result")
	}
	wg.Wait()
	t08RequireHit(t, wr, gen2, "exact", "recovery re-probe serves the recovered backend")
	require.EqualValues(t, 1, store.calls.Load(), "recovery must not re-enter the upstream layers")
	if got := testutil.ToFloat64(CacheRedisPartitionTotal); got != basePartitions+12 {
		t.Fatalf("partitioned lookups = %v, want 12 — the recovery re-probe must not run through the partition branch", got-basePartitions)
	}
}

// ---------------------------------------------------------------------------
// Axis D (REAL Redis): the lease-mandate holder cancels mid-upstream; the
// shared round, the other participants and the lock all survive — the lock
// freedom is proven by a fresh acquire + publish.
// ---------------------------------------------------------------------------

func TestN03P5T08_MandateHolderCancelIsolation_BServedLockFreedByAcquire(t *testing.T) {
	rdb := redisContainer(t)
	hook := &t08RedisHook{remaining: map[string]int{"get": 1}, injected: errors.New("t08 injected exact-layer outage")}
	rdb.AddHook(hook)

	ri := RouteIdentity{OrgID: "org-t08-mandate", Model: "gpt-4o"}.Resolved()
	body := stampedePrompt()
	hash := ComputePromptHash(normalizeForCache(body))
	key := MakeKey(ri.OrgID, ri.Model, hash)
	gen1 := json.RawMessage(`{"gen":"gen1"}`)
	sealed, err := SealEntry(gen1, ri)
	require.NoError(t, err)

	// Call#1 = leader (parks, returns the entry), call#2 = mandate holder
	// (parks cancellably on ITS OWN context).
	store := &t08SequencedStore{gated: 2, gate: make(chan struct{}), entry: &Entry{Response: sealed}}
	// Long lease window: the mandate is granted deterministically below; no
	// timer can hand out a second one mid-scenario.
	cs := t08Service(t, rdb, store, 10*time.Second, 600*time.Millisecond)

	baseLeases := testutil.ToFloat64(CachePartitionLeasesTotal)
	baseCoalesced := testutil.ToFloat64(CachePartitionCoalescedTotal)

	var wg sync.WaitGroup
	lookup := func(ctx context.Context, c chan t08Lookup) {
		hit, err := cs.LookupWithResult(ctx, ri, body)
		c <- t08Lookup{hit: hit, err: err}
	}
	l1c, w1c, w2c := make(chan t08Lookup, 1), make(chan t08Lookup, 1), make(chan t08Lookup, 1)

	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), l1c) }()
	waitFor(t, func() bool { return store.enteredCount() == 1 }, 2*time.Second)

	// W1 joins with a cancellable context — it will hold the mandate next.
	w1ctx, w1cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() { defer wg.Done(); lookup(w1ctx, w1c) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)

	// The leadership mandate moves to W1: it proceeds into its own upstream
	// attempt (store call#2) while the leader's load continues untouched.
	t08GrantLease(t, cs.partition, key)
	waitFor(t, func() bool { return store.enteredCount() == 2 }, 2*time.Second)

	// A (the mandate holder) is interrupted mid-upstream: it escapes on its
	// own context, promptly, with its own cancellation. The leader's load
	// and the flight are untouched.
	w1cancel()
	var w1 t08Lookup
	select {
	case w1 = <-w1c:
	case <-time.After(2 * time.Second):
		t.Fatal("mandate holder: cancel did not release it in time")
	}
	require.ErrorIs(t, w1.err, context.Canceled, "mandate holder must escape with its own cancellation")
	require.Nil(t, w1.hit)

	// B joins the still-open round while A's attempt is already gone.
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), w2c) }()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)

	// The leader's load completes: publish serves B; the leader itself is
	// served from the pg-exact layer.
	close(store.gate)
	wg.Wait()

	var l1, w2 t08Lookup
	for _, c := range []struct {
		ch   chan t08Lookup
		out  *t08Lookup
		name string
	}{{l1c, &l1, "leader"}, {w2c, &w2, "waiter B"}} {
		select {
		case r := <-c.ch:
			*c.out = r
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no result", c.name)
		}
	}
	t08RequireHit(t, l1, gen1, "pg_exact", "leader (A's cancel did not abort its load)")
	t08RequireHit(t, w2, gen1, "exact", "waiter B served by the publish")
	require.EqualValues(t, 2, store.calls.Load(), "leader load + cancelled mandate attempt, nothing more")
	if got := testutil.ToFloat64(CachePartitionLeasesTotal); got != baseLeases+1 {
		t.Fatalf("mandates granted = %v, want exactly 1", got-baseLeases)
	}
	if got := testutil.ToFloat64(CachePartitionCoalescedTotal); got != baseCoalesced+1 {
		t.Fatalf("coalesced serves = %v, want exactly 1", got-baseCoalesced)
	}
	_, gets := hook.watched()
	require.Equal(t, 1, gets, "only the leader probed the exact layer before the cooldown")

	// Lock freedom, proven by a fresh acquire: a new lookup creates its own
	// flight, completes, and the slot frees at the TTL.
	l2c := make(chan t08Lookup, 1)
	wg.Add(1)
	go func() { defer wg.Done(); lookup(context.Background(), l2c) }()
	var l2 t08Lookup
	select {
	case l2 = <-l2c:
	case <-time.After(2 * time.Second):
		t.Fatal("fresh acquire: no result")
	}
	wg.Wait()
	t08RequireMiss(t, l2, "fresh acquire after the round")
	require.EqualValues(t, 3, store.calls.Load(), "fresh acquire costs exactly one new leadership load")
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 5*time.Second)

	// Direct acquire+publish on the same key: the lock is free and usable.
	ldrPayload, ldrPublished := cs.partition.await(context.Background(), key)
	require.False(t, ldrPublished)
	require.Nil(t, ldrPayload)
	proofDone := make(chan []byte, 1)
	go func() {
		p, _ := cs.partition.await(context.Background(), key)
		proofDone <- p
	}()
	waitFor(t, func() bool { return t08FlightWaiters(cs.partition, key) == 1 }, 2*time.Second)
	cs.partition.publish(key, sealed)
	select {
	case p := <-proofDone:
		require.NotNil(t, p, "acquire proof: waiter not served")
	case <-time.After(2 * time.Second):
		t.Fatal("acquire proof: no result")
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}
