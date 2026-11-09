package cache

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

// flightEmbedder is a controllable embeddings.Client stub for the stampede
// guard tests: it counts upstream calls and can block every call on a gate.
type flightEmbedder struct {
	calls atomic.Int64
	vec   []float32
	err   error

	// ctxAware makes Embed return early on its OWN context cancellation —
	// used to prove the shared load is detached from caller contexts.
	ctxAware bool
	// gate, when non-nil, blocks every Embed call until it is closed.
	gate chan struct{}
	// entered, when non-nil, is closed when the first Embed call starts.
	entered chan struct{}
}

func (e *flightEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	if e.calls.Add(1) == 1 && e.entered != nil {
		close(e.entered)
	}
	if e.gate != nil {
		if e.ctxAware {
			select {
			case <-e.gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			<-e.gate
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	return append([]float32(nil), e.vec...), nil
}

// waitFor polls cond until it holds or the timeout elapses.
func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

// N03-P05-T02 acceptance: a stampede of identical prompts shares ONE
// upstream embedding call, and the flight table is cleaned afterwards.
func TestEmbedFlights_ConcurrentIdenticalHashesShareOneUpstreamCall(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{0.25, 0.5}, gate: make(chan struct{}), entered: make(chan struct{})}
	ef := newEmbedFlights(8, 5*time.Second)

	const callers = 16
	type result struct {
		vec []float32
		err error
	}
	results := make([]result, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := ef.do(context.Background(), "same-hash", func(c context.Context) ([]float32, error) {
				return emb.Embed(c, "text")
			})
			results[i] = result{vec: v, err: err}
		}(i)
	}

	// Deterministic join point: callers = 1 starter (inside fn) + 15 waiters.
	// Wait for the leader to ENTER fn first (entered closes on the first
	// Embed call): waiting only on the waiter count races the leader's fn
	// entry under load — the flight exists (waiters park) while the leader is
	// still descheduled between flight creation and the Embed call.
	<-emb.entered
	waitFor(t, func() bool { return ef.waiting("same-hash") == callers-1 }, 2*time.Second)

	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream embedding calls while joined = %d, want 1", got)
	}
	close(emb.gate)
	wg.Wait()

	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream embedding calls after completion = %d, want 1 (stampede multiplied calls)", got)
	}
	if ef.active() != 0 {
		t.Fatalf("flight table not cleaned after completion: %d entries remain", ef.active())
	}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("caller %d: unexpected error: %v", i, r.err)
		}
		if len(r.vec) != 2 || r.vec[0] != 0.25 || r.vec[1] != 0.5 {
			t.Fatalf("caller %d: unexpected vector %v", i, r.vec)
		}
	}
}

// N03-P05-T02 acceptance: the configured limit is hard — lookups beyond it
// degrade to ErrEmbedFlightBusy (a cache miss upstream of the provider)
// without multiplying upstream calls; the slot frees up afterwards.
func TestEmbedFlights_LimitDegradesOverflowToBusyWithoutUpstreamCall(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{1}, gate: make(chan struct{})}
	ef := newEmbedFlights(2, 5*time.Second)

	var wg sync.WaitGroup
	for _, h := range []string{"a", "b"} {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			_, _ = ef.do(context.Background(), h, func(c context.Context) ([]float32, error) {
				return emb.Embed(c, h)
			})
		}(h)
	}
	waitFor(t, func() bool { return ef.active() == 2 }, 2*time.Second)
	// Join point: wait until BOTH leaders have entered the embedder before
	// probing the overflow. active()==2 proves only that the table slots
	// exist (inserted by the callers under the mutex, embed_flight.go), while
	// each load runs in a goroutine spawned at do() that still has its
	// timeout/timer setup ahead of the fn call — under suite load a leader
	// can sit descheduled there, and the calls assertion below then races it
	// (calls==1 observed; repro: full -race -shuffle suite under machine
	// load). The stub increments calls as its first Embed action and then
	// parks on the unclosed gate, so calls==2 means both loads are parked
	// in-flight; the slots cannot free before close(gate) below. e37f14a
	// pinned the single-leader sibling via its `entered` channel; this test
	// has two leaders and no such channel — calls==2 is the exact join.
	waitFor(t, func() bool { return emb.calls.Load() == 2 }, 2*time.Second)

	vec, err := ef.do(context.Background(), "c", func(c context.Context) ([]float32, error) {
		return emb.Embed(c, "c")
	})
	if !errors.Is(err, ErrEmbedFlightBusy) {
		t.Fatalf("overflow hash: err = %v, want ErrEmbedFlightBusy", err)
	}
	if vec != nil {
		t.Fatalf("overflow hash returned a vector %v", vec)
	}
	if got := emb.calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (overflow must not make a call)", got)
	}

	close(emb.gate)
	wg.Wait()
	waitFor(t, func() bool { return ef.active() == 0 }, 2*time.Second)

	// With the limit freed, the same hash is admitted again.
	v, err := ef.do(context.Background(), "c", func(c context.Context) ([]float32, error) {
		return emb.Embed(c, "c")
	})
	if err != nil || len(v) != 1 || v[0] != 1 {
		t.Fatalf("post-limit lookup: v=%v err=%v, want [1] nil", v, err)
	}
	// do() only returns after the fresh load completed, and each admitted
	// load enters the embedder exactly once: 2 parked leaders + 1 fresh call.
	if got := emb.calls.Load(); got != 3 {
		t.Fatalf("post-limit upstream calls = %d, want 3 (re-admitted hash must call exactly once)", got)
	}
}

// N03-P05-T02 negative scenario: a waiter's cancellation returns only that
// waiter a miss — the shared load, its callers and the flight entry are
// untouched; the entry is removed once the load completes (no lock left).
func TestEmbedFlights_WaiterCancelMissesLocallyAndLeavesNoFlight(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{1, 1}, gate: make(chan struct{}), entered: make(chan struct{})}
	ef := newEmbedFlights(4, 5*time.Second)

	starterDone := make(chan error, 1)
	go func() {
		_, err := ef.do(context.Background(), "h", func(c context.Context) ([]float32, error) {
			return emb.Embed(c, "text")
		})
		starterDone <- err
	}()
	<-emb.entered

	bctx, bcancel := context.WithCancel(context.Background())
	defer bcancel()
	bDone := make(chan error, 1)
	go func() {
		_, err := ef.do(bctx, "h", func(c context.Context) ([]float32, error) {
			return emb.Embed(c, "text")
		})
		bDone <- err
	}()
	waitFor(t, func() bool { return ef.waiting("h") == 1 }, 2*time.Second)

	bcancel()
	select {
	case err := <-bDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter did not return promptly")
	}

	// The shared load and the starter are untouched by B's cancellation.
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls after waiter cancel = %d, want 1", got)
	}
	if ef.active() != 1 {
		t.Fatalf("flight dropped after waiter cancel: active = %d", ef.active())
	}

	close(emb.gate)
	if err := <-starterDone; err != nil {
		t.Fatalf("starter failed: %v", err)
	}
	waitFor(t, func() bool { return ef.active() == 0 }, 2*time.Second)
}

// N03-P05-T02 negative scenario, starter side: the FIRST caller's
// cancellation must not abort the shared load a later caller joined.
func TestEmbedFlights_StarterCancelDoesNotAbortSharedLoad(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{2}, gate: make(chan struct{}), entered: make(chan struct{}), ctxAware: true}
	ef := newEmbedFlights(4, 5*time.Second)

	actx, acancel := context.WithCancel(context.Background())
	aDone := make(chan error, 1)
	go func() {
		_, err := ef.do(actx, "h", func(c context.Context) ([]float32, error) {
			return emb.Embed(c, "text")
		})
		aDone <- err
	}()
	<-emb.entered

	acancel()
	select {
	case err := <-aDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled starter err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled starter did not return promptly")
	}

	// A late caller joins the still-running load.
	type cRes struct {
		vec []float32
		err error
	}
	cDone := make(chan cRes, 1)
	go func() {
		v, err := ef.do(context.Background(), "h", func(c context.Context) ([]float32, error) {
			return emb.Embed(c, "text")
		})
		cDone <- cRes{vec: v, err: err}
	}()
	waitFor(t, func() bool { return ef.waiting("h") == 1 }, 2*time.Second)

	close(emb.gate)
	select {
	case r := <-cDone:
		if r.err != nil {
			t.Fatalf("late joiner failed: %v", r.err)
		}
		if len(r.vec) != 1 || r.vec[0] != 2 {
			t.Fatalf("late joiner vector = %v, want [2]", r.vec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late joiner did not complete after gate release")
	}

	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls after starter cancel = %d, want 1 (load was aborted or restarted)", got)
	}
	waitFor(t, func() bool { return ef.active() == 0 }, 2*time.Second)
}

// A failed flight is shared to its joiners and removed from the table;
// a SEQUENTIAL repeat is a fresh call (no result cache — unchanged semantics).
func TestEmbedFlights_UpstreamFailureSharedAndSequentialRetries(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder down")}
	ef := newEmbedFlights(4, time.Second)

	for i := 0; i < 2; i++ {
		v, err := ef.do(context.Background(), "h", func(c context.Context) ([]float32, error) {
			return emb.Embed(c, "text")
		})
		if err == nil {
			t.Fatalf("call %d: want error", i)
		}
		if v != nil {
			t.Fatalf("call %d: want nil vector", i)
		}
		if ef.active() != 0 {
			t.Fatalf("call %d: failed flight left in table", i)
		}
	}
	if got := emb.calls.Load(); got != 2 {
		t.Fatalf("sequential calls = %d, want 2 (dedup is concurrent-window only)", got)
	}
}

// A nil group keeps the legacy direct-call behavior (partial CacheService
// constructions without the stampede guard).
func TestEmbedFlights_NilGroupDegradesToDirectCall(t *testing.T) {
	emb := &flightEmbedder{vec: []float32{3}}
	var ef *embedFlights
	v, err := ef.do(context.Background(), "h", func(c context.Context) ([]float32, error) {
		return emb.Embed(c, "text")
	})
	if err != nil || len(v) != 1 || v[0] != 3 {
		t.Fatalf("nil group direct call: v=%v err=%v", v, err)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

// N03-P05 review follow-up: a hung embedder that IGNORES its context must
// not wedge the flight table. The flight deadline releases the table slot
// although the abandoned load keeps running; a subsequent distinct-hash
// lookup is admitted again, and the busy counter stays honest — only
// lookups degraded WHILE the slot was held count as busy.
func TestEmbedFlights_TimeoutReleasesSlotWhenEmbedderIgnoresContext(t *testing.T) {
	// ctxAware=false: Embed blocks on the gate deaf to its load context —
	// only the flight deadline can end the slot occupation.
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond})
	// Deadline 1s: comfortably after the overflow lookup below arrives
	// (exact.Get on a refused port + in-memory policy ≈ a few ms), so the
	// busy phase is deterministic; waitFor bounds the release phase.
	cs := &CacheService{
		exact:       NewRedisStore(rdb, 24*time.Hour),
		policy:      pc,
		embedder:    emb,
		embedFlight: newEmbedFlights(1, 1*time.Second), // short injected deadline
		log:         slog.New(slog.DiscardHandler),
	}

	// The starter occupies the only slot and stays there: the embedder
	// ignores the flight's deadline context entirely.
	starterDone := make(chan error, 1)
	go func() {
		_, err := cs.LookupWithResult(context.Background(), RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"messages":[{"role":"user","content":"alpha"}]}`))
		starterDone <- err
	}()
	waitFor(t, func() bool { return cs.embedFlight.active() == 1 }, 2*time.Second)
	// Join point, same class as the LimitDegradesOverflow fix above:
	// active()==1 proves the starter's table slot, not that its spawned load
	// goroutine has entered the embedder yet. Wait for the entry (the stub
	// parks on the gate right after incrementing) so the busy probe below is
	// measured against a genuinely in-flight load and the calls assertion is
	// not racing a descheduled leader. Bounded below the injected 1s flight
	// deadline so a starved scheduler degrades to a prompt, honest failure
	// instead of outliving the slot this test assumes is held.
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 500*time.Millisecond)

	// While the slot is held, a distinct hash is honestly busy: degraded to
	// a miss, counted, and no upstream call for it. The caller context is
	// bounded so a pathological pause degrades to a fast assertion failure,
	// never a hang.
	busyBefore := testutil.ToFloat64(CacheEmbedFlightBusyTotal)
	octx, ocancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer ocancel()
	hit, err := cs.LookupWithResult(octx, RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"messages":[{"role":"user","content":"beta"}]}`))
	if err != nil || hit != nil {
		t.Fatalf("overflow lookup: hit=%v err=%v, want nil nil", hit, err)
	}
	if busyAfter := testutil.ToFloat64(CacheEmbedFlightBusyTotal); busyAfter != busyBefore+1 {
		t.Fatalf("busy counter = %v, want %v+1 while the slot was held", busyAfter, busyBefore)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (overflow must not make a call)", got)
	}

	// The deadline passes: the slot frees although the embedder never
	// returned and never observed its context.
	waitFor(t, func() bool { return cs.embedFlight.active() == 0 }, 2*time.Second)

	// A subsequent distinct-hash lookup proceeds on the freed slot — no
	// busy degradation and no extra busy-counter bump for it.
	v, err := cs.embedFlight.do(context.Background(), "fresh-hash", func(context.Context) ([]float32, error) {
		return []float32{9}, nil
	})
	if err != nil || len(v) != 1 || v[0] != 9 {
		t.Fatalf("post-deadline lookup: v=%v err=%v, want [9] nil", v, err)
	}
	if busyAfter := testutil.ToFloat64(CacheEmbedFlightBusyTotal); busyAfter != busyBefore+1 {
		t.Fatalf("busy counter = %v after release, want unchanged %v+1 (post-deadline lookups are not busy)", busyAfter, busyBefore)
	}

	// Cleanup: unblock the abandoned load so its goroutine finishes; the
	// starter degrades to a miss (embedder error), never an error.
	close(emb.gate)
	if err := <-starterDone; err != nil {
		t.Fatalf("starter lookup returned an error: %v", err)
	}
	waitFor(t, func() bool { return cs.embedFlight.active() == 0 }, 2*time.Second)
}

// CacheService wiring: concurrent identical lookups route through one shared
// embedding flight (one upstream call), and the busy degradation is counted.
func TestCacheService_LookupStampedeDedupsEmbeddingCalls(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{}), entered: make(chan struct{})}
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond})
	cs := &CacheService{
		exact:       NewRedisStore(rdb, 24*time.Hour),
		policy:      pc,
		embedder:    emb,
		embedFlight: newEmbedFlights(1, 5*time.Second), // limit 1: the second distinct hash must degrade to busy
		log:         slog.New(slog.DiscardHandler),
	}

	const callers = 8
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The gated embedder fails, so every caller degrades to a miss
			// before the semantic lookup — (nil, nil) with no error.
			hit, err := cs.LookupWithResult(context.Background(), RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"messages":[{"role":"user","content":"alpha"}]}`))
			if err != nil || hit != nil {
				t.Errorf("lookup: hit=%v err=%v, want nil nil", hit, err)
			}
		}()
	}
	waitFor(t, func() bool { return emb.calls.Load() == 1 }, 2*time.Second)
	hash := ComputePromptHash(normalizeForCache([]byte(`{"messages":[{"role":"user","content":"alpha"}]}`)))
	waitFor(t, func() bool { return cs.embedFlight.waiting(hash) == callers-1 }, 2*time.Second)

	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream embedding calls = %d, want 1 (lookup stampede multiplied calls)", got)
	}

	// A distinct hash beyond the service limit degrades to busy + counter.
	busyBefore := testutil.ToFloat64(CacheEmbedFlightBusyTotal)
	_, err := cs.LookupWithResult(context.Background(), RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"messages":[{"role":"user","content":"beta"}]}`))
	if err != nil {
		t.Fatalf("busy lookup returned an error: %v", err)
	}
	if busyAfter := testutil.ToFloat64(CacheEmbedFlightBusyTotal); busyAfter != busyBefore+1 {
		t.Fatalf("busy counter = %v, want %v+1", busyAfter, busyBefore)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("busy lookup made an upstream call: calls = %d, want 1", got)
	}

	close(emb.gate)
	wg.Wait()
	waitFor(t, func() bool { return cs.embedFlight.active() == 0 }, 2*time.Second)
}
