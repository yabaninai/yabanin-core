package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

// N03-P05-T06: THE joint user scenario — an N-client stampede on one
// uncached hot key while an org-wide invalidation lands around the leader's
// upstream dispatch and a client cancellation wave hits the same event.
//
// Four assertions per joint event (card N03-P05-T06):
//  1. STAMPEDE BOUND — upstream embedding attempts stay at one per flight
//     generation (the leader), never one per client, despite the crowd, the
//     racing invalidation and the cancellations.
//  2. CANCEL ISOLATION — a client's abort is local and prompt (≪ the lease
//     window): the shared flight, the leader's dispatched upstream call and
//     the surviving waiters are untouched, including across the invalidation
//     race. Pinned twice over: a WAITER's abort leaves the flight and its
//     survivors intact, and — stronger — the LEADER's own abort degrades
//     only that client (embedFlights.do returns on the caller's context)
//     while the detached load keeps running and the write-back still serves
//     every joined waiter.
//  3. NO LOCK LEFT — after the event settles no flight or lease survives
//     (active() == 0), the lease-mandate counter never moved (the next
//     request does not wait for one), and a fresh flight for the key is
//     immediately creatable and publishable.
//  4. GENERATION CORRECTNESS — no caller is ever served a foreign
//     generation's payload. The invalidation timing matrix pins the
//     documented contract (T05 record): waiters already joined when the
//     mid-flight Write publishes may receive the leader's payload even
//     though the invalidation raced it (bounded by the leader's
//     fresh-compute time, ≪ the flight TTL) — a pinned disposition, not a
//     defect; but after the invalidation has RETURNED, a fresh lookup
//     generation is never served the deleted generation's payload.
//
// Determinism note: the leader is whichever client creates the key's flight
// first, so the cancellation wave is launched only AFTER the flight is
// confirmed active (leader gated upstream, base crowd joined) — the wave
// clients then necessarily join as waiters, never as the leader.
//
// Real and mock checks are explicitly distinguished (the card's acceptance):
// the tests below are MOCK checks — refused-Redis partition, a gated
// embedder stub and a stub invalidator over the refused backend; they run
// without Docker and are -short safe. The REAL counterpart
// (TestCacheService_N03P5T06_JointScenario_LivePG, same file) runs the same
// joint event through the real semantic layer, the real writer pipeline and
// the real org-wide invalidation against a pgvector container, and is
// skipped in -short mode.

// n03p5t06CancelWaveSize is the number of clients that walk away mid-event.
const n03p5t06CancelWaveSize = 10

// n03p5t06CancelledBound is the cancelled-caller latency bound: the 10s
// lease window must never be approached by a local abort (1.5s leaves ample
// scheduler slack while still proving no mandate wait happened).
const n03p5t06CancelledBound = 1500 * time.Millisecond

// n03p5t06Outcome is one client's joint-scenario result.
type n03p5t06Outcome struct {
	hit       *CacheHit
	err       error
	cancelled bool
	elapsed   time.Duration
}

// n03p5t06StartCrowd launches callers concurrent lookups of one hot prompt.
// Clients whose index is in cancelledIdx carry a cancellable context (their
// CancelFunc is returned; the abort itself is fired by the test at the
// chosen moment of the joint event).
func n03p5t06StartCrowd(cs *CacheService, ri RouteIdentity, prompt []byte, callers int, cancelledIdx map[int]bool) (chan n03p5t06Outcome, []context.CancelFunc, *sync.WaitGroup) {
	results := make(chan n03p5t06Outcome, callers)
	cancels := make([]context.CancelFunc, callers)
	wg := &sync.WaitGroup{}
	for i := 0; i < callers; i++ {
		wg.Add(1)
		cancelled := cancelledIdx[i]
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		go func(ctx context.Context) {
			defer wg.Done()
			start := time.Now()
			hit, err := cs.LookupWithResult(ctx, ri, prompt)
			results <- n03p5t06Outcome{hit: hit, err: err, cancelled: cancelled, elapsed: time.Since(start)}
		}(ctx)
	}
	return results, cancels, wg
}

// n03p5t06Drain consumes exactly n outcomes and enforces the joint
// invariants: a cancelled client is a prompt local miss; a served client
// receives exactly the current generation's want payload (with strictSource,
// only the publish path's "exact" source counts — the mock world; otherwise
// any source qualifies, jsonb may re-serialize the document — the live
// world). A client that is neither cancelled nor served is counted as a
// miss. Returns (served, missed).
func n03p5t06Drain(t *testing.T, results chan n03p5t06Outcome, n int, want []byte, strictSource bool, timeout time.Duration) (served, missed int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("client %d: unexpected error %v", i, r.err)
			}
			switch {
			case r.cancelled:
				if r.hit != nil {
					t.Fatalf("cancelled client %d: served %q, want a local miss", i, r.hit.Data)
				}
				if r.elapsed > n03p5t06CancelledBound {
					t.Fatalf("cancelled client %d took %v, want <%v (a local abort must not wait on the flight or a lease)", i, r.elapsed, n03p5t06CancelledBound)
				}
				missed++
			case r.hit == nil:
				missed++
			case strictSource:
				if r.hit.SourceType == "exact" && bytes.Equal(r.hit.Data, want) {
					served++
				} else {
					t.Fatalf("client %d: payload %q (source %q), want the current generation's %q — a foreign generation's payload must never serve",
						i, r.hit.Data, r.hit.SourceType, want)
				}
			case sameJSON(r.hit.Data, want):
				served++
			default:
				t.Fatalf("client %d: payload %q (source %q), want the current generation's %q — a foreign generation's payload must never serve",
					i, r.hit.Data, r.hit.SourceType, want)
			}
		case <-time.After(timeout):
			t.Fatalf("client %d did not return in time (wedged by the joint event?)", i)
		}
	}
	return served, missed
}

// n03p5t06WaveIndexes returns the wave's client indexes (the first wave
// clients of the wave crowd).
func n03p5t06WaveIndexes(wave int) map[int]bool {
	idx := make(map[int]bool, wave)
	for i := 0; i < wave; i++ {
		idx[i] = true
	}
	return idx
}

// n03p5t06AssertNoLockLeft pins assertion 3: across the whole joint event no
// lease mandate was needed (the next request must not wait for one), the
// flight table is empty, and a fresh flight for the key is immediately
// creatable and publishable — leadership is available without delay.
func n03p5t06AssertNoLockLeft(t *testing.T, cs *CacheService, key string, leasesBefore float64) {
	t.Helper()
	if got := testutil.ToFloat64(CachePartitionLeasesTotal); got != leasesBefore {
		t.Fatalf("lease mandates = %v, want %v — the joint event must settle without a mandate and the next request must not wait on one", got, leasesBefore)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
	if _, published := cs.partition.await(context.Background(), key); published {
		t.Fatal("fresh creator must not be reported as published (the next request must proceed as leader)")
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("fresh flight: active = %d, want 1 (no stuck lock)", got)
	}
	cs.partition.publish(key, []byte(`{"answer":"n03p5t06-no-lock-probe"}`))
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
}

// Wait windows for the joint waits. Healthy mock rounds settle in
// milliseconds; the windows only need headroom for -race scheduling
// starvation under a fully loaded test process (observed: a dispatch landing
// just past a 3s window). A real defect never resolves, so a larger window
// costs nothing in detection latency.
const (
	n03p5t06LeaderWindow = 10 * time.Second
	n03p5t06JoinedWindow = 10 * time.Second
)

// n03p5t06Protect arms the failure isolation for one joint test: when the
// test finishes — pass or fail — every crowd context is cancelled, every
// embedder gate is closed exactly once and every partition flight is
// dissolved. A failing assertion can then never leak a gated leader, a
// joined waiter or a live lease mandate into a later test's global counters
// (the canceled contexts also bound every crowd goroutine's lifetime).
// pendingCancels is read at cleanup time, so crowds launched after the
// registration are covered too; append each crowd's cancel slice to it.
func n03p5t06Protect(t *testing.T, cs *CacheService, embs []*flightEmbedder, pendingCancels *[][]context.CancelFunc) {
	t.Helper()
	t.Cleanup(func() {
		for _, cancels := range *pendingCancels {
			for _, cancel := range cancels {
				cancel()
			}
		}
		for _, emb := range embs {
			if emb == nil {
				continue
			}
			select {
			case <-emb.gate:
			default:
				close(emb.gate)
			}
		}
		p := cs.partition
		p.mu.Lock()
		flights := make([]*partitionFlight, 0, len(p.flights))
		for _, f := range p.flights {
			flights = append(flights, f)
		}
		p.flights = make(map[string]*partitionFlight)
		p.mu.Unlock()
		for _, f := range flights {
			p.dissolve(f)
		}
	})
}

// n03p5t06PartitionCensus renders the flight table's internal state and the
// partition counters, so a failure discriminates replaced flights,
// finished-but-mapped flights and counter-attributed fall-throughs.
func n03p5t06PartitionCensus(p *partitionFlights) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "flights=%d [", len(p.flights))
	for k, f := range p.flights {
		fmt.Fprintf(&b, "{key=…%s waiters=%d finished=%v published=%v} ", k[len(k)-6:], f.waiters.Load(), f.finished, f.published)
	}
	fmt.Fprintf(&b, "] mode=%.0f leases=%.0f coalesced=%.0f overflow=%.0f",
		testutil.ToFloat64(CacheRedisPartitionTotal),
		testutil.ToFloat64(CachePartitionLeasesTotal),
		testutil.ToFloat64(CachePartitionCoalescedTotal),
		testutil.ToFloat64(CachePartitionOverflowTotal))
	return b.String()
}

// n03p5t06DumpStacks renders every goroutine stack (bounded) for failure
// diagnostics.
func n03p5t06DumpStacks() ([]byte, int) {
	buf := make([]byte, 2<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return buf, strings.Count(string(buf), "\ngoroutine ")
}

// n03p5t06WaitJoined waits until want callers are joined on key's flight and
// fails with full joint state on timeout: joined count, active flights, the
// leader's upstream progress and the process goroutine census — so a stall
// is attributable to a stage, not guessed at.
func n03p5t06WaitJoined(t *testing.T, cs *CacheService, emb *flightEmbedder, key string, want int64) {
	t.Helper()
	deadline := time.Now().Add(n03p5t06JoinedWindow)
	for time.Now().Before(deadline) {
		if cs.partition.waiting(key) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	stacks, goroutines := n03p5t06DumpStacks()
	t.Fatalf("joined = %d on key %s after %v, want %d [active=%d upstreamCalls=%d goroutines=%d census=%s]\n%s",
		cs.partition.waiting(key), key, n03p5t06JoinedWindow, want, cs.partition.active(), emb.calls.Load(), goroutines, n03p5t06PartitionCensus(cs.partition), stacks)
}

// n03p5t06WaitLeader waits until the joint crowd's leader has dispatched its
// single upstream intent; on timeout it dumps the same joint state plus all
// goroutine stacks, so a pre-dispatch stall (exact layer, policy, flight
// table) is visible instead of guessed at.
func n03p5t06WaitLeader(t *testing.T, cs *CacheService, emb *flightEmbedder, key string) {
	t.Helper()
	deadline := time.Now().Add(n03p5t06LeaderWindow)
	for time.Now().Before(deadline) {
		if emb.calls.Load() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	stacks, goroutines := n03p5t06DumpStacks()
	t.Fatalf("leader did not dispatch upstream in %v [upstreamCalls=%d active=%d joined=%d goroutines=%d census=%s]\n%s",
		n03p5t06LeaderWindow, emb.calls.Load(), cs.partition.active(), cs.partition.waiting(key), goroutines, n03p5t06PartitionCensus(cs.partition), stacks)
}

// The core joint event, MOCK: a 50-client stampede on one uncached hot key,
// the org-wide invalidation racing the leader's dispatched upstream call and
// returning BEFORE the write-back publishes, a 10-client cancellation wave
// landing while the leader is still upstream — then a fresh generation round
// that must never serve the deleted generation's payload.
func TestCacheService_N03P5T06_JointMidflightInvalidationCancelWave(t *testing.T) {
	emb1 := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	emb2 := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	cs := newPartitionTestService(t, emb1, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	crowdCancels := [][]context.CancelFunc{}
	n03p5t06Protect(t, cs, []*flightEmbedder{emb1, emb2}, &crowdCancels)
	inv := NewInvalidator(cs.exact, nil, refusedRedis())

	ri := RouteIdentity{OrgID: "org-n03p5t06-mid", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"joint-gen-1"}`)
	resp2 := []byte(`{"answer":"joint-gen-2-post-invalidation"}`)

	const base = 40
	const wave = n03p5t06CancelWaveSize
	const callers = base + wave

	leasesBefore := testutil.ToFloat64(CachePartitionLeasesTotal)
	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))
	t.Logf("midflight counters before the event: mode=%.0f leases=%.0f coalesced=%.0f overflow=%.0f",
		testutil.ToFloat64(CacheRedisPartitionTotal), leasesBefore,
		testutil.ToFloat64(CachePartitionCoalescedTotal),
		testutil.ToFloat64(CachePartitionOverflowTotal))

	// ---- The joint event: crowd → invalidation mid-upstream → cancel wave
	// ---- → write-back publication.
	results, cancels, wg := n03p5t06StartCrowd(cs, ri, prompt, base, nil)
	crowdCancels = append(crowdCancels, cancels)
	n03p5t06WaitLeader(t, cs, emb1, key)
	n03p5t06WaitJoined(t, cs, emb1, key, base-1)

	// The flight is active and the leader is gated upstream: the wave can
	// only join as waiters now (deterministic leader identity).
	waveResults, waveCancels, waveWG := n03p5t06StartCrowd(cs, ri, prompt, wave, n03p5t06WaveIndexes(wave))
	crowdCancels = append(crowdCancels, waveCancels)
	n03p5t06WaitJoined(t, cs, emb1, key, callers-1)

	// The invalidation races the leader's dispatched upstream call and
	// completes before the publication. Under the partition the Redis sweep
	// cannot finish — it must be reported incomplete, never as success.
	invErr := make(chan error, 1)
	go func() { invErr <- inv.InvalidateOrgAll(context.Background(), ri.OrgID) }()

	// The cancellation wave lands while the leader is STILL gated upstream:
	// every abort is local and prompt; the shared flight keeps its
	// survivors and the leader's upstream call is untouched.
	n03p5t06CancelWave := func() {
		for idx := range n03p5t06WaveIndexes(wave) {
			waveCancels[idx]()
		}
	}
	n03p5t06CancelWave()
	if served, missed := n03p5t06Drain(t, waveResults, wave, resp1, true, 2*time.Second); served != 0 || missed != wave {
		t.Fatalf("cancel wave: served=%d missed=%d, want 0/%d prompt local misses", served, missed, wave)
	}
	if got := cs.partition.waiting(key); got != int64(callers-1-wave) {
		t.Fatalf("waiters = %d after the cancel wave, want %d (the shared flight is untouched by foreign cancellations)", got, callers-1-wave)
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("active flights = %d after the cancel wave, want 1 (no lock dropped, none leaked)", got)
	}

	select {
	case err := <-invErr:
		if !errors.Is(err, ErrInvalidationIncomplete) {
			t.Fatalf("invalidation error %v, want ErrInvalidationIncomplete under the partition", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("invalidation did not finish while the leader was upstream")
	}

	// The gateway's write-back publishes generation 1 to the surviving
	// waiters. Pinned window (T05 record): the payload was computed by an
	// upstream call dispatched before the invalidation completed, and these
	// waiters had already joined — serving them is the documented bounded
	// staleness disposition, not a defect.
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	survivors := callers - 1 - wave
	if served, missed := n03p5t06Drain(t, results, survivors, resp1, true, 3*time.Second); served != survivors || missed != 0 {
		t.Fatalf("survivors: served=%d missed=%d, want %d/0", served, missed, survivors)
	}

	// Release the leader: exactly one upstream intent for the generation.
	close(emb1.gate)
	wg.Wait()
	waveWG.Wait()
	if served, missed := n03p5t06Drain(t, results, 1, resp1, true, 2*time.Second); served != 0 || missed != 1 {
		t.Fatalf("leader: served=%d missed=%d, want 0/1 (the single upstream intent ends in a probe miss)", served, missed)
	}
	if got := emb1.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d for the whole joint event (%d clients, racing invalidation, %d cancellations), want 1",
			got, callers, wave)
	}

	// ---- Post-invalidation generation: the invalidation has RETURNED, so
	// ---- the deleted generation's payload must never serve again.
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
	// Round 2 uses the pre-declared fresh embedder gate for its leader.
	cs.embedder = emb2
	results2, cancels2, wg2 := n03p5t06StartCrowd(cs, ri, prompt, callers, nil)
	crowdCancels = append(crowdCancels, cancels2)
	n03p5t06WaitLeader(t, cs, emb2, key)
	n03p5t06WaitJoined(t, cs, emb1, key, int64(callers-1))
	_ = cs.Write(context.Background(), ri, prompt, resp2, 1, 2)
	close(emb2.gate)
	wg2.Wait()
	if served2, missed2 := n03p5t06Drain(t, results2, callers, resp2, true, 3*time.Second); served2 != callers-1 || missed2 != 1 {
		t.Fatalf("post-invalidation round: served=%d missed=%d, want %d/1 (one fresh leader; the deleted generation must never serve)",
			served2, missed2, callers-1)
	}
	if got := emb2.calls.Load(); got != 1 {
		t.Fatalf("post-invalidation upstream calls = %d, want 1 (one leader per generation, not per client)", got)
	}

	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+float64(2+wave) {
		t.Fatalf("misses = %v, want +%d (one leader per generation + the %d cancelled clients)", got, 2+wave, wave)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+float64((callers-1-wave)+(callers-1)) {
		t.Fatalf("exact hits = %v, want +%d (every coalesced survivor of both generations; the wave was cancelled in round 1)",
			got, (callers-1-wave)+(callers-1))
	}
	n03p5t06AssertNoLockLeft(t, cs, key, leasesBefore)
}

// Cancel isolation at the JOINT level, strongest form, MOCK: the LEADER
// itself walks away mid-upstream. Its abort degrades only that client to a
// prompt local miss (embedFlights.do returns on the caller's context); the
// detached load is NOT aborted and makes no second upstream attempt; the
// joined waiters are still served by the write-back; the racing
// invalidation changes none of it. No lock is left on either flight table.
func TestCacheService_N03P5T06_JointLeaderCancelDetachedLoadServes(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	crowdCancels := [][]context.CancelFunc{}
	n03p5t06Protect(t, cs, []*flightEmbedder{emb}, &crowdCancels)
	inv := NewInvalidator(cs.exact, nil, refusedRedis())

	ri := RouteIdentity{OrgID: "org-n03p5t06-led", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"served-after-leader-cancel"}`)

	const waiters = 2

	leasesBefore := testutil.ToFloat64(CachePartitionLeasesTotal)
	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))

	// The first client alone is deterministically the leader; it dispatches
	// the (gated) upstream call.
	leaderResults, leaderCancels, leaderWG := n03p5t06StartCrowd(cs, ri, prompt, 1, map[int]bool{0: true})
	crowdCancels = append(crowdCancels, leaderCancels)
	n03p5t06WaitLeader(t, cs, emb, key)

	// Two waiters join the active flight.
	waiterResults, waiterCancels, waiterWG := n03p5t06StartCrowd(cs, ri, prompt, waiters, nil)
	crowdCancels = append(crowdCancels, waiterCancels)
	n03p5t06WaitJoined(t, cs, emb, key, waiters)

	// The leader walks away mid-upstream, and the invalidation races.
	invErr := make(chan error, 1)
	go func() { invErr <- inv.InvalidateOrgAll(context.Background(), ri.OrgID) }()
	leaderCancels[0]()
	if served, missed := n03p5t06Drain(t, leaderResults, 1, resp1, true, 2*time.Second); served != 0 || missed != 1 {
		t.Fatalf("cancelled leader: served=%d missed=%d, want 0/1 prompt local miss", served, missed)
	}
	select {
	case err := <-invErr:
		if !errors.Is(err, ErrInvalidationIncomplete) {
			t.Fatalf("invalidation error %v, want ErrInvalidationIncomplete under the partition", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("invalidation did not finish")
	}

	// The aborted leader left both the flight and its detached load intact:
	// still exactly one upstream intent, still one active partition flight
	// with both waiters joined.
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls after the leader's abort = %d, want 1 (the abort must not cancel or duplicate the shared load)", got)
	}
	if got := cs.partition.waiting(key); got != waiters {
		t.Fatalf("waiters = %d after the leader's abort, want %d (the shared flight is untouched)", got, waiters)
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("active flights = %d after the leader's abort, want 1", got)
	}

	// The write-back serves the joined waiters although the leader client
	// is gone.
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	if served, missed := n03p5t06Drain(t, waiterResults, waiters, resp1, true, 3*time.Second); served != waiters || missed != 0 {
		t.Fatalf("waiters: served=%d missed=%d, want %d/0 (served despite the cancelled leader)", served, missed, waiters)
	}

	// Release the detached load; it dissolves its embed-flight slot without
	// any further upstream attempt.
	close(emb.gate)
	leaderWG.Wait()
	waiterWG.Wait()
	waitFor(t, func() bool { return cs.embedFlight.active() == 0 }, 2*time.Second)
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("total upstream calls = %d, want 1", got)
	}

	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+1 {
		t.Fatalf("misses = %v, want +%d (only the cancelled leader)", got, 1)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+waiters {
		t.Fatalf("exact hits = %v, want +%d", got, waiters)
	}
	n03p5t06AssertNoLockLeft(t, cs, key, leasesBefore)
}

// Timing variant, MOCK: the invalidation completes BEFORE any client of the
// crowd dispatches upstream. The burst that follows is unaffected: one
// upstream intent, the cancel wave stays local, and every served payload is
// post-invalidation.
func TestCacheService_N03P5T06_JointInvalidationBeforeDispatch(t *testing.T) {
	emb := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	cs := newPartitionTestService(t, emb, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	crowdCancels := [][]context.CancelFunc{}
	n03p5t06Protect(t, cs, []*flightEmbedder{emb}, &crowdCancels)
	inv := NewInvalidator(cs.exact, nil, refusedRedis())

	ri := RouteIdentity{OrgID: "org-n03p5t06-pre", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"joint-post-invalidation-gen"}`)

	const base = 40
	const wave = n03p5t06CancelWaveSize
	const callers = base + wave

	leasesBefore := testutil.ToFloat64(CachePartitionLeasesTotal)
	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))

	// The invalidation completes before any upstream dispatch of the crowd.
	if err := inv.InvalidateOrgAll(context.Background(), ri.OrgID); !errors.Is(err, ErrInvalidationIncomplete) {
		t.Fatalf("invalidation error %v, want ErrInvalidationIncomplete under the partition", err)
	}

	results, cancels, wg := n03p5t06StartCrowd(cs, ri, prompt, base, nil)
	crowdCancels = append(crowdCancels, cancels)
	n03p5t06WaitLeader(t, cs, emb, key)
	n03p5t06WaitJoined(t, cs, emb, key, base-1)
	waveResults, waveCancels, waveWG := n03p5t06StartCrowd(cs, ri, prompt, wave, n03p5t06WaveIndexes(wave))
	crowdCancels = append(crowdCancels, waveCancels)
	n03p5t06WaitJoined(t, cs, emb, key, int64(callers-1))

	for idx := range n03p5t06WaveIndexes(wave) {
		waveCancels[idx]()
	}
	if served, missed := n03p5t06Drain(t, waveResults, wave, resp1, true, 2*time.Second); served != 0 || missed != wave {
		t.Fatalf("cancel wave: served=%d missed=%d, want 0/%d prompt local misses", served, missed, wave)
	}
	if got := cs.partition.active(); got != 1 {
		t.Fatalf("active flights = %d after the cancel wave, want 1", got)
	}

	// The write-back publishes the post-invalidation generation; every
	// survivor is served exactly that payload.
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	survivors := callers - 1 - wave
	if served, missed := n03p5t06Drain(t, results, survivors, resp1, true, 3*time.Second); served != survivors || missed != 0 {
		t.Fatalf("survivors: served=%d missed=%d, want %d/0", served, missed, survivors)
	}

	close(emb.gate)
	wg.Wait()
	waveWG.Wait()
	if served, missed := n03p5t06Drain(t, results, 1, resp1, true, 2*time.Second); served != 0 || missed != 1 {
		t.Fatalf("leader: served=%d missed=%d, want 0/1", served, missed)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d for %d clients after a completed invalidation, want 1", got, callers)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+float64(1+wave) {
		t.Fatalf("misses = %v, want +%d", got, 1+wave)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+float64(survivors) {
		t.Fatalf("exact hits = %v, want +%d", got, survivors)
	}
	n03p5t06AssertNoLockLeft(t, cs, key, leasesBefore)
}

// Timing variant, MOCK: the joint round settles fully (publication included)
// and the invalidation lands AFTER it; the fresh generation round that
// follows must be served only its own payload — the invalidated generation's
// payload must never reappear — with immediate leadership for the fresh
// round (no lease wait).
func TestCacheService_N03P5T06_JointInvalidationAfterPublication(t *testing.T) {
	emb1 := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	cs := newPartitionTestService(t, emb1, newPartitionFlights(8, 10*time.Second, 10*time.Second))
	emb2 := &flightEmbedder{err: errors.New("embedder probe"), gate: make(chan struct{})}
	crowdCancels := [][]context.CancelFunc{}
	n03p5t06Protect(t, cs, []*flightEmbedder{emb1, emb2}, &crowdCancels)
	inv := NewInvalidator(cs.exact, nil, refusedRedis())

	ri := RouteIdentity{OrgID: "org-n03p5t06-post", Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"joint-invalidated-gen"}`)
	resp2 := []byte(`{"answer":"joint-fresh-gen"}`)

	const callers = 50
	const fresh = 3

	leasesBefore := testutil.ToFloat64(CachePartitionLeasesTotal)
	missBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact"))

	// Round 1 settles completely: one leader, all waiters served, table
	// empty.
	results, cancels, wg := n03p5t06StartCrowd(cs, ri, prompt, callers, nil)
	crowdCancels = append(crowdCancels, cancels)
	n03p5t06WaitLeader(t, cs, emb1, key)
	n03p5t06WaitJoined(t, cs, emb1, key, int64(callers-1))
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	close(emb1.gate)
	wg.Wait()
	if served, missed := n03p5t06Drain(t, results, callers, resp1, true, 3*time.Second); served != callers-1 || missed != 1 {
		t.Fatalf("round 1: served=%d missed=%d, want %d/1", served, missed, callers-1)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)

	// The invalidation lands after the publication.
	if err := inv.InvalidateOrgAll(context.Background(), ri.OrgID); !errors.Is(err, ErrInvalidationIncomplete) {
		t.Fatalf("invalidation error %v, want ErrInvalidationIncomplete under the partition", err)
	}

	// The fresh generation: a small crowd, served only its own payload.
	// Round 2 uses the pre-declared fresh embedder gate for its leader.
	cs.embedder = emb2
	results2, cancels2, wg2 := n03p5t06StartCrowd(cs, ri, prompt, fresh, nil)
	crowdCancels = append(crowdCancels, cancels2)
	n03p5t06WaitLeader(t, cs, emb2, key)
	n03p5t06WaitJoined(t, cs, emb2, key, int64(fresh-1))
	_ = cs.Write(context.Background(), ri, prompt, resp2, 1, 2)
	close(emb2.gate)
	wg2.Wait()
	if served2, missed2 := n03p5t06Drain(t, results2, fresh, resp2, true, 3*time.Second); served2 != fresh-1 || missed2 != 1 {
		t.Fatalf("fresh generation: served=%d missed=%d, want %d/1 — the invalidated generation's %q must never serve",
			served2, missed2, fresh-1, resp1)
	}
	if got := emb1.calls.Load() + emb2.calls.Load(); got != 2 {
		t.Fatalf("total upstream calls = %d across both generations (%d + %d clients), want 2", got, callers, fresh)
	}

	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("miss")); got != missBefore+2 {
		t.Fatalf("misses = %v, want +%d (one leader per generation)", got, 2)
	}
	if got := testutil.ToFloat64(CacheHitsTotal.WithLabelValues("exact")); got != hitBefore+float64(callers-1+fresh-1) {
		t.Fatalf("exact hits = %v, want +%d", got, callers-1+fresh-1)
	}
	n03p5t06AssertNoLockLeft(t, cs, key, leasesBefore)
}

// The REAL counterpart of the joint scenario (pgvector container): the same
// event through the real semantic layer, the real writer pipeline and the
// real org-wide invalidation — the invalidation races the leader's
// dispatched upstream call, the cancel wave lands mid-event, the write-back
// publishes the pre-invalidation-ordered generation (pinned window), the
// invalidation provably deletes the landed pgvector row, and the fresh
// generation round is served only its own payload. Requires Docker; skipped
// in -short mode.
func TestCacheService_N03P5T06_JointScenario_LivePG(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) live joint scenario in -short mode")
	}
	pool := newSemanticPGPool(t, nil)
	pgStore := NewStore(pool)

	emb1 := &flightEmbedder{vec: makeTestEmbedding(384, 0.01), gate: make(chan struct{})}
	emb2 := &flightEmbedder{vec: makeTestEmbedding(384, 0.02), gate: make(chan struct{})}
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
	crowdCancels := [][]context.CancelFunc{}
	n03p5t06Protect(t, cs, []*flightEmbedder{emb1, emb2}, &crowdCancels)
	inv := NewInvalidator(cs.exact, pgStore, refusedRedis())

	// A real UUID org row: the pgvector writer path inserts org_id as uuid.
	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	ri := RouteIdentity{OrgID: orgID, Model: "gpt-4o"}.Resolved()
	prompt := stampedePrompt()
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)))
	resp1 := []byte(`{"answer":"live-joint-gen-1"}`)
	resp2 := []byte(`{"answer":"live-joint-gen-2"}`)

	const base = 10
	const wave = 2
	const callers = base + wave

	// ---- Round 1: the joint event on the live path. ----
	results, cancels, wg := n03p5t06StartCrowd(cs, ri, prompt, base, nil)
	crowdCancels = append(crowdCancels, cancels)
	n03p5t06WaitLeader(t, cs, emb1, key)
	n03p5t06WaitJoined(t, cs, emb1, key, base-1)
	waveResults, waveCancels, waveWG := n03p5t06StartCrowd(cs, ri, prompt, wave, n03p5t06WaveIndexes(wave))
	crowdCancels = append(crowdCancels, waveCancels)
	n03p5t06WaitJoined(t, cs, emb1, key, int64(callers-1))

	// The invalidation races the leader's dispatched upstream call; the
	// cancel wave lands while the leader is still gated.
	invErr := make(chan error, 1)
	go func() { invErr <- inv.InvalidateOrgAll(context.Background(), ri.OrgID) }()
	for idx := range n03p5t06WaveIndexes(wave) {
		waveCancels[idx]()
	}
	if served, missed := n03p5t06Drain(t, waveResults, wave, resp1, false, 2*time.Second); served != 0 || missed != wave {
		t.Fatalf("cancel wave: served=%d missed=%d, want 0/%d prompt local misses", served, missed, wave)
	}
	if got := cs.partition.waiting(key); got != int64(callers-1-wave) {
		t.Fatalf("waiters = %d after the cancel wave, want %d (shared flight untouched)", got, callers-1-wave)
	}
	select {
	case err := <-invErr:
		if !errors.Is(err, ErrInvalidationIncomplete) {
			t.Fatalf("invalidation error %v, want ErrInvalidationIncomplete (the redis side refuses under the partition)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("invalidation did not finish while the leader was upstream")
	}

	// Pinned window: the write-back publishes the generation computed by the
	// pre-invalidation upstream dispatch to the already-joined survivors.
	_ = cs.Write(context.Background(), ri, prompt, resp1, 1, 2)
	close(emb1.gate)
	wg.Wait()
	waveWG.Wait()
	if served, missed := n03p5t06Drain(t, results, callers-wave, resp1, false, 5*time.Second); missed > 1 || served < callers-wave-1 {
		t.Fatalf("round 1: served=%d missed=%d, want every joined survivor served and at most the leader missed", served, missed)
	}

	// The writer pipeline lands round 1's row (its write was ordered before
	// the sweep finished — the documented inherent SCAN caveat).
	waitFor(t, func() bool {
		e, err := cs.store.GetExact(context.Background(), ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)), ri.Version)
		return err == nil && e != nil
	}, 10*time.Second)
	emb1Total := emb1.calls.Load()

	// ---- Round 2: the invalidation has RETURNED after deleting the row —
	// ---- the deleted generation must never serve again.
	if err := inv.InvalidateOrgAll(context.Background(), ri.OrgID); !errors.Is(err, ErrInvalidationIncomplete) {
		t.Fatalf("round-2 invalidation error %v, want ErrInvalidationIncomplete (redis side)", err)
	}
	if e, err := cs.store.GetExact(context.Background(), ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(prompt)), ri.Version); err != nil || e != nil {
		t.Fatalf("post-invalidation GetExact: entry=%v err=%v, want the pgvector row really deleted", e, err)
	}

	cs.embedder = emb2 // fresh gate for the round-2 leader (the writer keeps emb1)
	const fresh = 6
	results2, cancels2, wg2 := n03p5t06StartCrowd(cs, ri, prompt, fresh, nil)
	crowdCancels = append(crowdCancels, cancels2)
	n03p5t06WaitLeader(t, cs, emb2, key)
	n03p5t06WaitJoined(t, cs, emb2, key, int64(fresh-1))
	_ = cs.Write(context.Background(), ri, prompt, resp2, 1, 2)
	close(emb2.gate)
	wg2.Wait()
	if served2, missed2 := n03p5t06Drain(t, results2, fresh, resp2, false, 5*time.Second); missed2 > 1 || served2 < fresh-1 {
		t.Fatalf("round 2: served=%d missed=%d, want every coalesced caller served resp2 and at most the leader missed — the deleted generation's %q must never serve",
			served2, missed2, resp1)
	}

	// Upstream bound across the whole live joint scenario: two leaders plus
	// the writer pipeline's embeds — never one per client, despite both
	// crowds, the racing invalidations and the cancellations.
	if total := emb1.calls.Load() + emb2.calls.Load(); total > emb1Total+4 {
		t.Fatalf("total embedding calls = %d, want ≤ %d (2 leaders + writer pipeline)", total, emb1Total+4)
	}
	waitFor(t, func() bool { return cs.partition.active() == 0 }, 2*time.Second)
	q, d, w := cs.WriterStats()
	f, s := cs.writer.OutcomeStats()
	t.Logf("writer outcomes after the live joint scenario: queued=%d dropped=%d written=%d failed=%d skipped=%d emb1=%d emb2=%d",
		q, d, w, f, s, emb1.calls.Load(), emb2.calls.Load())
}

// Regression (N03-P05-T06): the exact-layer classification that arms the
// partition must treat store-side timeouts as unavailability, not as caller
// cancellation. A dial or read timeout surfaces as a deadline-exceeded error
// while the caller's own context is still live; classifying it as a
// cancellation sent every such lookup straight to the embed layer, silently
// bypassing the stampede guard (observed as a 12-of-40 bypass under -race
// load in the joint scenario).
func TestCacheService_N03P5T06_ExactPartitionClassification(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrap := func(err error) error { return fmt.Errorf("redis get: %w", err) }

	if redisUnavailable(ctx, nil) {
		t.Fatal("no error must not arm the partition")
	}
	if redisUnavailable(ctx, redis.Nil) {
		t.Fatal("an ordinary miss must not arm the partition")
	}
	if !redisUnavailable(ctx, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Fatal("a refused connection with a live caller must arm the partition")
	}
	if !redisUnavailable(ctx, wrap(context.DeadlineExceeded)) {
		t.Fatal("a store-side dial/read timeout with a live caller must arm the partition — a miss here bypasses the stampede guard")
	}
	if redisUnavailable(ctx, wrap(context.Canceled)) {
		t.Fatal("a pure cancellation error with a live caller must not arm the partition")
	}
	cancel()
	if redisUnavailable(ctx, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Fatal("a gone caller must not arm the partition")
	}
}
