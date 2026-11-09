// Joint integration scenario for packet N09-P02 (T06): the packet's library
// surfaces composed the way the wave-2 wiring card will compose them at the
// dispatch site — FairAdmission.Admit (T02) as the pre-upstream admission
// gate, TenantMap/Breaker Allow + jittered RetryAfter hints (T02/T03) as the
// per-tenant circuit gate, retry.Do wrapping the upstream attempt, and the
// T04 terminal-path discipline (exactly one of RecordSuccess/RecordFailure/
// RecordCanceled per admitted attempt, Admit ended-context refuse, grant-scan
// dead-waiter retirement, abandon exactly-once) on every ending. The T05
// invariants are asserted on the composed stack, not on isolated units.
//
// Real and mock checks are explicitly distinguished (card stage acceptance):
//
//   - REAL: the production library stack — FairAdmission, TenantMap/Breaker
//     (real state machines, mutex/atomic mechanics), retry.Do, real
//     contexts/goroutines — and every assertion (admission ledger deltas,
//     breaker health counters, slot accounting, upstream attempt bounds).
//   - MOCK: the upstream endpoint (an in-process scripted fake with fault
//     phases and a hold latch — no network, no provider), the client
//     backoff clock (honored hints are real durations scaled down by a
//     small cap so the ordering property "back off before retry" is
//     exercised without multi-second wall waits) and the breaker open
//     windows (real short timers; every dependent assertion is
//     outcome-deterministic once the window has elapsed).
//
// Production HTTP wiring (pkg/gateway) is a separate card; no real network
// is involved anywhere in this scenario. Deterministic: channel-synchronized
// phases, bounded polls with hard horizons, label-delta assertions only
// (process-global promauto counters stay shuffle-safe). Race- and
// shuffle-safe: every goroutine is joined, every metric assertion is a
// delta, every stack is per-test.
package router

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/retry"
)

// jointUpstream is the MOCK endpoint of the scenario. Every attempt that
// reaches it is counted per tenant (attribution is a harness fact, not a
// wire fact), tracks observed in-flight concurrency against the admission
// bound, and serves from a deterministic script: while armed, a hold latch
// parks attempts (which abort with the context error when their context
// ends); the first failFirstServed served attempts get 503, the rest 200.
type jointUpstream struct {
	mu              sync.Mutex
	hold            chan struct{} // non-nil while armed: park new attempts
	hits            map[string]int
	inFlight        int
	maxInFlight     int
	served          int
	failFirstServed int
}

func newJointUpstream(failFirstServed int) *jointUpstream {
	return &jointUpstream{
		hits:            make(map[string]int),
		failFirstServed: failFirstServed,
	}
}

// armHold parks every attempt that reaches the endpoint until releaseHold.
// Call only while no attempt is in flight (the scenarios arm between
// synchronous phases).
func (u *jointUpstream) armHold() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.hold == nil {
		u.hold = make(chan struct{})
	}
}

func (u *jointUpstream) releaseHold() {
	u.mu.Lock()
	h := u.hold
	u.hold = nil
	u.mu.Unlock()
	if h != nil {
		close(h)
	}
}

func (u *jointUpstream) call(ctx context.Context, tenant string) retry.Result {
	u.mu.Lock()
	u.hits[tenant]++
	u.inFlight++
	if u.inFlight > u.maxInFlight {
		u.maxInFlight = u.inFlight
	}
	hold := u.hold
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.inFlight--
		u.mu.Unlock()
	}()

	// A held attempt models an upstream that accepted the connection but
	// has not answered yet. Its only escape before release is the context:
	// exactly the abort shape a real client cancel produces mid-attempt.
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return retry.Result{Err: ctx.Err()}
		}
	}

	u.mu.Lock()
	u.served++
	fail := u.served <= u.failFirstServed
	u.mu.Unlock()
	if fail {
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	}
	return retry.Result{StatusCode: http.StatusOK}
}

func (u *jointUpstream) hitsByTenant(tenant string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[tenant]
}

func (u *jointUpstream) maxObservedInFlight() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.maxInFlight
}

func (u *jointUpstream) inFlightNow() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.inFlight
}

// jointStack composes the REAL stack exactly as the wiring contract in the
// T04 record specifies: Admit with the request ctx, breaker Allow before the
// attempt, one terminal record per admitted attempt (canceled/deadline
// ctx ⇒ RecordCanceled), ticket released on every path.
type jointStack struct {
	fa      *FairAdmission
	tenants *circuit.TenantMap
	up      *jointUpstream
	ep      string
	policy  retry.Policy
}

func newJointStack(fa *FairAdmission, tenants *circuit.TenantMap, up *jointUpstream) *jointStack {
	return &jointStack{
		fa:      fa,
		tenants: tenants,
		up:      up,
		ep:      "https://joint.test/v1",
		// One attempt per dispatch: the retry storm in these scenarios is
		// the CLIENT loop below (which honors the refusal hints); retry.Do
		// contributes its ctx-check + classifier seam without multiplying
		// the attempt accounting.
		policy: retry.Policy{MaxAttempts: 1, RetryOn: retry.DefaultClassifier},
	}
}

// jointOutcome is one dispatch's observable result, tagged with the stage
// that decided it: "admit" (shed or context refusal), "circuit" (breaker
// refusal, with the RetryAfter hint) or "attempt" (a final upstream answer).
type jointOutcome struct {
	stage       string
	shed        *FairShedError
	ctxErr      error
	circuitErr  error
	upstreamErr error
	retryAfter  time.Duration
	status      int
}

func (s *jointStack) dispatch(ctx context.Context, org, workload string) jointOutcome {
	ticket, err := s.fa.Admit(ctx, org, workload)
	if err != nil {
		var shed *FairShedError
		if errors.As(err, &shed) {
			return jointOutcome{stage: "admit", shed: shed}
		}
		return jointOutcome{stage: "admit", ctxErr: err}
	}
	defer ticket.Release()

	if err := s.tenants.Allow(org, s.ep); err != nil {
		return jointOutcome{stage: "circuit", circuitErr: err, retryAfter: s.tenants.RetryAfter(org, s.ep)}
	}

	res := retry.Do(ctx, s.policy, func(ctx context.Context) retry.Result {
		return s.up.call(ctx, org)
	})

	// Terminal-path discipline (T04): the caller's context is the
	// authoritative cancellation signal and must never masquerade as an
	// upstream health failure.
	if ctx.Err() != nil {
		s.tenants.RecordCanceled(org, s.ep)
		return jointOutcome{stage: "attempt", ctxErr: ctx.Err()}
	}
	if res.Err != nil {
		s.tenants.RecordFailure(org, s.ep)
		return jointOutcome{stage: "attempt", upstreamErr: res.Err}
	}
	if res.StatusCode >= 400 {
		s.tenants.RecordFailure(org, s.ep)
		return jointOutcome{stage: "attempt", status: res.StatusCode}
	}
	s.tenants.RecordSuccess(org, s.ep)
	return jointOutcome{stage: "attempt", status: res.StatusCode}
}

func dispatchAsync(s *jointStack, ctx context.Context, org, workload string) <-chan jointOutcome {
	ch := make(chan jointOutcome, 1)
	go func() { ch <- s.dispatch(ctx, org, workload) }()
	return ch
}

func receiveJointOutcome(t *testing.T, ch <-chan jointOutcome, within time.Duration) jointOutcome {
	t.Helper()
	select {
	case out := <-ch:
		return out
	case <-time.After(within):
		t.Fatalf("dispatch outcome did not arrive within %v", within)
		return jointOutcome{}
	}
}

// jointClientLoop is the MOCK retry-storm client: it re-dispatches after
// every refusal, sleeping the refused stage's hint first (scaled down to
// backoffCap — the honored ordering property, at test speed). A final
// upstream answer ends the loop; only refusals are retried.
type jointClientLoop struct {
	stack    *jointStack
	org      string
	workload string

	attempts int
	outcomes []jointOutcome
	backoffs []time.Duration
}

func (c *jointClientLoop) run(ctx context.Context, maxAttempts int, backoffCap time.Duration) {
	for i := 0; i < maxAttempts; i++ {
		c.attempts++
		out := c.stack.dispatch(ctx, c.org, c.workload)
		c.outcomes = append(c.outcomes, out)
		if out.stage == "attempt" {
			return
		}
		hint := out.retryAfter
		if out.shed != nil {
			hint = out.shed.RetryAfter
		}
		if hint <= 0 || i == maxAttempts-1 {
			return
		}
		d := min(hint, backoffCap)
		c.backoffs = append(c.backoffs, d)
		time.Sleep(d)
	}
}

// waitForUpstreamInFlight polls until exactly want attempts are parked at
// the mock endpoint, so phase transitions never race the dispatch
// goroutines.
func waitForUpstreamInFlight(t *testing.T, u *jointUpstream, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if u.inFlightNow() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("upstream in-flight never reached %d (now %d)", want, u.inFlightNow())
}

// fairLedger snapshots the process-global fair-admission decision counters
// so assertions stay shuffle-safe deltas.
type fairLedger map[string]float64

func snapshotFairLedger() fairLedger {
	labels := []string{"admitted", "canceled", "shed_capacity", "shed_tenant_limit", "shed_queue_full", "shed_queue_timeout"}
	m := make(fairLedger, len(labels))
	for _, l := range labels {
		m[l] = testutil.ToFloat64(fairDecisions.WithLabelValues(l))
	}
	return m
}

func (l fairLedger) delta(t *testing.T, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(fairDecisions.WithLabelValues(label)) - l[label]
}

// Acceptance (packet N09-P02, joint scenario): under saturation a noisy
// tenant's storm — queued waiters, a queue-full shed, a dead-on-arrival
// request, an in-flight cancel — never displaces the quiet tenants. Every
// quiet request is served, the noisy cancel wave is retired exactly once by
// whichever of the grant-scan drop or its own abandon wins the race, the
// cancellation leaves no breaker health signal, the shed never reaches the
// upstream, and the upstream never sees more than the admission capacity.
func TestJointScenario_SaturationNoisyStormQuietTenantsServed(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       2,
		MaxPerTenant:   1,
		QueueLimit:     2,
		WaitTimeout:    30 * time.Second, // far above the test horizon
		ShedRetryAfter: 25 * time.Millisecond,
		ShedJitter:     0, // exact hints: the hint assertion is deterministic
	})
	// A real, enabled per-tenant breaker stack: the cancel wave must pass
	// through the actual RecordCanceled path with zero health effect.
	tenants := circuit.NewTenantMap(circuit.Config{
		Enabled:          true,
		FailureThreshold: 4,
		SuccessThreshold: 2,
		OpenTimeout:      time.Hour, // nothing in this scenario may open a circuit
		Window:           time.Minute,
	}, 0, nil)
	up := newJointUpstream(0) // healthy endpoint; the storm shape is the point here
	stack := newJointStack(fa, tenants, up)

	ledger := snapshotFairLedger()
	ctx := context.Background()

	// Phase 1 — saturation: two held dispatches (one noisy, one quiet)
	// fill the capacity; both park at the mock endpoint.
	up.armHold()
	noisyCtx, noisyCancel := context.WithCancel(ctx)
	defer noisyCancel()
	noisyCh := dispatchAsync(stack, noisyCtx, "noisy", "chat")
	quiet1Ch := dispatchAsync(stack, ctx, "quiet1", "chat")
	waitForUpstreamInFlight(t, up, 2)

	// Phase 2 — noisy storm at the admission gate: two queued waiters, a
	// third refused queue-full with a backpressure hint, and one
	// dead-on-arrival request refused before any accounting.
	const queuedStorm = 2
	stormChs := make([]<-chan jointOutcome, 0, queuedStorm)
	stormCancels := make([]context.CancelFunc, 0, queuedStorm)
	for i := 0; i < queuedStorm; i++ {
		sctx, scancel := context.WithCancel(ctx)
		stormCancels = append(stormCancels, scancel)
		ch := dispatchAsync(stack, sctx, "noisy", "chat")
		waitForQueueDepth(t, fa, "noisy", "chat", i+1)
		stormChs = append(stormChs, ch)
	}

	shedLoop := &jointClientLoop{stack: stack, org: "noisy", workload: "chat"}
	hitsBeforeShed := up.hitsByTenant("noisy") // the held attempt is already parked upstream
	shedLoop.run(ctx, 1, 10*time.Millisecond)  // single shot: observe the shed only
	if shedLoop.attempts != 1 || len(shedLoop.outcomes) != 1 {
		t.Fatalf("shed client must be single-shot, got %d attempts", shedLoop.attempts)
	}
	shedOut := shedLoop.outcomes[0]
	if shedOut.shed == nil || shedOut.shed.Reason != ShedQueueFull {
		t.Fatalf("third noisy request must be shed queue-full, got %+v", shedOut)
	}
	if shedOut.shed.RetryAfter != 25*time.Millisecond {
		t.Fatalf("shed hint must be the exact configured base, got %v", shedOut.shed.RetryAfter)
	}
	if got := up.hitsByTenant("noisy"); got != hitsBeforeShed {
		t.Fatalf("shed decision must stay pre-upstream, noisy hits %d -> %d", hitsBeforeShed, got)
	}

	doaCtx, doaCancel := context.WithCancel(ctx)
	doaCancel() // dead before Admit: the T04 ended-context refusal
	doaOut := stack.dispatch(doaCtx, "noisy", "chat")
	if doaOut.ctxErr == nil || !errors.Is(doaOut.ctxErr, context.Canceled) {
		t.Fatalf("dead-on-arrival request must be refused with context.Canceled, got %+v", doaOut)
	}
	if doaOut.stage != "admit" {
		t.Fatalf("dead-on-arrival refusal must happen at the admit stage, got %s", doaOut.stage)
	}

	// The quiet tenant queues behind the whole noisy storm.
	quiet2Ch := dispatchAsync(stack, ctx, "quiet2", "chat")
	waitForQueueDepth(t, fa, "quiet2", "chat", 1)

	// Phase 3 — the cancel wave: the queued noisy waiters end first, then
	// the noisy in-flight attempt is canceled mid-upstream. The freed slot
	// must go past the dead noisy run to the live quiet waiter, then the
	// latch lets quiet1 and quiet2 finish.
	for _, cancel := range stormCancels {
		cancel()
	}
	noisyCancel()
	up.releaseHold()
	quiet1Out := receiveJointOutcome(t, quiet1Ch, 5*time.Second)
	quiet2Out := receiveJointOutcome(t, quiet2Ch, 5*time.Second)
	noisyOut := receiveJointOutcome(t, noisyCh, 5*time.Second)
	for i, ch := range stormChs {
		out := receiveJointOutcome(t, ch, 5*time.Second)
		if out.ctxErr == nil || !errors.Is(out.ctxErr, context.Canceled) || out.stage != "admit" {
			t.Fatalf("queued noisy waiter %d must retire canceled at the admit stage, got %+v", i, out)
		}
	}

	if quiet1Out.status != http.StatusOK || quiet2Out.status != http.StatusOK {
		t.Fatalf("quiet tenants must be served through the storm, got %+v / %+v", quiet1Out, quiet2Out)
	}
	if noisyOut.ctxErr == nil || !errors.Is(noisyOut.ctxErr, context.Canceled) {
		t.Fatalf("canceled in-flight attempt must report the context error, got %+v", noisyOut)
	}

	// Ledger: exactly the expected decisions, each counted exactly once
	// regardless of which retirement path won the wake races.
	if got := ledger.delta(t, "admitted"); got != 3 {
		t.Fatalf("exactly the two held dispatches and quiet2 may be admitted, delta %v", got)
	}
	// The admission ledger counts admission decisions: the DOA refusal and
	// the two queued retirements. The canceled in-flight attempt was
	// already admitted (no admission decision left to count) — its
	// coherence is asserted on the breaker below.
	if got := ledger.delta(t, "canceled"); got != queuedStorm+1 { // 2 queued + DOA
		t.Fatalf("cancel wave must count exactly once per ended admission decision, delta %v", got)
	}
	if got := ledger.delta(t, "shed_queue_full"); got != 1 {
		t.Fatalf("exactly one queue-full shed expected, delta %v", got)
	}
	for _, silent := range []string{"shed_capacity", "shed_tenant_limit", "shed_queue_timeout"} {
		if got := ledger.delta(t, silent); got != 0 {
			t.Fatalf("%s must stay silent, delta %v", silent, got)
		}
	}

	// Breakers: the cancel wave must carry zero health signal on the real
	// state machines — no misattribution anywhere.
	for _, org := range []string{"noisy", "quiet1", "quiet2"} {
		m := tenants.Breaker(org, stack.ep).Metrics()
		if m.State != circuit.StateClosed {
			t.Fatalf("%s breaker must stay closed through the scenario, got %s", org, m.State)
		}
		if m.FailureCount != 0 {
			t.Fatalf("%s breaker must record zero failures from the cancel wave, got %d", org, m.FailureCount)
		}
		if m.HalfOpenInFlight != 0 {
			t.Fatalf("%s breaker must leak no probe slot, got %d", org, m.HalfOpenInFlight)
		}
	}

	// Upstream: only the three truly dispatched attempts ever reached the
	// endpoint (the held noisy one, then quiet1+quiet2), bounded by the
	// admission capacity; the shed, the DOA and the canceled queue never
	// touched it.
	if got := up.hitsByTenant("noisy"); got != 1 {
		t.Fatalf("noisy upstream hits must be exactly the one canceled attempt, got %d", got)
	}
	if got := up.hitsByTenant("quiet1") + up.hitsByTenant("quiet2"); got != 2 {
		t.Fatalf("quiet upstream hits must be exactly the two served requests, got %d", got)
	}
	if max := up.maxObservedInFlight(); max > 2 {
		t.Fatalf("upstream concurrency must never exceed the admission capacity, observed %d", max)
	}

	// Exact accounting after the full drain.
	if st := fa.stats(); st.Free != 2 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}

// waitForOpenWindowElapsed polls until the breaker's open window has fully
// elapsed (RetryAfter reaches 0) WITHOUT consuming a probe slot — the
// deterministic precondition for the next Allow to perform the Open→HalfOpen
// flip.
func waitForOpenWindowElapsed(t *testing.T, b *circuit.Breaker) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.RetryAfter() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("breaker open window never elapsed")
}

// Negative (packet N09-P02, joint scenario): a retry storm against an
// outage must not amplify it. The two subtests share the harness but keep
// their timing regimes disjoint and deterministic:
//
//   - lockout: with an open window far beyond the test horizon, every storm
//     retry is refused by the tenant's own circuit BEFORE the upstream (the
//     endpoint's hit counter freezes), each refusal surfaces a positive
//     backpressure hint that the client honors before retrying, and the
//     quiet tenant keeps flowing through its own untouched breaker.
//   - canceled-probe recovery: a half-open probe canceled mid-attempt is
//     recorded as exactly that (RecordCanceled) — no health signal, no
//     wedge — the epoch stays live, and genuine successes close the circuit
//     so the noisy tenant is served again after the outage.
func TestJointScenario_OutageRetryStormDoesNotAmplify(t *testing.T) {
	t.Run("lockout-refused-pre-upstream", func(t *testing.T) {
		const (
			stormLoops    = 4
			loopAttempts  = 3
			failingServed = 2 // exactly the two outage dispatches
		)
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity:     2,
			MaxPerTenant: 1,
			QueueLimit:   4,
			WaitTimeout:  5 * time.Second, // far above the test horizon
		})
		tenants := circuit.NewTenantMap(circuit.Config{
			Enabled:          true,
			FailureThreshold: 2,
			SuccessThreshold: 2,
			OpenTimeout:      time.Hour, // no flip inside the test: the lockout is total
			Window:           time.Minute,
		}, 0, nil)
		up := newJointUpstream(failingServed)
		stack := newJointStack(fa, tenants, up)
		ledger := snapshotFairLedger()
		ctx := context.Background()

		// Outage: two genuine attempts fail and trip the tenant's own circuit.
		for i := 0; i < failingServed; i++ {
			out := stack.dispatch(ctx, "noisy", "chat")
			if out.status != http.StatusServiceUnavailable {
				t.Fatalf("outage dispatch %d must observe the 503, got %+v", i+1, out)
			}
		}
		nb := tenants.Breaker("noisy", stack.ep)
		if m := nb.Metrics(); m.State != circuit.StateOpen || m.FailureCount != failingServed {
			t.Fatalf("outage must open the noisy breaker with %d failures, got %+v", failingServed, m)
		}
		if qb := tenants.Breaker("quiet1", stack.ep); qb.State() != circuit.StateClosed {
			t.Fatalf("quiet breaker must be untouched by the outage, got %s", qb.State())
		}

		// The storm: concurrent clients retrying every refusal, honoring the
		// hint first (real duration scaled down by the cap). Meanwhile the
		// quiet tenant keeps flowing on its own breaker.
		loops := make([]*jointClientLoop, 0, stormLoops)
		done := make(chan struct{}, stormLoops)
		for i := 0; i < stormLoops; i++ {
			l := &jointClientLoop{stack: stack, org: "noisy", workload: "chat"}
			loops = append(loops, l)
			go func() { l.run(ctx, loopAttempts, 10*time.Millisecond); done <- struct{}{} }()
		}
		quietCh := dispatchAsync(stack, ctx, "quiet1", "chat")

		for i := 0; i < stormLoops; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("storm loop %d never finished", i)
			}
		}
		quietOut := receiveJointOutcome(t, quietCh, 5*time.Second)
		if quietOut.status != http.StatusOK {
			t.Fatalf("quiet tenant must be served during the noisy lockout, got %+v", quietOut)
		}

		for i, l := range loops {
			if l.attempts != loopAttempts || len(l.outcomes) != loopAttempts {
				t.Fatalf("storm loop %d must make exactly %d attempts, got %d", i, loopAttempts, l.attempts)
			}
			for j, out := range l.outcomes {
				if out.stage != "circuit" || !errors.Is(out.circuitErr, circuit.ErrCircuitOpen) {
					t.Fatalf("storm loop %d attempt %d must be refused by the circuit, got %+v", i, j+1, out)
				}
				if out.retryAfter <= 0 {
					t.Fatalf("circuit refusal %d/%d must surface a backpressure hint, got %v", i, j+1, out.retryAfter)
				}
			}
			if len(l.backoffs) != loopAttempts-1 {
				t.Fatalf("storm loop %d must back off between all attempts, got %d backoffs", i, len(l.backoffs))
			}
			for _, d := range l.backoffs {
				if d <= 0 || d > 10*time.Millisecond {
					t.Fatalf("honored backoff must be positive and capped, got %v", d)
				}
			}
		}

		// The amplification proof: the storm's extra retries never reached
		// the endpoint — the outage saw exactly its own two hits.
		if got := up.hitsByTenant("noisy"); got != failingServed {
			t.Fatalf("retry storm must be refused pre-upstream: noisy hits must stay %d, got %d", failingServed, got)
		}
		if m := tenants.Breaker("quiet1", stack.ep).Metrics(); m.State != circuit.StateClosed || m.FailureCount != 0 {
			t.Fatalf("quiet breaker must stay closed with zero failures, got %+v", m)
		}
		if got := ledger.delta(t, "admitted"); got != failingServed+stormLoops*loopAttempts+1 {
			t.Fatalf("admission ledger must account every dispatch attempt exactly once, delta %v", got)
		}
		if got := ledger.delta(t, "canceled"); got != 0 {
			t.Fatalf("no admission decision may end canceled in this scenario, delta %v", got)
		}
		for _, silent := range []string{"shed_capacity", "shed_tenant_limit", "shed_queue_full", "shed_queue_timeout"} {
			if got := ledger.delta(t, silent); got != 0 {
				t.Fatalf("%s must stay silent (queue absorbs the storm), delta %v", silent, got)
			}
		}
		if max := up.maxObservedInFlight(); max > 2 {
			t.Fatalf("upstream concurrency must never exceed the admission capacity, observed %d", max)
		}
		if st := fa.stats(); st.Free != 2 || st.InFlight != 0 || st.Queued != 0 {
			t.Fatalf("drain must restore exact accounting, got %+v", st)
		}
	})

	t.Run("canceled-probe-recovery-closes", func(t *testing.T) {
		const (
			failingServed = 2
			openTimeout   = 80 * time.Millisecond
			successThresh = 2
		)
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity:     2,
			MaxPerTenant: 1,
			QueueLimit:   4,
			WaitTimeout:  5 * time.Second,
		})
		tenants := circuit.NewTenantMap(circuit.Config{
			Enabled:          true,
			FailureThreshold: failingServed,
			SuccessThreshold: successThresh,
			OpenTimeout:      openTimeout,
			Window:           time.Minute,
		}, 0, nil)
		up := newJointUpstream(failingServed)
		stack := newJointStack(fa, tenants, up)
		ledger := snapshotFairLedger()
		ctx := context.Background()

		for i := 0; i < failingServed; i++ {
			if out := stack.dispatch(ctx, "noisy", "chat"); out.status != http.StatusServiceUnavailable {
				t.Fatalf("outage dispatch %d must observe the 503, got %+v", i+1, out)
			}
		}
		nb := tenants.Breaker("noisy", stack.ep)
		if nb.State() != circuit.StateOpen {
			t.Fatalf("breaker must be open after the outage, got %s", nb.State())
		}

		// The canceled probe: admitted into the fresh half-open epoch, then
		// its caller gives up mid-attempt. The terminal-path discipline must
		// record exactly a cancellation — no health signal, no wedge.
		waitForOpenWindowElapsed(t, nb)
		probeCtx, probeCancel := context.WithCancel(ctx)
		defer probeCancel()
		up.armHold() // park the probe upstream mid-attempt
		probeCh := dispatchAsync(stack, probeCtx, "noisy", "chat")
		waitForUpstreamInFlight(t, up, 1)
		if m := nb.Metrics(); m.State != circuit.StateHalfOpen || m.HalfOpenInFlight != 1 {
			t.Fatalf("probe must own exactly one half-open slot, got %+v", m)
		}
		probeCancel()
		probeOut := receiveJointOutcome(t, probeCh, 5*time.Second)
		if probeOut.ctxErr == nil || !errors.Is(probeOut.ctxErr, context.Canceled) {
			t.Fatalf("canceled probe must report the context error, got %+v", probeOut)
		}
		if m := nb.Metrics(); m.State != circuit.StateHalfOpen {
			t.Fatalf("cancellation must not change the state machine, got %s", m.State)
		} else if m.FailureCount != failingServed {
			t.Fatalf("cancellation must leave the health signal untouched, got %d failures", m.FailureCount)
		} else if m.HalfOpenInFlight != 0 {
			t.Fatalf("canceled probe must free its slot (no wedge), got %d in flight", m.HalfOpenInFlight)
		}
		up.releaseHold()

		// Recovery: genuine successes close the circuit; the noisy tenant is
		// served again. Threshold 2: after the first success the epoch is
		// still half-open, after the second it closes.
		for i := 0; i < successThresh; i++ {
			out := stack.dispatch(ctx, "noisy", "chat")
			if out.status != http.StatusOK {
				t.Fatalf("recovery dispatch %d must succeed, got %+v", i+1, out)
			}
			want := circuit.StateHalfOpen
			if i == successThresh-1 {
				want = circuit.StateClosed
			}
			if got := nb.State(); got != want {
				t.Fatalf("after %d recovery success(es) the breaker must be %s, got %s", i+1, want, got)
			}
		}
		if out := stack.dispatch(ctx, "noisy", "chat"); out.status != http.StatusOK {
			t.Fatalf("post-recovery dispatch must be served normally, got %+v", out)
		}

		if m := nb.Metrics(); m.State != circuit.StateClosed || m.FailureCount != 0 || m.HalfOpenInFlight != 0 {
			t.Fatalf("recovered breaker must be clean, got %+v", m)
		}
		if got := ledger.delta(t, "admitted"); got != failingServed+1+successThresh+1 {
			t.Fatalf("admission ledger must account outage+probe+recovery+post dispatches, delta %v", got)
		}
		if got := ledger.delta(t, "canceled"); got != 0 {
			t.Fatalf("the canceled probe was already admitted: no admission decision to count, delta %v", got)
		}
		if got := up.hitsByTenant("noisy"); got != failingServed+1+successThresh+1 {
			t.Fatalf("every dispatched attempt must have reached the endpoint, got %d", got)
		}
		if st := fa.stats(); st.Free != 2 || st.InFlight != 0 || st.Queued != 0 {
			t.Fatalf("drain must restore exact accounting, got %+v", st)
		}
	})
}
