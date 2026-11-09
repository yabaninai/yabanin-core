// Joint recovery scenario for packet N09-P02 (T08): interruption, retry
// and resume across the composed stack, ending in recovered results
// without duplicates or losses. Where T06's joint scenarios pinned
// saturation isolation and the outage lockout, this scenario pins the
// full outage→lockout→recovery wave with a genuinely retrying client:
// bounded retry.Do loops against a scripted upstream, a refusal lockout
// that keeps every storm retry pre-upstream, and a recovery wave in which
// every dispatch is delivered exactly once with its final status intact.
//
// Real vs mock split follows the T06 harness: REAL — FairAdmission,
// TenantMap/Breaker state machines, retry.Do loops, contexts/goroutines;
// MOCK — the scripted upstream (in-process, no network) and the scaled
// backoff cap. Deterministic: scripted serving order, bounded polls with
// hard horizons, label-delta ledger assertions (shuffle-safe), all
// goroutines joined.
package router

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/circuit"
)

// TestJointScenario_RecoveryWaveResultsWithoutDuplicatesOrLosses walks one
// tenant through a complete outage episode on the composed stack:
//
//  1. Outage: two dispatches, each retrying to the 3-attempt bound against
//     a 503-ing endpoint, return their final 503 intact (the bounded loop
//     loses no result) and trip the tenant's own breaker with exactly the
//     two failures. The endpoint saw exactly 2×3 attempts — the retry
//     bound is the amplification ceiling.
//  2. Lockout: while Open, three storm clients retry with the same bounded
//     policy; every attempt is refused at the circuit stage with a
//     positive hint, the endpoint's hit counter freezes (the retry storm
//     does not amplify the outage), and every dispatch attempt is still
//     admission-accounted exactly once.
//  3. Recovery: after the open window, three healthy dispatches are served
//     — the breaker half-opens on the first success, closes on the second,
//     and serves normally — and every dispatch delivers exactly one 200
//     result. Total endpoint hits are exactly outage+recovery: no duplicate
//     strikes, no lost results.
func TestJointScenario_RecoveryWaveResultsWithoutDuplicatesOrLosses(t *testing.T) {
	const (
		attemptBound  = 3 // retry.Do MaxAttempts: the amplification ceiling
		outageWaves   = 2 // dispatches during the outage
		stormClients  = 3 // lockout clients
		recoveryWaves = 3 // dispatches after the window
		failingServed = 6 // outageWaves * attemptBound 503s, then healthy
		openTimeout   = 80 * time.Millisecond
	)
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     4,
		MaxPerTenant: 2,
		QueueLimit:   8,
		WaitTimeout:  5 * time.Second, // far above the test horizon
	})
	tenants := circuit.NewTenantMap(circuit.Config{
		Enabled:          true,
		FailureThreshold: outageWaves, // the outage exactly trips the breaker
		SuccessThreshold: 2,           // two healthy probes close it
		OpenTimeout:      openTimeout,
		Window:           time.Minute,
	}, 0, nil)
	up := newJointUpstream(failingServed) // fails exactly the outage attempts
	stack := newJointStack(fa, tenants, up)
	stack.policy.MaxAttempts = attemptBound // genuinely retrying client loops
	ledger := snapshotFairLedger()
	ctx := context.Background()

	// Phase 1 — outage: each wave runs its bounded retry loop to the end
	// and returns the final 503 intact.
	for i := 0; i < outageWaves; i++ {
		out := stack.dispatch(ctx, "noisy", "chat")
		if out.stage != "attempt" || out.status != http.StatusServiceUnavailable {
			t.Fatalf("outage wave %d must return the final 503, got %+v", i+1, out)
		}
	}
	nb := tenants.Breaker("noisy", stack.ep)
	if m := nb.Metrics(); m.State != circuit.StateOpen || m.FailureCount != outageWaves {
		t.Fatalf("outage must open the breaker with %d failures, got %+v", outageWaves, m)
	}
	if got := up.hitsByTenant("noisy"); got != failingServed {
		t.Fatalf("the retry bound must cap outage attempts at %d, got %d", failingServed, got)
	}

	// Phase 2 — lockout: the storm retries are refused pre-upstream; the
	// hit counter freezes for the whole phase.
	loops := make([]*jointClientLoop, 0, stormClients)
	done := make(chan struct{}, stormClients)
	for i := 0; i < stormClients; i++ {
		l := &jointClientLoop{stack: stack, org: "noisy", workload: "chat"}
		loops = append(loops, l)
		go func() { l.run(ctx, attemptBound, 10*time.Millisecond); done <- struct{}{} }()
	}
	for i := 0; i < stormClients; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("storm client %d never finished", i)
		}
	}
	for i, l := range loops {
		if l.attempts != attemptBound {
			t.Fatalf("storm client %d must make exactly %d attempts, got %d", i, attemptBound, l.attempts)
		}
		for j, out := range l.outcomes {
			if out.stage != "circuit" || out.retryAfter <= 0 {
				t.Fatalf("storm attempt %d/%d must be refused pre-upstream with a hint, got %+v", i, j+1, out)
			}
		}
	}
	if got := up.hitsByTenant("noisy"); got != failingServed {
		t.Fatalf("the lockout must keep every storm retry pre-upstream: hits must stay %d, got %d", failingServed, got)
	}

	// Phase 3 — recovery: the open window elapses, then healthy dispatches
	// ride the half-open epoch to a closed breaker. Exactly one dispatch
	// outcome per wave, every final status a 200: no duplicates, no losses.
	waitForOpenWindowElapsed(t, nb)
	for i := 0; i < recoveryWaves; i++ {
		out := stack.dispatch(ctx, "noisy", "chat")
		if out.stage != "attempt" || out.status != http.StatusOK {
			t.Fatalf("recovery wave %d must be served with a 200, got %+v", i+1, out)
		}
		want := circuit.StateHalfOpen
		if i >= 1 { // the second success closes; the third rides the closed breaker
			want = circuit.StateClosed
		}
		if got := nb.State(); got != want {
			t.Fatalf("after recovery wave %d the breaker must be %s, got %s", i+1, want, got)
		}
	}

	// Result ledger: every dispatch attempt of every phase accounted
	// exactly once; no cancellation, no shed anywhere in the episode.
	totalDispatches := outageWaves + stormClients*attemptBound + recoveryWaves
	if got := ledger.delta(t, "admitted"); got != float64(totalDispatches) {
		t.Fatalf("every dispatch attempt must be admitted exactly once, want %d, delta %v", totalDispatches, got)
	}
	if got := ledger.delta(t, "canceled"); got != 0 {
		t.Fatalf("no dispatch may end canceled in this scenario, delta %v", got)
	}
	for _, silent := range []string{"shed_capacity", "shed_tenant_limit", "shed_queue_full", "shed_queue_timeout"} {
		if got := ledger.delta(t, silent); got != 0 {
			t.Fatalf("%s must stay silent (the queue absorbs the storm), delta %v", silent, got)
		}
	}

	// Upstream total: exactly the outage attempts plus the three recovered
	// dispatches — the episode neither duplicated a strike nor lost a
	// result, and concurrency never exceeded the admission capacity.
	if got := up.hitsByTenant("noisy"); got != failingServed+recoveryWaves {
		t.Fatalf("total upstream hits must be exactly outage+recovery = %d, got %d", failingServed+recoveryWaves, got)
	}
	if max := up.maxObservedInFlight(); max > 4 {
		t.Fatalf("upstream concurrency must never exceed the admission capacity, observed %d", max)
	}
	m := nb.Metrics()
	if m.State != circuit.StateClosed || m.FailureCount != 0 || m.SuccessCount != 0 || m.HalfOpenInFlight != 0 {
		t.Fatalf("recovered breaker must be clean, got %+v", m)
	}
	if st := fa.stats(); st.Free != 4 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}
