// Cancellation-coherence tests (N09-P02-T04): a canceled or deadline-expired
// attempt is a client-side outcome, never an upstream health signal.
// RecordCanceled must free half-open probe slots without touching success or
// failure accounting, so a cancel storm can neither trip a breaker nor wedge
// a half-open epoch.
package circuit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newHalfOpenBreaker trips a breaker with threshold failures and backdates
// the open timestamp so the next Allow flips it to HalfOpen — deterministic,
// no wall-clock waiting.
func newHalfOpenBreaker(t *testing.T, cfg Config) *Breaker {
	t.Helper()
	cfg.Enabled = true
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 2
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = time.Minute
	}
	b := NewBreaker(cfg)
	for i := 0; i < cfg.FailureThreshold; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("probe %d must pass on a closed breaker, got %v", i, err)
		}
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("breaker must be open after %d failures, got %s", cfg.FailureThreshold, b.State())
	}
	// Backdate the open instant: the open timeout has fully elapsed.
	b.openAt.Store(time.Now().Add(-cfg.OpenTimeout).UnixNano())
	if err := b.Allow(); err != nil {
		t.Fatalf("first probe in half-open must pass, got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("breaker must be half-open after elapsed open timeout, got %s", b.State())
	}
	return b
}

// A canceled half-open probe frees its slot for the next probe and leaves
// every health counter untouched.
func TestBreaker_RecordCanceledFreesProbeSlotNoHealthSignal(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "cancel-slot"})

	before := b.Metrics()
	if before.HalfOpenInFlight != 1 {
		t.Fatalf("one probe must be in flight, got %d", before.HalfOpenInFlight)
	}

	b.RecordCanceled()

	after := b.Metrics()
	if after.HalfOpenInFlight != 0 {
		t.Fatalf("canceled probe must free its slot, got %d in flight", after.HalfOpenInFlight)
	}
	if after.State != StateHalfOpen {
		t.Fatalf("canceled probe must not change the state, got %s", after.State)
	}
	if after.FailureCount != before.FailureCount || after.SuccessCount != before.SuccessCount {
		t.Fatalf("canceled probe must not touch health counters: before %+v after %+v", before, after)
	}

	// The freed slot is immediately available to the next real probe.
	if err := b.Allow(); err != nil {
		t.Fatalf("slot freed by RecordCanceled must admit the next probe, got %v", err)
	}
	if got := b.Metrics().HalfOpenInFlight; got != 1 {
		t.Fatalf("next probe must hold the freed slot, got %d in flight", got)
	}
}

// Canceled probes never satisfy the success threshold: a half-open epoch
// whose every probe was canceled stays half-open with free slots — never
// closed on invented health, never wedged refusing everyone.
func TestBreaker_AllProbesCanceledStaysHalfOpenNotWedged(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "cancel-epoch"})

	// Second probe: both slots (SuccessThreshold=2) are now held.
	if err := b.Allow(); err != nil {
		t.Fatalf("second probe must pass, got %v", err)
	}
	// Probe budget exhausted: a third caller is refused.
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("exhausted probe budget must refuse, got %v", err)
	}

	// Both probes end as cancellations. The failures that tripped the
	// breaker remain — the assertion is that cancellation adds nothing.
	before := b.Metrics()
	b.RecordCanceled()
	b.RecordCanceled()

	after := b.Metrics()
	if after.HalfOpenInFlight != 0 {
		t.Fatalf("all canceled probes must free their slots, got %d in flight", after.HalfOpenInFlight)
	}
	if after.State != StateHalfOpen {
		t.Fatalf("epoch with only canceled probes must stay half-open, got %s", after.State)
	}
	if after.SuccessCount != before.SuccessCount || after.FailureCount != before.FailureCount {
		t.Fatalf("cancellations must not count as health outcomes: before %+v after %+v", before, after)
	}

	// The epoch is live: a fresh caller gets a probe slot.
	if err := b.Allow(); err != nil {
		t.Fatalf("half-open epoch must admit a probe after cancels, got %v", err)
	}

	// Only genuine successes close the circuit.
	b.RecordSuccess()
	if b.State() != StateHalfOpen {
		t.Fatalf("one success below the threshold must stay half-open, got %s", b.State())
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("success threshold must close the circuit, got %s", b.State())
	}
}

// Closed-state cancellations are pure no-ops: a cancel storm against a
// healthy breaker can never accumulate failures (the negative criterion:
// a retry/cancel storm must not amplify an outage upstream).
func TestBreaker_CancelStormOnClosedBreakerNoOp(t *testing.T) {
	b := NewBreaker(Config{Name: "cancel-storm", Enabled: true})
	before := b.Metrics()

	for i := 0; i < 1000; i++ {
		b.RecordCanceled()
	}

	after := b.Metrics()
	if after.State != StateClosed {
		t.Fatalf("cancel storm must not change the state, got %s", after.State)
	}
	if after.FailureCount != before.FailureCount || after.SuccessCount != before.SuccessCount {
		t.Fatalf("cancel storm must not touch health counters: before %+v after %+v", before, after)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("breaker must still serve after a cancel storm, got %v", err)
	}
}

// The canceled-probe refusal path must recover: canceling every probe cannot
// wedge the breaker into permanent refusal (probe slots return, new probes
// are admitted).
func TestBreaker_CanceledProbesDoNotWedgeHalfOpen(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "cancel-wedge", SuccessThreshold: 2})

	// Retire the helper's probe so every round starts from a clean epoch
	// state (zero slots in flight).
	b.RecordCanceled()

	for round := 0; round < 5; round++ {
		// Consume the probe budget: at most SuccessThreshold live probes.
		admitted := 0
		for admitted < 2 {
			if err := b.Allow(); err != nil {
				break
			}
			admitted++
		}
		if admitted == 0 {
			t.Fatalf("round %d: breaker wedged, no probe admitted", round)
		}
		for i := 0; i < admitted; i++ {
			b.RecordCanceled()
		}
		if m := b.Metrics(); m.HalfOpenInFlight != 0 {
			t.Fatalf("round %d: canceled probes must free all slots, got %d in flight", round, m.HalfOpenInFlight)
		}
		// The epoch is still live: a fresh caller gets a slot.
		if err := b.Allow(); err != nil {
			t.Fatalf("round %d: breaker wedged after cancels: %v", round, err)
		}
		b.RecordCanceled()
	}
}

// RecordCanceled is a no-op on a disabled breaker.
func TestBreaker_RecordCanceledDisabledNoOp(t *testing.T) {
	b := NewBreaker(Config{Name: "disabled", Enabled: false})
	b.RecordCanceled() // must not panic or mutate anything
	if err := b.Allow(); err != nil {
		t.Fatalf("disabled breaker must allow, got %v", err)
	}
}

// Concurrent mixed outcomes on one breaker: every admitted attempt is
// terminated by exactly one record; the probe counter must stay within its
// bound and the state machine must remain valid — race-detector checked.
//
// The final counter need not be zero: a probe admitted in HalfOpen whose
// epoch then flips (a sibling failure re-opens, a sibling success closes)
// records into a state that no longer owns that epoch's counter. This
// cross-epoch residue is bounded and accepted by the breaker design — the
// counter is reset to zero at every Open→HalfOpen flip, so residue can never
// accumulate or wedge an epoch. The sequential tests above pin exact
// slot accounting within one controlled epoch; this test pins the bounds
// under contention.
func TestBreaker_RecordCanceledConcurrentMixed(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "cancel-race"})

	const workers = 8
	const rounds = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := b.Allow(); err != nil {
					continue // refused (open/half-open exhausted): nothing to record
				}
				switch (w + i) % 3 {
				case 0:
					b.RecordCanceled()
				case 1:
					b.RecordFailure()
				default:
					b.RecordSuccess()
				}
			}
		}(w)
	}
	wg.Wait()

	m := b.Metrics()
	if m.HalfOpenInFlight < 0 || m.HalfOpenInFlight > b.halfOpenLimit {
		t.Fatalf("probe slots must stay within [0, %d] under concurrent records, got %d", b.halfOpenLimit, m.HalfOpenInFlight)
	}
	switch m.State {
	case StateClosed, StateOpen, StateHalfOpen:
		// All terminal states are valid; the invariant is bounded probe
		// accounting, not which state won the race.
	default:
		t.Fatalf("invalid final state %s", m.State)
	}
}

// Map plumbing: RecordCanceled reaches the keyed breaker and frees its probe
// slot without health attribution.
func TestMap_RecordCanceled(t *testing.T) {
	m := NewMap(Config{Enabled: true, FailureThreshold: 1, SuccessThreshold: 1, OpenTimeout: time.Minute}, 0, nil)

	if err := m.Allow("ep"); err != nil {
		t.Fatalf("first allow must pass, got %v", err)
	}
	m.RecordFailure("ep")
	if m.State("ep") != StateOpen {
		t.Fatalf("endpoint breaker must be open, got %s", m.State("ep"))
	}

	b := m.Breaker("ep")
	b.openAt.Store(time.Now().Add(-time.Minute).UnixNano())
	if err := m.Allow("ep"); err != nil {
		t.Fatalf("probe must pass in half-open, got %v", err)
	}
	m.RecordCanceled("ep")

	bm := b.Metrics()
	if bm.HalfOpenInFlight != 0 {
		t.Fatalf("canceled probe must free its slot through Map, got %d", bm.HalfOpenInFlight)
	}
	if bm.State != StateHalfOpen {
		t.Fatalf("cancellation must not change the state through Map, got %s", bm.State)
	}
}

// TenantMap plumbing: a canceled attempt on one (tenant, endpoint) pair
// frees its probe slot, stays out of the health signal and leaves other
// tenants' breakers untouched.
func TestTenantMap_RecordCanceled(t *testing.T) {
	tm := NewTenantMap(Config{Enabled: true, FailureThreshold: 1, SuccessThreshold: 1, OpenTimeout: time.Minute}, 0, nil)

	if err := tm.Allow("noisy", "https://up.example"); err != nil {
		t.Fatalf("first allow must pass, got %v", err)
	}
	tm.RecordFailure("noisy", "https://up.example")
	if tm.State("noisy", "https://up.example") != StateOpen {
		t.Fatalf("noisy breaker must be open, got %s", tm.State("noisy", "https://up.example"))
	}

	b := tm.Breaker("noisy", "https://up.example")
	b.openAt.Store(time.Now().Add(-time.Minute).UnixNano())
	if err := tm.Allow("noisy", "https://up.example"); err != nil {
		t.Fatalf("probe must pass in half-open, got %v", err)
	}
	tm.RecordCanceled("noisy", "https://up.example")

	bm := b.Metrics()
	if bm.HalfOpenInFlight != 0 || bm.State != StateHalfOpen {
		t.Fatalf("canceled tenant probe must free the slot and keep the state, got in-flight %d state %s", bm.HalfOpenInFlight, bm.State)
	}

	// Quiet tenant: untouched by the noisy tenant's episode, including its
	// cancellation bookkeeping.
	if err := tm.Allow("quiet", "https://up.example"); err != nil {
		t.Fatalf("quiet tenant must pass, got %v", err)
	}
	tm.RecordSuccess("quiet", "https://up.example")
	if s := tm.State("quiet", "https://up.example"); s != StateClosed {
		t.Fatalf("quiet tenant breaker must be closed, got %s", s)
	}
}
