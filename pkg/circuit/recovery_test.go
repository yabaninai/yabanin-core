package circuit

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// N09-P02-T08 recovery corpus, aspect pkg/circuit: the recovery side of the
// breaker state machine. Where T07 pinned the transition boundaries and T04
// the cancellation discipline, this corpus pins what recovery reports and
// what stray terminals after recovery cannot corrupt: recovery callbacks
// fire exactly once (no duplicate recovery events), duplicate or late
// terminal records stay inert without driving the probe counter negative,
// a refusal storm during Open never postpones the outage window (the
// negative criterion at the breaker layer), and a recovered breaker hands
// callers an immediate resume with no stuck backpressure. All cases are
// deterministic: the open window is backdated through openAt, no probe
// outcome depends on goroutine timing.
//
// TestBreaker_RecoveryCallbacksFireExactlyOnce pins event exactly-once
// across a full trip→recover cycle: OnOpen fires once per trip (extra
// failures while Open are ignored, not re-reported), OnRecover fires once
// when the success threshold closes the circuit, and a duplicate terminal
// record after recovery cannot re-fire it — consumers observing these
// callbacks (alerting, hint propagation) must see one event per episode.
func TestBreaker_RecoveryCallbacksFireExactlyOnce(t *testing.T) {
	var opens, recovers atomic.Int32
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Name = "recovery-once"
	cfg.FailureThreshold = 2
	cfg.SuccessThreshold = 2
	cfg.OpenTimeout = time.Minute
	cfg.Window = time.Minute
	cfg.OnOpen = func(string) { opens.Add(1) }
	cfg.OnRecover = func(string) { recovers.Add(1) }
	b := NewBreaker(cfg)

	// Trip: the threshold-crossing failure opens once; further failures
	// while Open are ignored by design and must not re-fire OnOpen.
	for i := 0; i < 5; i++ {
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("breaker must be open after the threshold failures, state %s", b.State())
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("OnOpen must fire exactly once per trip, got %d", got)
	}

	// Recover: two admitted probes succeed; OnRecover fires exactly at the
	// closing success, not per success.
	b.openAt.Store(time.Now().Add(-cfg.OpenTimeout).UnixNano()) // open window elapsed
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 1 must be admitted, got %v", err)
	}
	b.RecordSuccess()
	if b.State() != StateHalfOpen {
		t.Fatalf("one success below the threshold must stay half-open, state %s", b.State())
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 2 must be admitted, got %v", err)
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("success threshold must close the circuit, state %s", b.State())
	}
	if got := recovers.Load(); got != 1 {
		t.Fatalf("OnRecover must fire exactly once per recovery, got %d", got)
	}

	// A duplicate terminal (the same attempt recorded again, or a caller
	// bug) must not re-fire recovery: the breaker is Closed, so the record
	// lands in the closed-state branch.
	b.RecordSuccess()
	b.RecordCanceled()
	if got := recovers.Load(); got != 1 {
		t.Fatalf("duplicate terminals after recovery must not re-fire OnRecover, got %d", got)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("duplicate terminals after recovery must not re-open, got %d opens", got)
	}
	m := b.Metrics()
	if m.State != StateClosed || m.HalfOpenInFlight != 0 {
		t.Fatalf("post-recovery duplicates must leave a clean closed breaker, got %+v", m)
	}
}

// TestBreaker_LateDuplicateTerminalsAfterReopenAreInert pins the
// double-terminal and cross-episode residue cases on the failure leg: a
// half-open probe that records its failure re-opens the circuit and
// releases its slot; a late cancellation for that same attempt (a duplicate
// terminal) must be inert — the released slot must not go negative, the
// re-open must stand, and a fresh probe after the window must still be
// admitted (the recovery path resumes). The closed-state variant pins the
// same inertness after a successful recovery.
func TestBreaker_LateDuplicateTerminalsAfterReopenAreInert(t *testing.T) {
	t.Run("cancel after a probe failure re-open", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.FailureThreshold = 1
		cfg.SuccessThreshold = 2
		cfg.OpenTimeout = time.Minute
		cfg.Window = time.Minute
		b := NewBreaker(cfg)

		b.RecordFailure() // trip
		b.openAt.Store(time.Now().Add(-cfg.OpenTimeout).UnixNano())
		if err := b.Allow(); err != nil {
			t.Fatalf("probe must be admitted, got %v", err)
		}
		b.RecordFailure() // probe fails: re-open, slot released
		if b.State() != StateOpen {
			t.Fatalf("probe failure must re-open, state %s", b.State())
		}

		// Duplicate terminal for the same attempt: the state is no longer
		// HalfOpen, so the cancel must be a no-op — never a negative slot.
		b.RecordCanceled()
		m := b.Metrics()
		if m.HalfOpenInFlight != 0 {
			t.Fatalf("late cancel must not corrupt the probe counter, got %d", m.HalfOpenInFlight)
		}
		if m.State != StateOpen {
			t.Fatalf("late cancel must not override the re-open, state %s", m.State)
		}

		// The recovery path resumes: a fresh probe is admitted after the
		// window and genuine successes close the circuit.
		b.openAt.Store(time.Now().Add(-cfg.OpenTimeout).UnixNano())
		if err := b.Allow(); err != nil {
			t.Fatalf("fresh probe after the window must be admitted, got %v", err)
		}
		if b.State() != StateHalfOpen {
			t.Fatalf("expected a fresh half-open epoch, state %s", b.State())
		}
		b.RecordSuccess()
		if err := b.Allow(); err != nil {
			t.Fatalf("probe 2 must be admitted, got %v", err)
		}
		b.RecordSuccess()
		if b.State() != StateClosed {
			t.Fatalf("recovery must complete after the fresh epoch, state %s", b.State())
		}
	})

	t.Run("cancel after a closing success", func(t *testing.T) {
		b := newHalfOpenBreaker(t, Config{Name: "late-cancel-closed", SuccessThreshold: 1})
		b.RecordSuccess() // closes: threshold 1
		if b.State() != StateClosed {
			t.Fatalf("success must close, state %s", b.State())
		}

		// The attempt's late cancellation lands on a Closed breaker.
		b.RecordCanceled()
		m := b.Metrics()
		if m.State != StateClosed || m.HalfOpenInFlight != 0 {
			t.Fatalf("late cancel on a closed breaker must be inert, got %+v", m)
		}
		if err := b.Allow(); err != nil {
			t.Fatalf("breaker must keep serving after the late cancel, got %v", err)
		}
	})
}

// TestBreaker_RefusalStormDoesNotPostponeRecovery pins the negative
// criterion at the breaker layer: refused callers during Open cannot
// extend the outage — refusals never move the open timestamp, the hint
// stays anchored to the original trip, and once the window has elapsed the
// very next Allow flips to HalfOpen regardless of how many refusals
// preceded it. A retry storm delays its own clients, never the recovery.
func TestBreaker_RefusalStormDoesNotPostponeRecovery(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 1
	cfg.OpenTimeout = time.Minute
	cfg.Window = time.Minute
	b := NewBreaker(cfg)

	b.RecordFailure() // trip
	trippedAt := b.openAt.Load()
	if b.State() != StateOpen {
		t.Fatalf("expected open, state %s", b.State())
	}

	// The storm: every refusal while Open must leave the window untouched.
	for i := 0; i < 500; i++ {
		if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("refusal %d must be ErrCircuitOpen, got %v", i, err)
		}
	}
	if got := b.openAt.Load(); got != trippedAt {
		t.Fatal("refusals must never move the open timestamp: the outage window is caller-independent")
	}
	if ra := b.RetryAfter(); ra <= 0 || ra > cfg.OpenTimeout {
		t.Fatalf("hint must stay anchored in (0, OpenTimeout], got %v", ra)
	}

	// Recovery is not postponed: once the window has elapsed, the next
	// Allow flips to HalfOpen and a genuine success closes immediately.
	b.openAt.Store(time.Now().Add(-cfg.OpenTimeout).UnixNano())
	if err := b.Allow(); err != nil {
		t.Fatalf("the next Allow after the window must admit a probe, got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open after the elapsed window, state %s", b.State())
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("recovery must close, state %s", b.State())
	}
	if ra := b.RetryAfter(); ra != 0 {
		t.Fatalf("recovered breaker must hand callers an immediate resume (hint 0), got %v", ra)
	}
	// And the closed breaker serves without refusals.
	if err := b.Allow(); err != nil {
		t.Fatalf("recovered breaker must admit normal traffic, got %v", err)
	}
}
