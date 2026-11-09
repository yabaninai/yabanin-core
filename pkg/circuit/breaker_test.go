package circuit

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
)

func TestNewBreaker_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.FailureThreshold != 10 {
		t.Fatalf("expected FailureThreshold=10, got %d", cfg.FailureThreshold)
	}
	if cfg.SuccessThreshold != 2 {
		t.Fatalf("expected SuccessThreshold=2, got %d", cfg.SuccessThreshold)
	}
	if cfg.OpenTimeout != 30*time.Second {
		t.Fatalf("expected OpenTimeout=30s, got %v", cfg.OpenTimeout)
	}
	if cfg.Window != 30*time.Second {
		t.Fatalf("expected Window=30s, got %v", cfg.Window)
	}

	b := NewBreaker(cfg)
	if b.State() != StateClosed {
		t.Fatalf("expected initial state closed, got %s", b.State())
	}
}

func TestNewBreaker_CustomConfig(t *testing.T) {
	cfg := Config{
		FailureThreshold: 3,
		SuccessThreshold: 1,
		OpenTimeout:      5 * time.Second,
		Window:           10 * time.Second,
	}
	_ = NewBreaker(cfg) // verify no panic

	// Verify defaults are filled in for zero values.
	cfg2 := Config{FailureThreshold: 0, SuccessThreshold: 0, OpenTimeout: 0, Window: 0}
	b2 := NewBreaker(cfg2)
	if b2.cfg.FailureThreshold != DefaultConfig().FailureThreshold {
		t.Fatal("zero FailureThreshold should use default")
	}
}

func TestDisabledBreaker_AllowsAll(t *testing.T) {
	cfg := Config{Enabled: false, FailureThreshold: 1}
	b := NewBreaker(cfg)

	for i := 0; i < 100; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: disabled breaker should allow all, got %v", i, err)
		}
	}

	b.RecordFailure()
	if b.State() != StateClosed {
		t.Fatal("disabled breaker should never open")
	}
}

// --- Closed -> Open transitions ---

func TestClosedToOpen_WhenFailureThresholdReached(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 5,
		Window:           30 * time.Second,
		OpenTimeout:      30 * time.Second,
	}
	b := NewBreaker(cfg)

	for i := 0; i < 4; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}
	if b.State() != StateClosed {
		t.Fatal("breaker should still be closed before threshold")
	}

	// The 5th failure should trip the circuit.
	if err := b.Allow(); err != nil {
		t.Fatalf("request 4 (last allowed): should allow, got %v", err)
	}
	b.RecordFailure()

	if b.State() != StateOpen {
		t.Fatalf("expected state open after threshold, got %s", b.State())
	}
}

func TestClosedToOpen_SlidingWindowResets(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 5,
		Window:           100 * time.Millisecond,
		OpenTimeout:      30 * time.Second,
	}
	b := NewBreaker(cfg)

	// Fill half the threshold.
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	// Wait for window to expire.
	time.Sleep(150 * time.Millisecond)

	// Add 2 more failures — should NOT trip because window reset.
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}
	if b.State() != StateClosed {
		t.Fatal("breaker should stay closed after window expires")
	}

	// Now add 1 more (total 3 in new window) — still not enough.
	if err := b.Allow(); err != nil {
		t.Fatalf("request: should allow, got %v", err)
	}
	b.RecordFailure()
	if b.State() != StateClosed {
		t.Fatal("should still be closed")
	}

	// One more to reach threshold of 5 in current window? No, only 3 so far.
	// Need 2 more.
	if err := b.Allow(); err != nil {
		t.Fatalf("request: should allow, got %v", err)
	}
	b.RecordFailure()
	if err := b.Allow(); err != nil {
		t.Fatalf("request: should allow, got %v", err)
	}
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open after 5 failures, got %s", b.State())
	}
}

// --- Open -> HalfOpen transitions ---

func TestOpenToHalfOpen_AfterTimeout(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	// Trip the circuit.
	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatal("expected open")
	}

	// Requests should be rejected during Open state.
	err := b.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}

	// Wait for timeout.
	time.Sleep(150 * time.Millisecond)

	// Next Allow should transition to HalfOpen and permit one probe.
	err = b.Allow()
	if err != nil {
		t.Fatalf("expected Allow() to succeed in half-open, got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open, got %s", b.State())
	}
}

func TestOpen_RejectsDuringTimeout(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      500 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	// Multiple requests during Open should all be rejected.
	for i := 0; i < 5; i++ {
		err := b.Allow()
		if !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("request %d: expected ErrCircuitOpen, got %v", i, err)
		}
	}

	if b.State() != StateOpen {
		t.Fatal("state should remain open during timeout")
	}
}

// --- HalfOpen -> Closed transitions ---

func TestHalfOpenToClosed_AfterSuccessThreshold(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	// Trip to Open.
	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	// Wait for HalfOpen.
	time.Sleep(150 * time.Millisecond)

	// Allow the first probe.
	if err := b.Allow(); err != nil {
		t.Fatalf("expected Allow in half-open, got %v", err)
	}
	b.RecordSuccess() // success 1

	// Still half-open (need 2 successes).
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open after 1 success, got %s", b.State())
	}

	// Allow second probe.
	if err := b.Allow(); err != nil {
		t.Fatalf("expected Allow in half-open, got %v", err)
	}
	b.RecordSuccess() // success 2

	if b.State() != StateClosed {
		t.Fatalf("expected closed after threshold successes, got %s", b.State())
	}
}

func TestHalfOpenToOpen_AfterFailure(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	// Trip to Open.
	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	// Wait for HalfOpen.
	time.Sleep(150 * time.Millisecond)

	// Allow a probe.
	if err := b.Allow(); err != nil {
		t.Fatalf("expected Allow in half-open, got %v", err)
	}
	// Failure in HalfOpen re-opens immediately.
	b.RecordFailure()

	if b.State() != StateOpen {
		t.Fatalf("expected re-open after failure in half-open, got %s", b.State())
	}
}

func TestHalfOpen_LimitedProbes(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      50 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	time.Sleep(100 * time.Millisecond)

	// Allow first probe (success threshold = 2, so limit = 2 probes).
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 1: expected Allow, got %v", err)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 2: expected Allow, got %v", err)
	}

	// Third probe should be rejected since limit is 2.
	err := b.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe 3: expected ErrCircuitOpen (limit reached), got %v", err)
	}

	if b.State() != StateHalfOpen {
		t.Fatalf("expected still half-open, got %s", b.State())
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state  State
		expect string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.expect {
			t.Errorf("State(%d).String() = %q, want %q", tc.state, got, tc.expect)
		}
	}
}

func TestErrCircuitOpen(t *testing.T) {
	if !errors.Is(ErrCircuitOpen, ErrCircuitOpen) {
		t.Fatal("ErrCircuitOpen should be comparable with errors.Is")
	}
}

// --- Metrics ---

func TestMetrics_Snapshot(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Window:           30 * time.Second,
		OpenTimeout:      30 * time.Second,
	}
	b := NewBreaker(cfg)

	m := b.Metrics()
	if m.State != StateClosed {
		t.Fatalf("expected metrics state closed, got %s", m.State)
	}
	if m.FailureCount != 0 {
		t.Fatalf("expected 0 failures, got %d", m.FailureCount)
	}

	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()

	m = b.Metrics()
	if m.FailureCount != 2 {
		t.Fatalf("expected 2 failures, got %d", m.FailureCount)
	}
}

func TestMetrics_WindowProgress(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Window:  100 * time.Millisecond,
	}
	b := NewBreaker(cfg)

	m := b.Metrics()
	if m.WindowProgress < 0 || m.WindowProgress > 100 {
		t.Fatalf("WindowProgress should be between 0 and 100, got %f", m.WindowProgress)
	}
}

// --- Concurrency ---

func TestBreaker_ConcurrentAccess(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 100,
		SuccessThreshold: 2,
		OpenTimeout:      30 * time.Second,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Allow()
			b.RecordFailure()
			_ = b.Metrics()
		}()
	}
	wg.Wait()

	// Verify consistent state.
	m := b.Metrics()
	if m.FailureCount == 0 || m.FailureCount > 100 {
		t.Fatalf("unexpected failure count: %d", m.FailureCount)
	}
}

func TestBreaker_ConcurrentHalfOpenTransitions(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      50 * time.Millisecond,
		Window:           30 * time.Second,
	}
	b := NewBreaker(cfg)

	for i := 0; i < 3; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("request %d: should allow, got %v", i, err)
		}
		b.RecordFailure()
	}

	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Allow()
		}()
	}
	wg.Wait()
}

func TestBreaker_SuccessInClosedResetsWindow(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 3,
		Window:           100 * time.Millisecond,
		OpenTimeout:      30 * time.Second,
	}
	b := NewBreaker(cfg)

	// 2 failures.
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()

	// Success in closed state should reset the window.
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordSuccess()

	// Wait for old window to expire.
	time.Sleep(150 * time.Millisecond)

	// 2 more failures — still below threshold since window was reset by success.
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()
	if err := b.Allow(); err != nil {
		t.Fatalf("should allow, got %v", err)
	}
	b.RecordFailure()

	if b.State() != StateClosed {
		t.Fatalf("expected closed (window reset), got %s", b.State())
	}
}

// The coverage baseline pins pkg/circuit above 93%: Allow's fail-closed
// default branch, the HalfOpen probe-limit rejection and safeInt32 clamping
// were uncovered after the static-analysis remediation pass.

func TestAllow_UnknownStateFailsClosed(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Second,
		Window:           time.Second,
	})
	// Simulate a corrupted state value: an unknown state must fail closed.
	b.state.Store(int32(99))
	b.mu.Lock()
	b.st = State(99)
	b.mu.Unlock()

	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("unknown state must fail closed, got %v", err)
	}
}

func TestAllow_HalfOpenRejectsProbeBeyondLimit(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1, // halfOpenLimit = 1
		OpenTimeout:      time.Second,
		Window:           time.Second,
	})
	b.state.Store(int32(StateHalfOpen))
	b.mu.Lock()
	b.st = StateHalfOpen
	b.mu.Unlock()

	if err := b.Allow(); err != nil {
		t.Fatalf("first HalfOpen probe must be allowed, got %v", err)
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe beyond the HalfOpen limit must be rejected, got %v", err)
	}
}

// TestAllow_HalfOpenProbeLimitInLockedPath models a caller that observed an
// Open atomic state immediately before another caller moved the protected
// state to HalfOpen. This synthetic stale observation deterministically
// covers the locked StateOpen path without relying on scheduler timing.
func TestAllow_HalfOpenProbeLimitInLockedPath(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1, // halfOpenLimit = 1
		OpenTimeout:      time.Second,
		Window:           time.Second,
	})

	// Trip the breaker to Open.
	if err := b.Allow(); err != nil {
		t.Fatalf("first request must be allowed, got %v", err)
	}
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}

	// Keep the atomic view at Open, but model the protected state after the
	// competing caller has transitioned to HalfOpen and occupied its only
	// probe slot. Allow must use the protected state after taking the lock,
	// reject this extra probe, and preserve the occupied slot.
	b.mu.Lock()
	b.st = StateHalfOpen
	b.mu.Unlock()
	b.halfOpenInFlight.Store(1)
	b.openAt.Store(time.Now().Add(-2 * time.Second).UnixNano())

	err := b.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe beyond the half-open limit in the locked path must be rejected, got %v", err)
	}
	if got := b.State(); got != StateOpen {
		t.Fatalf("synthetic stale atomic state must remain open, got %s", got)
	}
	b.mu.Lock()
	protectedState := b.st
	b.mu.Unlock()
	if protectedState != StateHalfOpen {
		t.Fatalf("protected state must remain half-open, got %s", protectedState)
	}
	// The rejected probe must neither reset nor leak the occupied slot.
	if got := b.halfOpenInFlight.Load(); got != 1 {
		t.Fatalf("rejected probe must decrement in-flight back to 1, got %d", got)
	}
}

// TestAllow_StaleOpenSnapshotDoesNotReviveClosedState models the other locked
// outcome: the caller's atomic view is still Open, but the protected state
// has already closed. An expired timeout must not revive that closed breaker.
func TestAllow_StaleOpenSnapshotDoesNotReviveClosedState(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Second,
		Window:           time.Second,
	})
	if err := b.Allow(); err != nil {
		t.Fatalf("first request must be allowed, got %v", err)
	}
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}

	// Preserve the synthetic stale atomic Open observation while the
	// mutex-protected state reflects a completed recovery to Closed.
	b.mu.Lock()
	b.st = StateClosed
	b.mu.Unlock()
	b.openAt.Store(time.Now().Add(-2 * time.Second).UnixNano())
	const occupiedProbeSlots = int32(2)
	b.halfOpenInFlight.Store(occupiedProbeSlots)

	err := b.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("stale open observation must be rejected after protected close, got %v", err)
	}
	if got := b.State(); got != StateOpen {
		t.Fatalf("synthetic stale atomic state must remain open, got %s", got)
	}
	b.mu.Lock()
	protectedState := b.st
	b.mu.Unlock()
	if protectedState != StateClosed {
		t.Fatalf("protected closed state must not be revived, got %s", protectedState)
	}
	if got := b.halfOpenInFlight.Load(); got != occupiedProbeSlots {
		t.Fatalf("closed-state rejection must not change probe slots: got %d, want %d", got, occupiedProbeSlots)
	}
}

func TestSafeInt32_Clamps(t *testing.T) {
	if got := safeInt32(-5); got != 0 {
		t.Fatalf("negative must clamp to 0, got %d", got)
	}
	if got := safeInt32(math.MaxInt32 + 10); got != math.MaxInt32 {
		t.Fatalf("overflow must clamp to MaxInt32, got %d", got)
	}
	if got := safeInt32(3); got != 3 {
		t.Fatalf("in-range value must pass through, got %d", got)
	}
}

// TestHalfOpen_ProbeSlotsResetPerEpoch is the regression test for the
// stuck-open bug: a failed probe used to leak its half-open slot (the
// decrement only existed on the success path), so each failed probe epoch
// permanently consumed budget until every future Allow returned
// ErrCircuitOpen. After two failed epochs the third attempt must be admitted.
func TestHalfOpen_ProbeSlotsResetPerEpoch(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1, // halfOpenLimit = 1
		OpenTimeout:      20 * time.Millisecond,
		Window:           time.Minute,
	}
	b := NewBreaker(cfg)

	b.RecordFailure() // → Open

	for epoch := 1; epoch <= 2; epoch++ {
		time.Sleep(3 * cfg.OpenTimeout)
		if err := b.Allow(); err != nil {
			t.Fatalf("epoch %d: probe must be admitted after the open timeout, got %v", epoch, err)
		}
		if got := b.Metrics().HalfOpenInFlight; got != 1 {
			t.Fatalf("epoch %d: expected one in-flight probe, got %d", epoch, got)
		}
		b.RecordFailure() // re-opens; previously leaked the probe slot
		if got := b.Metrics().HalfOpenInFlight; got != 0 {
			t.Fatalf("epoch %d: failed probe must release its slot, got %d in flight", epoch, got)
		}
	}

	time.Sleep(3 * cfg.OpenTimeout)
	if err := b.Allow(); err != nil {
		t.Fatalf("third attempt after two failed probe epochs must be allowed, got %v", err)
	}
}

// TestAllow_OpenToHalfOpen_ResetsLeakedProbeSlots pins the epoch reset: probe
// slots leaked by a previous half-open epoch must not survive the locked
// Open→HalfOpen transition.
func TestAllow_OpenToHalfOpen_ResetsLeakedProbeSlots(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1, // halfOpenLimit = 1
		OpenTimeout:      time.Second,
		Window:           time.Second,
	})

	if err := b.Allow(); err != nil {
		t.Fatalf("first request must be allowed, got %v", err)
	}
	b.RecordFailure() // → Open
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}

	// Simulate slots leaked by a previous half-open epoch.
	b.halfOpenInFlight.Store(3)
	b.openAt.Store(time.Now().Add(-2 * time.Second).UnixNano())

	if err := b.Allow(); err != nil {
		t.Fatalf("epoch transition must reset leaked slots and admit the probe, got %v", err)
	}
	if got := b.halfOpenInFlight.Load(); got != 1 {
		t.Fatalf("in-flight must equal the single admitted probe after the reset, got %d", got)
	}
}

// TestRecordSuccess_HalfOpenCloseCountsRecovery pins CircuitRecoveries: the
// HalfOpen→Closed transition must count as a recovery (wasOpen compared
// against StateOpen and never fired).
func TestRecordSuccess_HalfOpenCloseCountsRecovery(t *testing.T) {
	name := "recovery-count-regression"
	b := NewBreaker(Config{
		Name:             name,
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      20 * time.Millisecond,
		Window:           time.Minute,
	})

	b.RecordFailure() // → Open
	before := testutil.ToFloat64(metrics.CircuitRecoveries.WithLabelValues(name))

	time.Sleep(60 * time.Millisecond)
	if err := b.Allow(); err != nil {
		t.Fatalf("expected probe to be admitted in half-open, got %v", err)
	}
	b.RecordSuccess() // closes the circuit — a recovery

	after := testutil.ToFloat64(metrics.CircuitRecoveries.WithLabelValues(name))
	if after != before+1 {
		t.Fatalf("half-open→closed must increment CircuitRecoveries, delta got %v", after-before)
	}
}

// TestBreaker_ConcurrentAllowRecordMixed hammers Allow/RecordSuccess/
// RecordFailure concurrently (run under -race) and asserts the probe-slot
// accounting stays bounded: leaked slots used to wedge the breaker open.
func TestBreaker_ConcurrentAllowRecordMixed(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 2,
		OpenTimeout:      time.Millisecond,
		Window:           time.Minute,
	}
	b := NewBreaker(cfg)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if err := b.Allow(); err != nil {
					continue
				}
				if (g+i)%3 == 0 {
					b.RecordFailure()
				} else {
					b.RecordSuccess()
				}
			}
		}(g)
	}
	wg.Wait()

	if m := b.Metrics(); m.HalfOpenInFlight < 0 || int(m.HalfOpenInFlight) > cfg.SuccessThreshold {
		t.Fatalf("half-open in-flight must stay within [0, %d], got %d", cfg.SuccessThreshold, m.HalfOpenInFlight)
	}
	switch s := b.State(); s {
	case StateClosed, StateOpen, StateHalfOpen:
	default:
		t.Fatalf("impossible state after mixed traffic: %s", s)
	}
}
