package classifier

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_ClosedToOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Second, 1)

	if cb.State() != CircuitClosed {
		t.Fatalf("initial state should be closed, got %s", cb.State())
	}

	// Record 2 failures — still closed
	for i := 0; i < 2; i++ {
		cb.RecordFailure()
		if !cb.Allow() {
			t.Errorf("after %d failures, should still allow requests", i+1)
		}
	}

	if cb.State() != CircuitClosed {
		t.Fatalf("after 2 failures should be closed, got %s", cb.State())
	}

	// 3rd failure → open
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("after 3 failures should be open, got %s", cb.State())
	}

	// Should NOT allow after going open
	if cb.Allow() {
		t.Error("should not allow when circuit is open")
	}
}

func TestCircuitBreaker_OpenToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 1)

	cb.RecordFailure() // → open
	if cb.State() != CircuitOpen {
		t.Fatalf("should be open after failure")
	}

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Should transition to half-open and allow probe
	if !cb.Allow() {
		t.Error("should allow after open timeout (half-open)")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("should be half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenSuccess(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 1)

	cb.RecordFailure() // → open
	time.Sleep(100 * time.Millisecond)
	cb.Allow() // half-open

	// Success in half-open → closed
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Fatalf("should be closed after half-open success, got %s", cb.State())
	}
	if !cb.Allow() {
		t.Error("should allow when circuit is closed")
	}
}

func TestCircuitBreaker_HalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 1)

	cb.RecordFailure() // → open
	time.Sleep(100 * time.Millisecond)
	cb.Allow() // half-open

	// Failure in half-open → back to open
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("should be open after half-open failure, got %s", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Second, 1)

	cb.RecordFailure() // 1
	cb.RecordFailure() // 2

	// Success should reset counter
	cb.RecordSuccess()
	cb.RecordFailure() // 1 (reset by success)
	cb.RecordFailure() // 2
	cb.RecordFailure() // 3 → open

	if cb.State() != CircuitOpen {
		t.Fatalf("should be open after reset+3 failures, got %s", cb.State())
	}
}

func TestCircuitBreaker_MultipleSuccessesHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 2) // need 2 successes in half-open

	cb.RecordFailure() // → open
	time.Sleep(100 * time.Millisecond)

	cb.Allow()         // half-open
	cb.RecordSuccess() // 1/2
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("should still be half-open after 1 success, got %s", cb.State())
	}

	cb.RecordSuccess() // 2/2 → closed
	if cb.State() != CircuitClosed {
		t.Fatalf("should be closed after 2 successes in half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_StateRefreshesOpenTimer(t *testing.T) {
	cb := NewCircuitBreaker(1, 200*time.Millisecond, 1)

	cb.RecordFailure() // → open at T0
	if cb.State() != CircuitOpen {
		t.Fatalf("should be open")
	}

	// At T150ms — still open (before timeout)
	time.Sleep(150 * time.Millisecond)
	// State() is a pure read and must not transition to half-open;
	// only Allow() performs the Open→HalfOpen transition.
	if cb.Allow() {
		t.Error("should not allow before timeout")
	}

	// After 250ms total → past openUntil (200ms), should be half-open
	time.Sleep(150 * time.Millisecond)
	if !cb.Allow() {
		t.Error("should allow after open timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("should be half-open after timeout, got %s", cb.State())
	}
}

func TestCircuitBreaker_ConcurrentSafety(t *testing.T) {
	cb := NewCircuitBreaker(100, 1*time.Second, 1)
	done := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		go func() {
			cb.Allow()
			cb.RecordSuccess()
			done <- true
		}()
	}

	for i := 0; i < 200; i++ {
		<-done
	}
	close(done)
}

// TestCircuitBreaker_HalfOpenLimitsConcurrentProbes pins the half-open probe
// limit: HalfOpen used to admit every caller, and a probe slot now must be
// released before the next epoch can use it again.
func TestCircuitBreaker_HalfOpenLimitsConcurrentProbes(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 1) // successThreshold=1 → 1 probe

	cb.RecordFailure() // → open
	time.Sleep(100 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("first half-open probe must be admitted")
	}
	if cb.Allow() {
		t.Fatal("second concurrent probe must be rejected while the slot is held")
	}

	cb.RecordFailure() // probe failed → open; the slot must be released
	time.Sleep(100 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("a failed probe epoch must not wedge the breaker; the new epoch must admit a probe")
	}
}

// TestCircuitBreaker_StateDoesNotMutate pins that State is a pure read: only
// Allow performs the Open→HalfOpen transition.
func TestCircuitBreaker_StateDoesNotMutate(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond, 1)

	cb.RecordFailure() // → open
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open, got %s", cb.State())
	}

	time.Sleep(100 * time.Millisecond)
	if cb.State() != CircuitOpen {
		t.Fatalf("State must not mutate state; got %s", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("Allow must transition to half-open and admit the probe")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open after Allow, got %s", cb.State())
	}
}

// TestCircuitHealthChecker_DoubleStartStop pins idempotent lifecycle: a
// second Start must not spawn another loop and a second Stop must not panic
// on a double close of the done channel.
func TestCircuitHealthChecker_DoubleStartStop(t *testing.T) {
	hc := NewCircuitHealthChecker(NewRuleTier(), NewCircuitBreaker(3, time.Second, 1), slog.Default())

	hc.Start(context.Background())
	hc.Start(context.Background()) // must not start a second loop
	hc.Stop()
	hc.Stop() // must not panic on double close
}

// TestCircuitBreaker_ConcurrentMixedOutcomes hammers Allow/RecordSuccess/
// RecordFailure concurrently (run under -race) across many open/half-open
// epochs and asserts the state machine never leaves its domain.
func TestCircuitBreaker_ConcurrentMixedOutcomes(t *testing.T) {
	cb := NewCircuitBreaker(2, time.Millisecond, 1)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if !cb.Allow() {
					continue
				}
				if (g+i)%3 == 0 {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}
			}
		}(g)
	}
	wg.Wait()

	switch s := cb.State(); s {
	case CircuitClosed, CircuitOpen, CircuitHalfOpen:
	default:
		t.Fatalf("impossible state after mixed traffic: %s", s)
	}
}
