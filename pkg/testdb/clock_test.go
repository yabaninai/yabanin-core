package testdb

import (
	"testing"
	"time"
)

// TestWaitClockCaughtUp: the helper must return quickly on a healthy stand
// (DB clock ≈ host clock) — the W-VER report-flake guard.
func TestWaitClockCaughtUp(t *testing.T) {
	pool := Postgres(t)
	done := make(chan struct{})
	go func() {
		WaitClockCaughtUp(t, pool)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("WaitClockCaughtUp did not return on a healthy stand")
	}
}
