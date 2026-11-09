package circuit

// N09-P01-T07 boundary regression corpus — the circuit consumer seam
// (pkg/circuit).
//
// The breaker's unit guarantees are pinned by breaker_test.go (open/refuse/
// half-open/close lifecycle, thresholds, window accounting). This corpus
// adds the no-repeat-stack regression dimension: what a REFUSAL does to the
// breaker's own books, and the single-failure edge of the threshold.
//
// Two properties are pinned here:
//  1. An Allow() rejection records nothing — admission refusals must never
//     inflate FailureCount nor extend the open state, or every routing
//     attempt against an open endpoint would make its outage look worse
//     than it is (a self-reinforcing penalty spiral).
//  2. A threshold-1 breaker opens on the first real failure and a failure
//     recorded while open is ignored — the penalty is per incident, never
//     doubled by bookkeeping that arrives after the verdict.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN09P1T07_Boundary_AllowRejectionRecordsNothing opens a threshold-1
// breaker with one real failure, then hammers Allow(): every refusal
// surfaces the sentinel and the books stay exactly where the real failure
// left them.
func TestN09P1T07_Boundary_AllowRejectionRecordsNothing(t *testing.T) {
	b := NewBreaker(Config{
		Name:             "n09p1t07-refusal",
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	})
	b.RecordFailure()
	require.Equal(t, StateOpen, b.State(), "precondition: the real failure opened the breaker")
	before := b.Metrics()

	for i := 0; i < 3; i++ {
		err := b.Allow()
		require.ErrorIs(t, err, ErrCircuitOpen,
			"refusal %d must surface the sentinel the caller maps to 503", i+1)
	}

	after := b.Metrics()
	assert.Equal(t, StateOpen, b.State(), "refusals never change the verdict")
	assert.Equal(t, before.FailureCount, after.FailureCount,
		"an admission refusal records no failure")
	assert.Equal(t, before.SuccessCount, after.SuccessCount,
		"an admission refusal records no success")
	assert.Equal(t, before.HalfOpenInFlight, after.HalfOpenInFlight,
		"an admission refusal leaves no half-open flight behind")
}

// TestN09P1T07_Boundary_ThresholdOneAndNoDoublePenalty pins the
// single-failure edge: the first failure of a fresh breaker opens it
// immediately, and a failure signal that arrives while open changes
// nothing — the incident is already counted once.
func TestN09P1T07_Boundary_ThresholdOneAndNoDoublePenalty(t *testing.T) {
	b := NewBreaker(Config{
		Name:             "n09p1t07-threshold-one",
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	})

	require.NoError(t, b.Allow(), "a fresh breaker admits")
	assert.Equal(t, StateClosed, b.State())

	b.RecordFailure()

	assert.Equal(t, StateOpen, b.State(),
		"a threshold-1 breaker opens on the first real failure")
	require.ErrorIs(t, b.Allow(), ErrCircuitOpen)

	b.RecordFailure() // late bookkeeping for the same incident

	m := b.Metrics()
	assert.Equal(t, 1, m.FailureCount,
		"the failure is counted once — a recorded failure while open is ignored")
	assert.Equal(t, 0, m.SuccessCount)
	assert.Equal(t, StateOpen, b.State())
	require.ErrorIs(t, b.Allow(), ErrCircuitOpen)
}
