package circuit

// N09-P01-T08 recovery corpus — the per-endpoint breaker (pkg/circuit).
//
// The lifecycle transitions and the probe-slot accounting are pinned by
// breaker_test.go (TestHalfOpen_ProbeSlotsResetPerEpoch,
// TestAllow_OpenToHalfOpen_ResetsLeakedProbeSlots,
// TestRecordSuccess_HalfOpenCloseCountsRecovery, the half-open concurrency
// tests). This corpus adds the recovery dimension those leave open: a FULL
// interrupted-incident arc driven through the public API only — a probe
// whose outcome never arrives (the process died mid-probe), the frozen
// refusal window while the probe is in flight, and the LATE outcome
// replayed after the restart, which must restore service with fresh books;
// plus the failed-probe re-open arc with hooks firing on every transition.

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN09P1T08_Recovery_LostProbeOutcomeArcRestoresService walks the arc of
// an interrupted probe (SuccessThreshold 1 → a single in-flight probe):
//
//  1. an incident trips the breaker open;
//  2. during the open window, refusals (and a racing duplicate failure)
//     record nothing — the books keep exactly the one real failure;
//  3. the open timeout admits the probe; its outcome is LOST (the
//     interruption) — the breaker wedges half-open, refusing further
//     traffic without moving any book;
//  4. the late outcome arrives (the restarted probe owner reports) — the
//     circuit closes with fresh books and the recovery is counted exactly
//     once.
func TestN09P1T08_Recovery_LostProbeOutcomeArcRestoresService(t *testing.T) {
	var opens, recovers atomic.Int64
	cfg := Config{
		Name:             "t08-lost-probe",
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      20 * time.Millisecond,
		Window:           time.Minute,
		OnOpen:           func(string) { opens.Add(1) },
		OnRecover:        func(string) { recovers.Add(1) },
	}
	b := NewBreaker(cfg)

	// 1. The incident trips the breaker.
	b.RecordFailure()
	require.Equal(t, StateOpen, b.State())
	assert.EqualValues(t, 1, opens.Load())

	// 2. Refusal window: Allow refusals and a racing duplicate failure
	// record nothing — the books keep exactly the one real failure.
	require.ErrorIs(t, b.Allow(), ErrCircuitOpen)
	b.RecordFailure() // a caller that raced past Allow before the trip
	m := b.Metrics()
	assert.Equal(t, 1, m.FailureCount, "the duplicate failure during Open is ignored")
	assert.Equal(t, 0, m.SuccessCount)

	// 3. The open timeout admits the probe — then its outcome is lost.
	time.Sleep(3 * cfg.OpenTimeout)
	require.NoError(t, b.Allow())
	assert.Equal(t, StateHalfOpen, b.State())
	assert.EqualValues(t, 1, b.Metrics().HalfOpenInFlight)

	// Wedged window: the probe never reports. Further traffic is refused
	// and the books stay frozen — refusal is not bookkeeping.
	require.ErrorIs(t, b.Allow(), ErrCircuitOpen,
		"while the lost probe holds the only slot, nothing else is admitted")
	wedged := b.Metrics()
	assert.Equal(t, 1, wedged.FailureCount)
	assert.Equal(t, 0, wedged.SuccessCount)
	assert.EqualValues(t, 1, wedged.HalfOpenInFlight)
	assert.Equal(t, StateHalfOpen, b.State(),
		"the wedge is stable and safe: refusals only, no state drift")

	// 4. The late outcome arrives: the restarted probe owner reports the
	// success of the probe it had started. The slot is released, the
	// threshold is met and the circuit closes with fresh books.
	b.RecordSuccess()
	require.Equal(t, StateClosed, b.State())
	closed := b.Metrics()
	assert.Equal(t, 0, closed.FailureCount)
	assert.Equal(t, 0, closed.SuccessCount)
	assert.EqualValues(t, 0, closed.HalfOpenInFlight)
	assert.EqualValues(t, 1, recovers.Load(),
		"the half-open→closed transition counts exactly one recovery")
	assert.EqualValues(t, 1, opens.Load(), "no spurious re-open on the way back")
	require.NoError(t, b.Allow(), "service is restored for ordinary traffic")
}

// TestN09P1T08_Recovery_FailedProbeReopensThenReclosesWithFreshBooks pins
// the other half of the interrupted-incident story: the admitted probe's
// outcome arrives and it is a FAILURE. The probe slot must be released
// BEFORE the re-open (no leak into the next epoch), OnOpen fires again, the
// re-opened refusal window records nothing new, and the eventual recovery
// closes the circuit with zeroed books.
func TestN09P1T08_Recovery_FailedProbeReopensThenReclosesWithFreshBooks(t *testing.T) {
	var opens, recovers atomic.Int64
	cfg := Config{
		Name:             "t08-reopen",
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      20 * time.Millisecond,
		Window:           time.Minute,
		OnOpen:           func(string) { opens.Add(1) },
		OnRecover:        func(string) { recovers.Add(1) },
	}
	b := NewBreaker(cfg)

	// Incident → open.
	b.RecordFailure()
	require.Equal(t, StateOpen, b.State())
	assert.EqualValues(t, 1, opens.Load())

	// The probe is admitted and FAILS: immediate re-open, slot released.
	time.Sleep(3 * cfg.OpenTimeout)
	require.NoError(t, b.Allow())
	require.Equal(t, StateHalfOpen, b.State())
	b.RecordFailure()
	assert.Equal(t, StateOpen, b.State())
	assert.EqualValues(t, 0, b.Metrics().HalfOpenInFlight,
		"the failed probe released its slot before the re-open")
	assert.EqualValues(t, 2, opens.Load(),
		"the re-open fires OnOpen again — the hook sees every trip")

	// Re-opened refusal window: refusals and duplicates record nothing new.
	require.ErrorIs(t, b.Allow(), ErrCircuitOpen)
	b.RecordFailure() // duplicate during Open — ignored
	m := b.Metrics()
	assert.Equal(t, 1, m.FailureCount, "the duplicate failure during Open is ignored")
	assert.Equal(t, 0, m.SuccessCount)

	// The next epoch's probe succeeds: closed with fresh books.
	time.Sleep(3 * cfg.OpenTimeout)
	require.NoError(t, b.Allow())
	b.RecordSuccess()
	require.Equal(t, StateClosed, b.State())
	closed := b.Metrics()
	assert.Equal(t, 0, closed.FailureCount)
	assert.Equal(t, 0, closed.SuccessCount)
	assert.EqualValues(t, 0, closed.HalfOpenInFlight)
	assert.EqualValues(t, 1, recovers.Load())
	require.NoError(t, b.Allow(), "service is restored for ordinary traffic")
}
