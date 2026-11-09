package circuit

// N09-P01-T09 [compatibility] — old/new configuration walk for pkg/circuit.
//
// The walk proves by behaviour (never by reading struct defaults) that the
// historical configuration shapes keep working through the real consumers:
//
//	legacy minimal breaker  Config{Name, Enabled}          — default thresholds trip
//	legacy partial shape    only OpenTimeout set            — defaults fill the rest
//	legacy Map call shape   NewMap(cfg, 0, nil), key-scoped — inherited defaults per key
//	out-of-band values      negative thresholds             — normalized to defaults
//
// Reused lane-pinned contract: halfOpenLimit = SuccessThreshold (T05), here
// re-proven under legacy shapes where SuccessThreshold is unset/invalid.
// Existing coverage intentionally not duplicated: global-key kill-switch
// sharing (TestCircuitMap_GlobalKeySharesOneBreaker), LRU bounds and
// eviction, hook logging, disabled-breaker pass-through.

import (
	"errors"
	"testing"
	"time"
)

// t09TripAtDefaultThreshold drives b with n failures through the real
// Allow/RecordFailure consumer pair and reports the first Allow rejection.
func t09TripAtDefaultThreshold(t *testing.T, b *Breaker, failures int) {
	t.Helper()
	for i := 0; i < failures; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("failure %d: breaker tripped early: %v", i+1, err)
		}
		b.RecordFailure()
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("after %d failures: want ErrCircuitOpen, got %v", failures, err)
	}
	if b.State() != StateOpen {
		t.Fatalf("after %d failures: state %s, want open", failures, b.State())
	}
}

// TestN09P1T09_Compat_LegacyMinimalConfigTripsAtDefaults pins the old
// single-breaker literal — Config{Name, Enabled} with every threshold left
// unset — the shape historical call sites constructed before the map landed.
// It must still trip at the documented default of ten failures, count no
// double penalties while open, and stay open until the timeout elapses.
func TestN09P1T09_Compat_LegacyMinimalConfigTripsAtDefaults(t *testing.T) {
	b := NewBreaker(Config{Name: "legacy-gw", Enabled: true})

	t09TripAtDefaultThreshold(t, b, 10)

	// Additional failures while open are ignored (no double penalty) and the
	// rejection persists — the default OpenTimeout (30s) has not elapsed.
	b.RecordFailure()
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("extra failure while open changed rejection: %v", err)
	}
	if got := b.Metrics().FailureCount; got != 10 {
		t.Fatalf("failure count while open: got %d, want 10 (no double counting)", got)
	}
}

// TestN09P1T09_Compat_UnsetSuccessThresholdGetsTwoProbes walks the partial
// legacy shape — only OpenTimeout overridden, SuccessThreshold unset —
// through the full open→half-open→closed cycle, re-proving the pinned
// halfOpenLimit=SuccessThreshold contract where the threshold is defaulted
// (two probes, third rejected, recovery on two successes).
func TestN09P1T09_Compat_UnsetSuccessThresholdGetsTwoProbes(t *testing.T) {
	b := NewBreaker(Config{Name: "legacy-partial", Enabled: true, OpenTimeout: 20 * time.Millisecond})

	t09TripAtDefaultThreshold(t, b, 10)

	time.Sleep(60 * time.Millisecond) // default-normalized OpenTimeout overridden; thresholds still defaults

	if err := b.Allow(); err != nil {
		t.Fatalf("probe 1: want Allow, got %v", err)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 2: want Allow, got %v", err)
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe 3: want ErrCircuitOpen (default SuccessThreshold=2), got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("state %s, want half-open", b.State())
	}

	b.RecordSuccess()
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("after two probe successes: state %s, want closed", b.State())
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("recovered breaker must admit traffic: %v", err)
	}
}

// TestN09P1T09_Compat_NegativeThresholdsNormalizeToDefaults pins tolerance
// for out-of-band legacy values: negative thresholds are indistinguishable
// from unset ones — same trip point, same probe limit, same recovery.
func TestN09P1T09_Compat_NegativeThresholdsNormalizeToDefaults(t *testing.T) {
	b := NewBreaker(Config{
		Name:             "legacy-negative",
		Enabled:          true,
		FailureThreshold: -3,
		SuccessThreshold: -1,
		OpenTimeout:      20 * time.Millisecond,
	})

	t09TripAtDefaultThreshold(t, b, 10)

	time.Sleep(60 * time.Millisecond)

	if err := b.Allow(); err != nil {
		t.Fatalf("probe 1: want Allow, got %v", err)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 2: want Allow, got %v", err)
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe 3: want ErrCircuitOpen (normalized SuccessThreshold=2), got %v", err)
	}
}

// TestN09P1T09_Compat_LegacyMapCallShapeInheritsDefaults walks the historical
// Map construction — zero maxEntries, bare config, unscoped endpoint keys —
// and proves each endpoint breaker inherits the normalized defaults instead
// of the zero values (a zero threshold would trip on the first failure).
func TestN09P1T09_Compat_LegacyMapCallShapeInheritsDefaults(t *testing.T) {
	m := NewMap(Config{Name: "legacy-map", Enabled: true}, 0, nil)

	b := m.Breaker("ep-one")
	if b == nil {
		t.Fatal("legacy map call shape returned nil breaker")
	}
	t09TripAtDefaultThreshold(t, b, 10)

	// A sibling endpoint is unaffected (per-key isolation under the legacy
	// call shape) and its breaker also starts closed with default thresholds.
	other := m.Breaker("ep-two")
	if err := other.Allow(); err != nil {
		t.Fatalf("sibling endpoint must be unaffected: %v", err)
	}
	if other.State() != StateClosed {
		t.Fatalf("sibling endpoint state %s, want closed", other.State())
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("map length: got %d, want 2", got)
	}
}
