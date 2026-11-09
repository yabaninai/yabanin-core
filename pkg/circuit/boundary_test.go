package circuit

import (
	"errors"
	"testing"
	"time"
)

// N09-P02-T07 boundary corpus, aspect pkg/circuit: the breaker state machine
// pinned at its configuration and transition boundaries. Every case pins
// prior behavior at an exact edge — below/at/above a threshold, the degenerate
// minimum configuration, the hint floor and the jitter endpoints — so a future
// change that shifts any boundary is an observable test failure, not a silent
// semantic drift. All cases are deterministic: jitter draws are injected and
// wall-clock sleeps are orders of magnitude larger than the boundary they
// guarantee to cross.

// TestBreaker_BoundaryNegativeConfigFallsBackToDefaults pins the clamp
// boundary below the minimum: every numeric config field individually set to
// a negative value must fall back to the same default the zero value gets.
// A clamp that only handled 0 (not <0) would silently change trip and probe
// semantics for misconfigured breakers.
func TestBreaker_BoundaryNegativeConfigFallsBackToDefaults(t *testing.T) {
	def := DefaultConfig()
	fields := []struct {
		name  string
		apply func(*Config)
		read  func(Config) time.Duration
		want  time.Duration
	}{
		{
			name:  "negative FailureThreshold",
			apply: func(c *Config) { c.FailureThreshold = -1 },
			read:  func(c Config) time.Duration { return time.Duration(c.FailureThreshold) },
			want:  time.Duration(def.FailureThreshold),
		},
		{
			name:  "negative SuccessThreshold",
			apply: func(c *Config) { c.SuccessThreshold = -1 },
			read:  func(c Config) time.Duration { return time.Duration(c.SuccessThreshold) },
			want:  time.Duration(def.SuccessThreshold),
		},
		{
			name:  "negative OpenTimeout",
			apply: func(c *Config) { c.OpenTimeout = -time.Second },
			read:  func(c Config) time.Duration { return c.OpenTimeout },
			want:  def.OpenTimeout,
		},
		{
			name:  "negative Window",
			apply: func(c *Config) { c.Window = -time.Second },
			read:  func(c Config) time.Duration { return c.Window },
			want:  def.Window,
		},
	}
	for _, tc := range fields {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			tc.apply(&cfg)
			b := NewBreaker(cfg)

			if got := tc.read(b.cfg); got != tc.want {
				t.Fatalf("negative value must fall back to the default %v, got %v", tc.want, got)
			}

			// The breaker must be fully usable at the clamped boundary:
			// trip it with the effective (default) threshold and observe
			// the open state.
			for i := 0; i < def.FailureThreshold; i++ {
				b.RecordFailure()
			}
			if b.State() != StateOpen {
				t.Fatalf("breaker clamped to defaults must trip at the default threshold, state %s", b.State())
			}
			if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
				t.Fatalf("open breaker must refuse, got %v", err)
			}
		})
	}
}

// TestBreaker_BoundaryFailureThresholdOne pins the minimal positive
// threshold: zero failures stay closed, the very first failure trips. This is
// the N-1/N boundary at its smallest — the "one strike" guard that contains a
// hard-down upstream after a single observed failure.
func TestBreaker_BoundaryFailureThresholdOne(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 1
	cfg.OpenTimeout = 30 * time.Millisecond
	cfg.Window = time.Minute
	b := NewBreaker(cfg)

	if err := b.Allow(); err != nil {
		t.Fatalf("zero failures must stay closed, got %v", err)
	}
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("one failure at threshold 1 must trip, state %s", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("tripped breaker must refuse pre-upstream, got %v", err)
	}
}

// TestBreaker_BoundaryCloseResetsFailureCount pins the accounting boundary on
// recovery: closing from HalfOpen must clear the failure count, so the closed
// breaker needs a fresh full window of failures to trip again. A stale count
// carried across recovery would re-trip the breaker on the first post-recovery
// failure — turning a recovered upstream into a flap loop.
func TestBreaker_BoundaryCloseResetsFailureCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 2
	cfg.SuccessThreshold = 1
	cfg.OpenTimeout = 2 * time.Millisecond
	cfg.Window = time.Minute
	b := NewBreaker(cfg)

	b.RecordFailure()
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open after threshold failures, state %s", b.State())
	}
	time.Sleep(5 * time.Millisecond) // open timeout elapses (2ms)

	if err := b.Allow(); err != nil {
		t.Fatalf("probe must be admitted, got %v", err)
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("single success at threshold 1 must close, state %s", b.State())
	}

	// First failure after recovery: a stale count (2 carried over) would
	// re-trip here. The boundary contract says closed.
	b.RecordFailure()
	if b.State() != StateClosed {
		t.Fatalf("post-recovery failure must start a fresh window, state %s", b.State())
	}
	// Only the second failure in the new window trips.
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("second post-recovery failure must trip, state %s", b.State())
	}
}

// TestBreaker_BoundaryHalfOpenLastProbeFailsReopens pins the recovery edge:
// when the final probe before the success threshold fails, the breaker
// re-opens immediately and stays fully usable — no wedged probe slot, and a
// fresh refusal hint — so a recovery that fails at the last step degrades to
// the ordinary open state instead of a dead breaker.
func TestBreaker_BoundaryHalfOpenLastProbeFailsReopens(t *testing.T) {
	restore := withRetryAfterRandom(t, func() float64 { return 0 })
	defer restore()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 2 // two probes must both succeed to close
	cfg.OpenTimeout = 2 * time.Millisecond
	cfg.Window = time.Minute
	b := NewBreaker(cfg)

	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open, state %s", b.State())
	}
	time.Sleep(5 * time.Millisecond)

	if err := b.Allow(); err != nil {
		t.Fatalf("probe 1 must be admitted, got %v", err)
	}
	b.RecordSuccess() // success 1 of 2 — at the threshold-1 boundary, still half-open
	if b.State() != StateHalfOpen {
		t.Fatalf("threshold-1 successes must stay half-open, state %s", b.State())
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("probe 2 must be admitted, got %v", err)
	}
	b.RecordFailure() // the last step fails

	if b.State() != StateOpen {
		t.Fatalf("failure at the recovery boundary must re-open, state %s", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("re-opened breaker must refuse, got %v", err)
	}
	// The refusal hint must be a fresh positive open-epoch hint, not a
	// stale half-open fraction: recovery failed, so clients wait out the
	// full open timeout.
	if ra := b.RetryAfter(); ra <= 0 || ra > cfg.OpenTimeout {
		t.Fatalf("re-open hint must be in (0, OpenTimeout], got %v", ra)
	}

	// No wedge: after the re-open timeout a fresh probe is admitted.
	time.Sleep(5 * time.Millisecond)
	if err := b.Allow(); err != nil {
		t.Fatalf("post-re-open probe must be admitted (no slot leak), got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("expected fresh half-open epoch, state %s", b.State())
	}
}

// TestBreaker_BoundaryHalfOpenHintFloorsAtMinimum pins the degenerate-config
// boundary: with the smallest positive OpenTimeout the scaled half-open hint
// (OpenTimeout/10) computes to zero, and the floor must replace it with
// minRetryHint so refused probes are never sent straight back. A missing floor
// would amplify re-strikes precisely for breakers tuned to fail fast.
func TestBreaker_BoundaryHalfOpenHintFloorsAtMinimum(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 1
	cfg.OpenTimeout = 5 * time.Nanosecond // smallest practical positive timeout: 5ns/10 == 0
	cfg.Window = time.Minute
	b := NewBreaker(cfg)

	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open, state %s", b.State())
	}
	// Guarantee the 5ns open timeout has elapsed (the sleep is six orders
	// of magnitude larger), so Allow flips straight to HalfOpen.
	time.Sleep(50 * time.Microsecond)

	if err := b.Allow(); err != nil {
		t.Fatalf("probe must be admitted, got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open, state %s", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("exhausted probe budget must refuse, got %v", err)
	}
	if ra := b.RetryAfter(); ra != minRetryHint {
		t.Fatalf("degenerate half-open hint must floor at %v, got %v", minRetryHint, ra)
	}
}

// TestJitterHint_Boundaries pins the pure hint-widening function at its
// endpoint matrix: disabled (fraction 0, negative fraction, nil draw, zero
// base) leaves the hint untouched, and at the other end fraction values above
// 1 clamp to double the base with draw 1. All values are exact — no clock, no
// randomness (the draw is a test-controlled sequence).
func TestJitterHint_Boundaries(t *testing.T) {
	base := 100 * time.Millisecond
	cases := []struct {
		name     string
		base     time.Duration
		fraction float64
		draw     func() float64
		want     time.Duration
	}{
		{name: "zero base stays zero", base: 0, fraction: 0.5, draw: func() float64 { return 1 }, want: 0},
		{name: "negative base stays as-is", base: -time.Millisecond, fraction: 0.5, draw: func() float64 { return 1 }, want: -time.Millisecond},
		{name: "zero fraction is exact", base: base, fraction: 0, draw: func() float64 { return 1 }, want: base},
		{name: "negative fraction is exact", base: base, fraction: -0.5, draw: func() float64 { return 1 }, want: base},
		{name: "nil draw is exact", base: base, fraction: 0.5, draw: nil, want: base},
		{name: "draw 0 widens nothing", base: base, fraction: 0.5, draw: func() float64 { return 0 }, want: base},
		{
			name:     "draw 1 at fraction 0.5 is exactly 1.5x",
			base:     base,
			fraction: 0.5,
			draw:     func() float64 { return 1 },
			want:     base + base/2,
		},
		{
			name:     "fraction above 1 clamps to exactly 2x",
			base:     base,
			fraction: 5,
			draw:     func() float64 { return 1 },
			want:     2 * base,
		},
		{
			name:     "draw 1 at fraction 1 is exactly 2x",
			base:     base,
			fraction: 1,
			draw:     func() float64 { return 1 },
			want:     2 * base,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jitterHint(tc.base, tc.fraction, tc.draw); got != tc.want {
				t.Fatalf("jitterHint(%v, %v, draw) = %v, want %v", tc.base, tc.fraction, got, tc.want)
			}
		})
	}
}
