package circuit

import (
	"testing"
	"time"
)

func TestBreaker_RetryAfter(t *testing.T) {
	// Each case drives the breaker into a state and then reads hints itself,
	// so a case controls exactly when the hint is read relative to Allow.
	cases := []struct {
		name          string
		setup         func(t *testing.T, b *Breaker) // drives the breaker into the state
		check         func(t *testing.T, b *Breaker)
		afterTimeouts int // OpenTimeout multiples to wait before the check
	}{
		{
			name: "disabled breaker has no hint",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				b.RecordFailure()
			},
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if ra := b.RetryAfter(); ra != 0 {
					t.Fatalf("disabled breaker must report 0, got %v", ra)
				}
			},
		},
		{
			name: "closed breaker has no hint",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
			},
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if ra := b.RetryAfter(); ra != 0 {
					t.Fatalf("closed breaker must report 0, got %v", ra)
				}
			},
		},
		{
			name: "open breaker reports remaining refusal time",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if ra := b.RetryAfter(); ra <= 0 || ra > b.cfg.OpenTimeout {
					t.Fatalf("open breaker hint must be in (0, OpenTimeout], got %v", ra)
				}
			},
		},
		{
			name: "elapsed open timeout reports 0 before the state flips",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			afterTimeouts: 2,
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if b.State() != StateOpen {
					t.Fatalf("state must stay open until probed, got %s", b.State())
				}
				if ra := b.RetryAfter(); ra != 0 {
					t.Fatalf("elapsed timeout must report 0, got %v", ra)
				}
			},
		},
		{
			name: "half-open refusal carries a spaced hint",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			afterTimeouts: 2,
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if err := b.Allow(); err != nil {
					t.Fatalf("probe must be admitted, got %v", err)
				}
				if b.State() != StateHalfOpen {
					t.Fatalf("expected half-open, got %s", b.State())
				}
				// Refused callers (probe budget exhausted) must not be sent
				// straight back: the hint spaces them inside the epoch. The
				// base hint is OpenTimeout/10, well under OpenTimeout.
				base := b.cfg.OpenTimeout / 10
				if ra := b.RetryAfter(); ra < base || ra > b.cfg.OpenTimeout {
					t.Fatalf("half-open hint must be in [%v, %v], got %v", base, b.cfg.OpenTimeout, ra)
				}
			},
		},
		{
			name: "jitter widens the open hint deterministically",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				b.cfg.RetryAfterJitter = 0.5
				// A 10s base makes read-side decay (µs–ms) negligible against
				// the 1s assertion tolerance.
				b.cfg.OpenTimeout = 10 * time.Second
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				// draw()==0.5 with fraction 0.5 widens the remaining time by
				// exactly 25%. The remaining time decays between the trip and
				// the read, so the target carries a tolerance that still
				// rejects a missing or wrong-scaled jitter: on a 10s base,
				// no-jitter reads ~10s, double-jitter ~15s, both far outside.
				ra := b.RetryAfter()
				want := 1.25 * float64(b.cfg.OpenTimeout)
				tolerance := float64(time.Second)
				if d := float64(ra); d < want-tolerance || d > want {
					t.Fatalf("jittered hint must be %v minus decay (≤1s), got %v", time.Duration(want), ra)
				}
			},
		},
		{
			name: "jitter never shortens the open hint",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				b.cfg.RetryAfterJitter = 1
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if ra := b.RetryAfter(); ra < b.cfg.OpenTimeout || ra > 2*b.cfg.OpenTimeout {
					t.Fatalf("full jitter must keep the hint in [OpenTimeout, 2×OpenTimeout], got %v", ra)
				}
			},
		},
		{
			name: "half-open refusal hint is jittered",
			setup: func(t *testing.T, b *Breaker) {
				t.Helper()
				b.cfg.RetryAfterJitter = 1
				for i := 0; i < b.cfg.FailureThreshold; i++ {
					b.RecordFailure()
				}
			},
			afterTimeouts: 2,
			check: func(t *testing.T, b *Breaker) {
				t.Helper()
				if err := b.Allow(); err != nil {
					t.Fatalf("probe must be admitted, got %v", err)
				}
				// draw()==0.5 with fraction 1 must widen the constant base
				// hint (OpenTimeout/10) by exactly 50%: no wall clock in the
				// base, so the equality is exact.
				want := b.cfg.OpenTimeout/10 + b.cfg.OpenTimeout/20
				if ra := b.RetryAfter(); ra != want {
					t.Fatalf("jittered half-open hint must be exactly %v, got %v", want, ra)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Deterministic draw: every jittered hint lands at fraction×0.5.
			restore := withRetryAfterRandom(t, func() float64 { return 0.5 })
			defer restore()

			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.FailureThreshold = 2
			cfg.SuccessThreshold = 1
			cfg.OpenTimeout = 30 * time.Millisecond
			cfg.Window = time.Minute
			b := NewBreaker(cfg)
			tc.setup(t, b)
			if tc.afterTimeouts > 0 {
				time.Sleep(time.Duration(tc.afterTimeouts) * cfg.OpenTimeout)
			}
			tc.check(t, b)
		})
	}
}

// TestBreaker_RetryAfter_JitterSpreadsRefusals verifies the anti-storm
// property: hints drawn concurrently for the same refusal moment spread
// across the jitter window instead of being identical. Uses the real random
// source and asserts only invariants that hold for every draw.
func TestBreaker_RetryAfter_JitterSpreadsRefusals(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.OpenTimeout = time.Second
	cfg.Window = time.Minute
	cfg.RetryAfterJitter = 1
	b := NewBreaker(cfg)
	b.RecordFailure()

	const samples = 64
	seen := make(map[time.Duration]bool, samples)
	for i := 0; i < samples; i++ {
		ra := b.RetryAfter()
		if ra < cfg.OpenTimeout || ra >= 2*cfg.OpenTimeout {
			t.Fatalf("hint %d must be in [1s, 2s), got %v", i, ra)
		}
		seen[ra] = true
	}
	// 64 uniform draws collapsing to a single value is impossible in
	// practice; if the jitter stopped being applied, this is exactly what
	// would happen, so the spread assertion is the regression tripwire.
	if len(seen) < 2 {
		t.Fatalf("jitter must spread hints across the window, got %d distinct values in %d samples", len(seen), samples)
	}
}

// TestBreaker_RetryAfter_JitterScalesOnHalfOpen verifies that the half-open
// refusal hint is scaled off the configured OpenTimeout (not hard-coded) and
// that its jitter window matches the configured fraction, using the constant
// half-open base so the bounds are exact.
func TestBreaker_RetryAfter_JitterScalesOnHalfOpen(t *testing.T) {
	// Deterministic draw: the hint must land at exactly base × 1.25.
	restore := withRetryAfterRandom(t, func() float64 { return 0.5 })
	defer restore()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 1
	cfg.OpenTimeout = 2 * time.Second
	cfg.Window = time.Minute
	cfg.RetryAfterJitter = 0.5
	b := NewBreaker(cfg)
	b.RecordFailure()
	time.Sleep(2 * cfg.OpenTimeout)
	if err := b.Allow(); err != nil {
		t.Fatalf("probe must be admitted, got %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open, got %s", b.State())
	}
	// draw()==0.5, fraction 0.5 → base × 1.25 = 200ms/10 × 1.25 = 250ms.
	if ra := b.RetryAfter(); ra != 250*time.Millisecond {
		t.Fatalf("scaled half-open hint must be exactly 250ms, got %v", ra)
	}
}

// withRetryAfterRandom swaps the jitter draw for fn and returns a restore
// function. Tests are serial within a package, so the swap is race-free.
func withRetryAfterRandom(t *testing.T, fn func() float64) func() {
	t.Helper()
	prev := retryAfterRandom
	retryAfterRandom = fn
	return func() {
		retryAfterRandom = prev
	}
}

func TestMap_RetryAfter(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      40 * time.Millisecond,
		Window:           time.Minute,
	}, 0, nil)
	key := EndpointKey("http://a.test")

	if ra := m.RetryAfter(key); ra != 0 {
		t.Fatalf("untripped endpoint must report 0, got %v", ra)
	}
	if ra := m.RetryAfter(EndpointKey("http://never-seen.test")); ra != 0 {
		t.Fatalf("unknown endpoint must report 0, got %v", ra)
	}

	if err := m.Allow(key); err != nil {
		t.Fatalf("allowed, got %v", err)
	}
	m.RecordFailure(key)
	if ra := m.RetryAfter(key); ra <= 0 || ra > 40*time.Millisecond {
		t.Fatalf("open endpoint hint must be in (0, OpenTimeout], got %v", ra)
	}
}
