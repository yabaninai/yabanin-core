package circuit

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// retryAfterRandom supplies the draw behind RetryAfter hint jitter. It is a
// package variable so tests can inject a deterministic sequence; production
// code never reassigns it. math/rand (not crypto/rand) is the right source:
// the value spaces client retries, it never protects anything.
var retryAfterRandom = rand.Float64

// State represents the current state of the circuit breaker.
type State int32

const (
	// StateClosed means normal operation; requests pass through.
	StateClosed State = iota
	// StateOpen means the circuit tripped; requests are rejected immediately.
	StateOpen
	// StateHalfOpen means probing recovery; limited requests are allowed.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when a request is rejected because the circuit
// breaker is in the Open state.
var ErrCircuitOpen = errors.New("circuit breaker open")

// Config holds the parameters for a Breaker instance.
type Config struct {
	Name             string        // Human-readable name for metrics labels.
	Enabled          bool          // Whether the breaker is active.
	FailureThreshold int           // Number of failures within Window to trip the circuit. Default: 10.
	SuccessThreshold int           // Successes needed in HalfOpen to close. Default: 2.
	OpenTimeout      time.Duration // How long before Open transitions to HalfOpen. Default: 30s.
	Window           time.Duration // Sliding window duration for failure counting. Default: 30s.

	// OnOpen, when set, is invoked after the breaker trips to Open with the
	// breaker's Name (the endpoint key for per-endpoint breakers). It runs
	// under the breaker mutex: keep it non-blocking (logging is fine).
	OnOpen func(name string)
	// OnRecover, when set, is invoked after a HalfOpen→Closed recovery.
	OnRecover func(name string)

	// RetryAfterJitter is the extra spread added to RetryAfter hints as a
	// fraction of the base hint, in [0, 1]. 0 (the default) keeps hints
	// exact; every refused client would then retry at the same instant —
	// at the Open→HalfOpen flip a synchronized wave competes for the few
	// probe slots and re-strikes a recovering upstream. With j > 0 each
	// hint is widened upward to [base, base×(1+j)): no client is sent
	// earlier than the breaker could possibly admit it, and arrivals
	// spread across the window instead of piling up at its start.
	RetryAfterJitter float64
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Name:             "default",
		FailureThreshold: 10,
		SuccessThreshold: 2,
		OpenTimeout:      30 * time.Second,
		Window:           30 * time.Second,
	}
}

// Breaker is a thread-safe circuit breaker that uses a sliding window to track
// failures and controls request flow through Close/Open/HalfOpen states.
type Breaker struct {
	cfg Config

	mu sync.RWMutex
	st State // protected by mu

	// Sliding window metrics (protected by mu).
	windowStart  time.Time
	failureCount int
	successCount int

	// Atomic snapshot of the current state for lock-free reads.
	state atomic.Int32

	// OpenAt records when the breaker transitioned to Open; used for
	// HalfOpen timing without holding a lock.
	openAt atomic.Int64 // unix-nano, zero means not in Open state.

	// Limit controls how many probes are allowed through in HalfOpen state.
	halfOpenLimit    int32
	halfOpenInFlight atomic.Int32
}

// NewBreaker creates a Breaker with the given config. Unset fields in cfg
// are filled with defaults from DefaultConfig().
func NewBreaker(cfg Config) *Breaker {
	def := DefaultConfig()
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = def.FailureThreshold
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = def.SuccessThreshold
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = def.OpenTimeout
	}
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}

	b := &Breaker{
		cfg:           cfg,
		st:            StateClosed,
		windowStart:   time.Now(),
		halfOpenLimit: safeInt32(cfg.SuccessThreshold),
	}
	b.state.Store(int32(StateClosed))
	return b
}

// Allow checks whether an outbound request should be permitted. It returns
// ErrCircuitOpen when the circuit is Open and the timeout has not elapsed, or
// when HalfOpen probes are exhausted. Callers must terminate every admitted
// attempt with exactly one of RecordSuccess, RecordFailure or RecordCanceled
// (for attempts abandoned because their context was canceled or its deadline
// elapsed) so state transitions occur and probe slots cannot leak.
func (b *Breaker) Allow() error {
	err := b.allow()
	if err != nil {
		// the endpoint key in per-endpoint scope.
		metrics.CircuitRejects.WithLabelValues(b.cfg.Name).Inc()
	}
	return err
}

func (b *Breaker) allow() error {
	if !b.cfg.Enabled {
		return nil
	}

	st := State(b.state.Load())

	switch st {
	case StateClosed:
		return nil

	case StateOpen:
		openAt := time.Unix(0, b.openAt.Load())
		if time.Since(openAt) >= b.cfg.OpenTimeout {
			// Try to transition to HalfOpen.
			b.mu.Lock()
			// Double-check after acquiring the lock — another goroutine may
			// have already moved us out of Open.
			if b.st == StateOpen && time.Since(openAt) >= b.cfg.OpenTimeout {
				b.st = StateHalfOpen
				b.successCount = 0
				// Drop slots carried over from the previous half-open epoch;
				// a leaked slot would otherwise wedge the breaker open.
				b.halfOpenInFlight.Store(0)
				b.state.Store(int32(StateHalfOpen))
			}
			// Read b.st under the mutex: it is protected by mu and other
			// goroutines may mutate it between Unlock and a later read.
			halfOpen := b.st == StateHalfOpen
			b.mu.Unlock()

			if halfOpen {
				// Allow one probe.
				n := b.halfOpenInFlight.Add(1)
				if n <= b.halfOpenLimit {
					return nil
				}
				// Over-limit: give the slot back through the floor-0 CAS
				// helper. A blind Add(-1) can race the Open→HalfOpen epoch
				// reset (Store(0)) and drive the counter negative.
				b.releaseProbeSlot()
				return ErrCircuitOpen
			}
			return ErrCircuitOpen
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		n := b.halfOpenInFlight.Add(1)
		if n <= b.halfOpenLimit {
			return nil
		}
		b.releaseProbeSlot()
		return ErrCircuitOpen

	default:
		return ErrCircuitOpen
	}
}

// RecordSuccess records a successful request outcome. When called from a
// HalfOpen state and the success threshold is met, the circuit closes.
func (b *Breaker) RecordSuccess() {
	if !b.cfg.Enabled {
		return
	}

	if b.state.Load() != int32(StateHalfOpen) {
		// In Closed state we just reset the window on any success.
		b.mu.Lock()
		if b.st == StateClosed {
			b.maybeResetWindowLocked()
		}
		b.mu.Unlock()
		return
	}

	b.mu.Lock()
	b.successCount++
	b.releaseProbeSlot()

	// This block only runs for outcomes recorded out of HalfOpen, so closing
	// here is a recovery from a prior Open episode.
	recovered := b.st == StateHalfOpen

	if b.successCount >= b.cfg.SuccessThreshold {
		b.st = StateClosed
		b.failureCount = 0
		b.successCount = 0
		b.windowStart = time.Now()

		if recovered {
			metrics.CircuitRecoveries.WithLabelValues(b.cfg.Name).Inc()
			if b.cfg.OnRecover != nil {
				b.cfg.OnRecover(b.cfg.Name)
			}
		}

		b.state.Store(int32(StateClosed))
	}
	b.mu.Unlock()
}

// RecordCanceled records that an admitted attempt ended because its caller's
// context was canceled or its deadline elapsed — a client-side outcome, not an
// upstream health signal. It is the cancellation leg of the terminal-path
// discipline: an admitted attempt ends in exactly one of RecordSuccess,
// RecordFailure or RecordCanceled.
//
// Why a separate outcome matters (N09-P02-T04 deadline/cancellation
// coordination): misreporting a canceled attempt as a failure lets an
// impatient client storm trip the breaker — a cancel wave then opens the
// circuit for every tenant behind the same breaker and amplifies exactly the
// outage the breaker contains. Leaking the record instead wedges HalfOpen:
// the probe slot is never freed, probes stay exhausted and every caller is
// refused until a state change that can no longer happen on its own.
//
//   - HalfOpen: frees the canceled attempt's probe slot for the next probe
//     without touching success/failure counts or the state machine.
//   - Closed/Open: no-op.
func (b *Breaker) RecordCanceled() {
	if !b.cfg.Enabled {
		return
	}

	if b.state.Load() != int32(StateHalfOpen) {
		return
	}

	b.mu.Lock()
	// Re-check under the mutex: the state may have transitioned between the
	// atomic snapshot above and the lock (a concurrent probe may have closed
	// the circuit); a slot must only be freed while this epoch still owns it.
	if b.st == StateHalfOpen {
		b.releaseProbeSlot()
	}
	b.mu.Unlock()
}

// RecordFailure records a failed request outcome. When the failure count
// reaches the threshold within the sliding window, the circuit opens.
func (b *Breaker) RecordFailure() {
	if !b.cfg.Enabled {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.st {
	case StateClosed:
		b.maybeResetWindowLocked()
		b.failureCount++
		if b.failureCount >= b.cfg.FailureThreshold {
			b.tripOpenLocked()
		}

	case StateHalfOpen:
		// Release the probe slot before re-opening so it cannot leak into
		// the next half-open epoch (mirrors RecordSuccess).
		b.releaseProbeSlot()
		// Any failure in HalfOpen immediately re-opens the circuit.
		b.tripOpenLocked()

	case StateOpen:
		// Already open; ignore additional failures.
	}
}

func (b *Breaker) maybeResetWindowLocked() {
	if time.Since(b.windowStart) >= b.cfg.Window {
		b.failureCount = 0
		b.successCount = 0
		b.windowStart = time.Now()
	}
}

// releaseProbeSlot frees one half-open probe slot. It never drives the
// counter below zero when concurrent completions race for the same slot.
func (b *Breaker) releaseProbeSlot() {
	for {
		n := b.halfOpenInFlight.Load()
		if n <= 0 {
			return
		}
		if b.halfOpenInFlight.CompareAndSwap(n, n-1) {
			return
		}
	}
}

func (b *Breaker) tripOpenLocked() {
	b.st = StateOpen
	b.openAt.Store(time.Now().UnixNano())
	b.state.Store(int32(StateOpen))

	metrics.CircuitFailures.WithLabelValues(b.cfg.Name).Inc()
	metrics.CircuitState.WithLabelValues(b.cfg.Name).Set(float64(StateOpen))
	if b.cfg.OnOpen != nil {
		b.cfg.OnOpen(b.cfg.Name)
	}
}

// State returns the current breaker state without mutation.
func (b *Breaker) State() State {
	return State(b.state.Load())
}

// RetryAfter reports how much longer a refused caller should wait before
// retrying, as a backpressure hint for Retry-After headers.
//
//   - Open: the remaining time until the Open→HalfOpen transition becomes
//     possible, widened by RetryAfterJitter so simultaneous refusals spread
//     their retries instead of converging on the flip instant; 0 once the
//     open timeout has elapsed (the next Allow call may then flip the state).
//   - HalfOpen: probes are exhausted (the only situation in which a refused
//     caller consults this), so the hint is a fraction of OpenTimeout — long
//     enough to space re-strikes, short enough to retry within the probe
//     epoch. A hint of 0 here would send refused clients straight back,
//     amplifying the very outage the breaker is containing.
//   - Closed: 0 — there is nothing to wait for.
func (b *Breaker) RetryAfter() time.Duration {
	switch State(b.state.Load()) {
	case StateOpen:
		openAt := time.Unix(0, b.openAt.Load())
		remaining := b.cfg.OpenTimeout - time.Since(openAt)
		if remaining <= 0 {
			return 0
		}
		return jitterHint(remaining, b.cfg.RetryAfterJitter, retryAfterRandom)
	case StateHalfOpen:
		hint := b.cfg.OpenTimeout / probeHintDivisor
		if hint <= 0 {
			hint = minRetryHint
		}
		return jitterHint(hint, b.cfg.RetryAfterJitter, retryAfterRandom)
	default:
		return 0
	}
}

const (
	// probeHintDivisor scales the half-open refusal hint off OpenTimeout.
	probeHintDivisor = 10
	// minRetryHint floors the half-open refusal hint so a degenerately
	// small OpenTimeout still spaces retries at all.
	minRetryHint = time.Millisecond
)

// jitterHint widens a retry hint upward by a random fraction of itself so
// simultaneous refusals spread their retries over [base, base×(1+fraction))
// instead of striking at the same instant. fraction is clamped to [0, 1];
// base ≤ 0, fraction ≤ 0 or a missing draw leave the hint unchanged. The
// widening is upward-only by design: no caller may be sent earlier than the
// base guarantee.
func jitterHint(base time.Duration, fraction float64, draw func() float64) time.Duration {
	if base <= 0 || fraction <= 0 || draw == nil {
		return base
	}
	if fraction > 1 {
		fraction = 1
	}
	return base + time.Duration(draw()*fraction*float64(base))
}

// Metrics returns a snapshot of the breaker's internal counters for
// instrumentation / health endpoints.
func (b *Breaker) Metrics() BreakerMetrics {
	b.mu.RLock()
	defer b.mu.RUnlock()

	age := time.Since(b.windowStart)
	windowProgress := 0.0
	if b.cfg.Window > 0 {
		windowProgress = math.Min(float64(age)/float64(b.cfg.Window)*100, 100)
	}

	return BreakerMetrics{
		State:            State(b.state.Load()),
		FailureCount:     b.failureCount,
		SuccessCount:     b.successCount,
		WindowAge:        age,
		WindowProgress:   windowProgress,
		HalfOpenInFlight: b.halfOpenInFlight.Load(),
	}
}

// BreakerMetrics holds a snapshot of breaker counters.
// safeInt32 converts int to int32, clamping to valid range.
func safeInt32(v int) int32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v)
}

// BreakerMetrics exposes counters describing breaker transitions.
type BreakerMetrics struct {
	State            State
	FailureCount     int
	SuccessCount     int
	WindowAge        time.Duration
	WindowProgress   float64 // 0-100, how far into the window we are.
	HalfOpenInFlight int32
}
