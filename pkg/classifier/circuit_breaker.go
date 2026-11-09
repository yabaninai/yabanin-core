package classifier

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// CircuitState represents the state of the classifier circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the ML service is considered healthy.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the ML service has failed; fast-fail to fallback.
	CircuitOpen
	// CircuitHalfOpen means the probe period after the open timeout.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements a state machine for the ML classifier service.
// After N consecutive failures, it enters Open state (fail-fast to fallback).
// After openTimeout, it transitions to HalfOpen (limited probe requests).
// Success in HalfOpen → Closed; failure → back to Open.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	consecutiveFail  int
	failureThreshold int
	openUntil        time.Time
	openTimeout      time.Duration
	halfOpenSuccess  int
	successThreshold int
	// halfOpenInFlight counts probes admitted in the current half-open
	// epoch; it is reset on every Open→HalfOpen transition so a probe that
	// never completes cannot wedge the breaker open.
	halfOpenInFlight int
}

// NewCircuitBreaker creates a classifier circuit breaker.
func NewCircuitBreaker(failureThreshold int, openTimeout time.Duration, successThreshold int) *CircuitBreaker {
	return &CircuitBreaker{
		state:            CircuitClosed,
		failureThreshold: failureThreshold,
		openTimeout:      openTimeout,
		successThreshold: successThreshold,
	}
}

// Allow returns true if a request to the ML service should be attempted.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Now().After(cb.openUntil) {
			// Start a fresh half-open epoch; drop slots left over from
			// probes of the previous epoch that never completed.
			cb.halfOpenInFlight = 0
			cb.state = CircuitHalfOpen
			return cb.admitProbeLocked()
		}
		return false
	case CircuitHalfOpen:
		return cb.admitProbeLocked()
	default:
		return false
	}
}

// admitProbeLocked admits at most successThreshold concurrent probes per
// half-open epoch. Caller must hold cb.mu.
func (cb *CircuitBreaker) admitProbeLocked() bool {
	limit := cb.successThreshold
	if limit < 1 {
		limit = 1
	}
	if cb.halfOpenInFlight >= limit {
		return false
	}
	cb.halfOpenInFlight++
	return true
}

// RecordSuccess records a successful ML classifier call.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		if cb.halfOpenInFlight > 0 {
			cb.halfOpenInFlight--
		}
		cb.halfOpenSuccess++
		if cb.halfOpenSuccess >= cb.successThreshold {
			cb.state = CircuitClosed
			cb.consecutiveFail = 0
			cb.halfOpenSuccess = 0
		}
	case CircuitClosed:
		cb.consecutiveFail = 0
	default:
		cb.consecutiveFail = 0
	}
}

// RecordFailure records a failed ML classifier call.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		cb.consecutiveFail++
		if cb.consecutiveFail >= cb.failureThreshold {
			cb.state = CircuitOpen
			cb.openUntil = time.Now().Add(cb.openTimeout)
		}
	case CircuitHalfOpen:
		// Release the probe slot before re-opening so it cannot leak into
		// the next half-open epoch (mirrors RecordSuccess).
		if cb.halfOpenInFlight > 0 {
			cb.halfOpenInFlight--
		}
		// Probe failed — back to Open
		cb.state = CircuitOpen
		cb.openUntil = time.Now().Add(cb.openTimeout)
		cb.halfOpenSuccess = 0
	default:
		// Already open, just reset timer if extended timeout desired
	}
}

// State returns the current circuit breaker state without mutating it. The
// Open→HalfOpen transition only happens in Allow.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.state
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("classifier: circuit breaker open — falling back to rule-tier")

// CircuitBreakerClassifier wraps an ML classifier with circuit breaker logic.
type CircuitBreakerClassifier struct {
	inner Classifier
	cb    *CircuitBreaker
}

// Classify routes the request through the wrapped classifier while the breaker is closed.
// Classify.
func (c *CircuitBreakerClassifier) Classify(ctx context.Context, in Input) (Result, error) {
	if !c.cb.Allow() {
		return Result{}, ErrCircuitOpen
	}

	res, err := c.inner.Classify(ctx, in)
	if err != nil {
		c.cb.RecordFailure()
		return Result{}, err
	}
	c.cb.RecordSuccess()
	return res, nil
}

// NewCircuitBreakerClassifier creates a CircuitBreakerClassifier wrapper.
func NewCircuitBreakerClassifier(inner Classifier, cb *CircuitBreaker) *CircuitBreakerClassifier {
	return &CircuitBreakerClassifier{inner: inner, cb: cb}
}

// Name returns the provider identifier used in logs and metrics.
// Name.
func (c *CircuitBreakerClassifier) Name() string { return "circuit_breaker_" + c.inner.Name() }

// CircuitHealthChecker periodically checks ML service health and updates the breaker.
type CircuitHealthChecker struct {
	ml        Classifier
	breaker   *CircuitBreaker
	log       *slog.Logger
	ticker    *time.Ticker
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	period    time.Duration
}

// NewCircuitHealthChecker starts periodic health probes for the classifier breaker.
// NewCircuitHealthChecker.
func NewCircuitHealthChecker(ml Classifier, cb *CircuitBreaker, log *slog.Logger) *CircuitHealthChecker {
	return &CircuitHealthChecker{
		ml:      ml,
		breaker: cb,
		log:     log.With("component", "classifier-health-checker"),
		period:  10 * time.Second,
		done:    make(chan struct{}),
	}
}

// Start begins periodic health checks. Subsequent calls are no-ops so a
// double Start cannot leak a second ticker/goroutine.
func (hc *CircuitHealthChecker) Start(ctx context.Context) {
	hc.startOnce.Do(func() {
		hc.ticker = time.NewTicker(hc.period)
		go func() {
			for {
				select {
				case <-ctx.Done():
					hc.ticker.Stop()
					return
				case <-hc.done:
					hc.ticker.Stop()
					return
				case <-hc.ticker.C:
					if err := hc.check(); err != nil { //nolint:contextcheck // health check is independent of caller ctx
						hc.breaker.RecordFailure()
						hc.log.Warn("classifier health check failed", "error", err)
					} else {
						hc.breaker.RecordSuccess()
						hc.log.Debug("classifier health check passed")
					}
				}
			}
		}()
	})
}

// Stop terminates the health checker. Safe to call multiple times; only the
// first call closes the done channel.
func (hc *CircuitHealthChecker) Stop() {
	hc.stopOnce.Do(func() { close(hc.done) })
}

func (hc *CircuitHealthChecker) check() error {
	if hcChecker, ok := hc.ml.(interface{ HealthCheck(context.Context) error }); ok {
		return hcChecker.HealthCheck(context.Background())
	}
	return errors.New("no HealthCheck method")
}
