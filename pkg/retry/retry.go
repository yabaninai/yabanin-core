// Package retry provides bounded exponential-backoff retry for upstream HTTP
// calls. It is intentionally small and decoupled from the upstream client:
// callers pass an idempotent closure that returns (statusCode, headers, err)
// and retry.Do decides whether and how long to wait before the next attempt.
package retry

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"time"
)

// Result captures one attempt's outcome. Headers are surfaced so callers can
// respect Retry-After (P3.8).
type Result struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Err        error
	Safety     OutcomeSafety
	Proof      IdempotencyProof
}

// OutcomeSafety records evidence about whether a failed request could have
// executed. Its zero value is conservative: an errored attempt is unknown.
type OutcomeSafety uint8

const (
	// OutcomeUnknown is the conservative zero value for an errored attempt.
	OutcomeUnknown OutcomeSafety = iota
	// OutcomeNotExecuted means the caller has proof the attempt did not execute.
	OutcomeNotExecuted
)

// IdempotencyProof is an opt-in extension for a verified provider/action
// deduplication contract. Implementations must only return true when repeating
// the exact operation is deduplicated upstream. No implementation is supplied
// by this package, and absent proof never permits a retry.
type IdempotencyProof interface {
	AllowsRetry() bool
}

// Classifier decides whether a given attempt's outcome should be retried.
// Implementations typically return true for approved transport errors, 429,
// 503 and 529. Do blocks transport retries with unknown outcomes.
type Classifier func(statusCode int, err error) bool

// Policy configures retry behaviour. Zero-value MaxAttempts disables retry.
type Policy struct {
	MaxAttempts  int
	BaseDelay    time.Duration
	MaxDelay     time.Duration
	JitterFactor float64 // 0..1, fraction of delay used for symmetric jitter
	RetryOn      Classifier
}

// DefaultPolicy returns the recommended retry policy for upstream LLM calls:
// up to 3 attempts with exponential backoff (50ms → 200ms → 800ms) and ±25%
// jitter. Retries are triggered on proven pre-send transport errors, 429, 503
// and 529.
func DefaultPolicy() Policy {
	return Policy{
		MaxAttempts:  3,
		BaseDelay:    50 * time.Millisecond,
		MaxDelay:     800 * time.Millisecond,
		JitterFactor: 0.25,
		RetryOn:      DefaultClassifier,
	}
}

// DefaultClassifier classifies transport errors, HTTP 429, 503 and 529 as
// retry candidates. Do additionally requires explicit OutcomeNotExecuted
// evidence before it retries a transport error.
// (Cloudflare-overloaded). Other 4xx and 2xx are considered final.
var DefaultClassifier Classifier = func(code int, err error) bool {
	if err != nil {
		return true
	}
	return code == http.StatusTooManyRequests ||
		code == http.StatusServiceUnavailable ||
		code == 529
}

// Do calls fn up to Policy.MaxAttempts times, sleeping between attempts
// according to exponential backoff with optional jitter. The supplied fn must
// be idempotent: callers rebuild any request body from in-memory buffers on
// every invocation (Go's http.Request.Body is single-use).
//
// Context cancellation aborts the loop immediately and returns the context
// error rather than the last fn error.
func Do(ctx context.Context, p Policy, fn func(ctx context.Context) Result) Result {
	if p.MaxAttempts <= 0 {
		p = DefaultPolicy()
	}
	if p.RetryOn == nil {
		p.RetryOn = DefaultClassifier
	}

	var last Result
	for attempt := 0; attempt < p.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			last.Err = ctx.Err()
			return last
		default:
		}

		last = fn(ctx)
		if last.Err != nil && last.StatusCode == 0 && !MayRepeat(last.Safety, last.Proof) {
			return last
		}
		if last.Err == nil && !p.RetryOn(last.StatusCode, nil) {
			return last
		}
		if last.Err != nil && ctx.Err() != nil {
			last.Err = ctx.Err()
			return last
		}
		if !p.RetryOn(last.StatusCode, last.Err) {
			return last
		}
		if attempt == p.MaxAttempts-1 {
			break
		}

		delay := p.delayFor(attempt, last)
		select {
		case <-ctx.Done():
			last.Err = ctx.Err()
			return last
		case <-time.After(delay):
		}
	}
	return last
}

// DefinitelyNotSent reports only errors that prove the HTTP transport failed
// while establishing a connection. Write/read errors are intentionally not
// accepted: a timeout or reset after request bytes were written is unknown.
func DefinitelyNotSent(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// delayFor computes the backoff for the given attempt, optionally extended by
// a Retry-After header (P3.8). Retry-After takes precedence when present and
// parseable; otherwise exponential backoff with jitter applies.
func (p Policy) delayFor(attempt int, r Result) time.Duration {
	if ra := retryAfter(r); ra > 0 {
		if p.MaxDelay > 0 && ra > p.MaxDelay {
			return p.MaxDelay
		}
		return ra
	}

	if p.BaseDelay <= 0 {
		p.BaseDelay = 50 * time.Millisecond
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = 800 * time.Millisecond
	}
	d := p.BaseDelay << uint(attempt)
	if d <= 0 || d > p.MaxDelay {
		d = p.MaxDelay
	}
	if p.JitterFactor > 0 {
		//nolint:gosec // math/rand/v2 is appropriate for non-crypto jitter; G404 is a false positive on v2.
		jitter := time.Duration(float64(d) * p.JitterFactor * (rand.Float64()*2 - 1))
		d += jitter
	}
	return d
}

// After parses a Retry-After header value. Supports both delta-seconds
// and HTTP-date forms. Returns 0 when absent, unparseable, or in the past —
// the caller treats 0 as "no usable hint" (never fabricates one). This is the
// single canonical parser for Retry-After hints in the gateway; the decision
// layer feeds it captured attempt headers and the client-facing render path
// converts the result to whole seconds. (Named `After`, not `RetryAfter`:
// package-qualified `retry.RetryAfter` stutters.)
func After(h http.Header) time.Duration {
	if h == nil {
		return 0
	}
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	// Try seconds form first.
	if secs := parseUint(v); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	// Fall back to HTTP-date.
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// retryAfter applies the canonical parse to an attempt's captured headers.
func retryAfter(r Result) time.Duration {
	return After(r.Headers)
}

// parseUint returns the non-negative integer value of s, or 0 on error.
func parseUint(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
