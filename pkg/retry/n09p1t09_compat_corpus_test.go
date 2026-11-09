package retry_test

// N09-P01-T09 [compatibility] — old/new configuration walk for pkg/retry.
//
// Card: walk old and new configuration shapes through the real consumer
// (retry.Do) so migration parity is proven by behaviour, not by reading
// defaults. Zero production changes; this file only pins observed contracts.
//
// Layers walked (see artifacts/internal-delivery-program/N09-P01/N09-P01-T09-compat-matrix.md):
//
//	old single-field shape   Policy{MaxAttempts: N}         — delays/classifier defaulted
//	old caller payloads      Status-only and silent errors  — classification unchanged
//	old zero-value Safety    OutcomeUnknown (pre-evidence)  — stays conservative
//	new evidence shape       Safety + Proof + Headers       — compose with old shapes
//	out-of-band values       negative/zero fields           — normalized, never panic
//
// Reused lane-pinned contracts: StatusCode==0 unknown-outcome terminal rule
// (T04/T07) and the Retry-After clamp to MaxDelay (P3.8, retry_contract_test).

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/retry"
)

// t09Attempts counts invocations of a retry closure (compat-walk counter).
type t09Attempts struct{ n int }

func (a *t09Attempts) bump() int { a.n++; return a.n }

// t09DialRefused builds the canonical proven-unreachable transport error:
// a dial OpError whose Err carries StatusCode 0 and no Safety evidence, so
// the unknown-outcome gate treats it as terminal on the first attempt.
func t09DialRefused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
}

// TestN09P1T09_Compat_LegacyMinimalPolicyKeepsWorking pins the old
// single-field policy shape: a caller that only sets MaxAttempts (the shape
// every pre-evidence call site used) still gets the recommended backoff,
// the default classifier and a bounded wall clock.
func TestN09P1T09_Compat_LegacyMinimalPolicyKeepsWorking(t *testing.T) {
	calls := &t09Attempts{}
	start := time.Now()

	res := retry.Do(context.Background(), retry.Policy{MaxAttempts: 3}, func(context.Context) retry.Result {
		switch calls.bump() {
		case 1, 2:
			return retry.Result{StatusCode: http.StatusServiceUnavailable}
		default:
			return retry.Result{StatusCode: http.StatusOK}
		}
	})

	if calls.n != 3 {
		t.Fatalf("legacy minimal policy: got %d calls, want 3 (nil RetryOn must default)", calls.n)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legacy minimal policy: final status %d, want 200", res.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Fatalf("legacy minimal policy: %v elapsed, defaulted delays must stay near 150ms", elapsed)
	}
}

// TestN09P1T09_Compat_ZeroValueSafetyKeepsOldCallersTerminal pins that callers
// who never set the new Safety/Proof fields keep the conservative contract:
// a failed attempt reporting no status and no evidence is terminal on the
// first attempt — including dial errors the classifier would otherwise like
// to retry (the unknown-outcome gate precedes classification).
func TestN09P1T09_Compat_ZeroValueSafetyKeepsOldCallersTerminal(t *testing.T) {
	t.Run("silent error with zero-value Safety is terminal", func(t *testing.T) {
		calls := &t09Attempts{}
		boom := errors.New("boom")
		res := retry.Do(context.Background(), retry.Policy{MaxAttempts: 5}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{Err: boom} // StatusCode 0, Safety zero, no proof
		})
		if calls.n != 1 {
			t.Fatalf("silent unknown outcome: got %d calls, want 1", calls.n)
		}
		if !errors.Is(res.Err, boom) {
			t.Fatalf("silent unknown outcome: raw error must pass through, got %v", res.Err)
		}
	})

	t.Run("dial-refused with zero-value Safety stays terminal", func(t *testing.T) {
		calls := &t09Attempts{}
		res := retry.Do(context.Background(), retry.Policy{MaxAttempts: 5}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{Err: t09DialRefused()} // would retry only with proven non-execution
		})
		if calls.n != 1 {
			t.Fatalf("unknown dial outcome: got %d calls, want 1 (evidence gate precedes classifier)", calls.n)
		}
		if res.StatusCode != 0 {
			t.Fatalf("unknown dial outcome: status %d, want 0", res.StatusCode)
		}
	})

	t.Run("status-only shape keeps retrying", func(t *testing.T) {
		calls := &t09Attempts{}
		res := retry.Do(context.Background(), retry.Policy{MaxAttempts: 5}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{StatusCode: http.StatusServiceUnavailable}
		})
		if calls.n != 5 {
			t.Fatalf("status-only shape: got %d calls, want 5", calls.n)
		}
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status-only shape: final status %d, want 503", res.StatusCode)
		}
	})
}

// TestN09P1T09_Compat_ModernShapeValidatedTogether walks the full modern
// policy — explicit delays, jitter, classifier, evidence fields and headers —
// through one real Do loop: an unknown-outcome attempt continues only because
// a proof allows it, then a 429 with a huge Retry-After is clamped to
// MaxDelay, then success. Composition of every new surface with the old loop.
func TestN09P1T09_Compat_ModernShapeValidatedTogether(t *testing.T) {
	calls := &t09Attempts{}
	policy := retry.Policy{
		MaxAttempts:  3,
		BaseDelay:    5 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		JitterFactor: 0.25,
		RetryOn:      retry.DefaultClassifier,
	}
	start := time.Now()

	res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
		switch calls.bump() {
		case 1: // unknown outcome, but a verified dedup contract allows repeating
			return retry.Result{Err: errors.New("ambiguous timeout"), Proof: outcomeProbeProof{allows: true}}
		case 2: // 429 demanding an hour — must clamp to MaxDelay=20ms
			h := http.Header{}
			h.Set("Retry-After", "3600")
			return retry.Result{StatusCode: http.StatusTooManyRequests, Headers: h}
		default:
			return retry.Result{StatusCode: http.StatusOK}
		}
	})

	if calls.n != 3 {
		t.Fatalf("modern shape: got %d calls, want 3 (proof allowed the unknown attempt)", calls.n)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("modern shape: final status %d, want 200", res.StatusCode)
	}
	// Without the MaxDelay clamp the Retry-After leg alone would stall ~1h;
	// the clamp keeps the whole walk under two seconds.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("modern shape: %v elapsed — Retry-After was not clamped to MaxDelay", elapsed)
	}
}

// TestN09P1T09_Compat_OutOfBandPolicyValuesStayBounded pins tolerance for
// unsupported policy values: they are normalized (or replaced wholesale),
// never panic, and never inflate the attempt budget or the wall clock.
func TestN09P1T09_Compat_OutOfBandPolicyValuesStayBounded(t *testing.T) {
	t.Run("negative MaxAttempts becomes the default budget", func(t *testing.T) {
		calls := &t09Attempts{}
		retry.Do(context.Background(), retry.Policy{MaxAttempts: -1}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{StatusCode: http.StatusServiceUnavailable}
		})
		if calls.n != 3 {
			t.Fatalf("negative MaxAttempts: got %d calls, want 3 (DefaultPolicy budget)", calls.n)
		}
	})

	t.Run("zero MaxAttempts replaces the whole policy with defaults", func(t *testing.T) {
		// Documented normalization quirk: MaxAttempts<=0 installs the full
		// DefaultPolicy — including its classifier — so a custom classifier
		// supplied alongside is ignored. 500 is retryable only under the
		// custom classifier, so one call proves the replacement happened.
		calls := &t09Attempts{}
		retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 0,
			RetryOn:     func(code int, _ error) bool { return code == http.StatusInternalServerError },
		}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{StatusCode: http.StatusInternalServerError}
		})
		if calls.n != 1 {
			t.Fatalf("zero MaxAttempts: got %d calls, want 1 (DefaultPolicy classifier replaced the custom one)", calls.n)
		}
	})

	t.Run("negative delays and wide jitter stay bounded", func(t *testing.T) {
		calls := &t09Attempts{}
		start := time.Now()
		retry.Do(context.Background(), retry.Policy{
			MaxAttempts:  3,
			BaseDelay:    -time.Second,
			MaxDelay:     -time.Second,
			JitterFactor: 0.9,
		}, func(context.Context) retry.Result {
			calls.bump()
			return retry.Result{StatusCode: http.StatusServiceUnavailable}
		})
		if calls.n != 3 {
			t.Fatalf("negative delays: got %d calls, want 3", calls.n)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("negative delays: %v elapsed — normalization must bound the backoff", elapsed)
		}
	})
}
