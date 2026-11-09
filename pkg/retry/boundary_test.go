package retry_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// N09-P02-T07 boundary corpus, aspect pkg/retry: the bounded-retry loop pinned
// at its edges — the attempt-count boundary, the zero-policy substitution, the
// Retry-After parse boundary (zero, garbage, past date), the MaxDelay clamp,
// the backoff shift-overflow guard, the idempotency-proof override and the
// errored-but-classified outcome boundary. Every case pins prior behavior at
// an exact edge; attempt counts are exact, and timing assertions use coarse
// envelopes whose lower bounds sit below a guaranteed sleep, so they can only
// fail when the boundary behavior itself changed.

// proofFixture is a caller-supplied deduplication contract for the
// IdempotencyProof boundary.
type proofFixture struct{ allows bool }

func (p proofFixture) AllowsRetry() bool { return p.allows }

// TestDo_BoundaryMaxAttemptsOne pins the single-attempt boundary: exactly one
// attempt is made, the retryable result is returned as-is and no backoff
// sleep runs (the sleep only exists between attempts).
func TestDo_BoundaryMaxAttemptsOne(t *testing.T) {
	var calls int32
	start := time.Now()
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 1, BaseDelay: 50 * time.Millisecond, MaxDelay: 50 * time.Millisecond, JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	})
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	// No sleep must have run: the guaranteed backoff (50ms) would push the
	// elapsed time past this envelope.
	assert.Less(t, time.Since(start), 40*time.Millisecond)
}

// TestDo_BoundaryZeroPolicySubstitutesDefault pins the MaxAttempts<=0
// boundary: a zero-value Policy must behave exactly like DefaultPolicy —
// three attempts on a retryable status, not zero attempts and not one.
func TestDo_BoundaryZeroPolicySubstitutesDefault(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	})
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
}

// TestDo_BoundaryRetryAfterIgnoredForms pins the hint parse boundary: a hint
// of zero seconds, a padded zero, a non-numeric value and an HTTP date in the
// past are all "no hint" — the exponential backoff must still run. A parse
// regression that honored any of these as a positive (or immediate) delay
// would either amplify re-strikes (zero delay) or stall callers.
func TestDo_BoundaryRetryAfterIgnoredForms(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	cases := []struct {
		name string
		hint string
	}{
		{name: "zero seconds", hint: "0"},
		{name: "padded zero", hint: "00"},
		{name: "non-numeric", hint: "soon"},
		{name: "past http-date", hint: past},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			header.Set("Retry-After", tc.hint)
			var calls int32
			start := time.Now()
			res := retry.Do(context.Background(), retry.Policy{
				MaxAttempts: 2, BaseDelay: 10 * time.Millisecond, MaxDelay: 10 * time.Millisecond, JitterFactor: 0,
			}, func(ctx context.Context) retry.Result {
				n := atomic.AddInt32(&calls, 1)
				if n == 1 {
					return retry.Result{StatusCode: http.StatusTooManyRequests, Headers: header}
				}
				return retry.Result{StatusCode: http.StatusOK}
			})
			require.Equal(t, http.StatusOK, res.StatusCode)
			assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
			// The exponential backoff (10ms) must have run: a zero-delay
			// misparse would return in single-digit milliseconds.
			assert.GreaterOrEqual(t, time.Since(start), 8*time.Millisecond)
		})
	}
}

// TestDo_BoundaryRetryAfterHonoredAndClamped pins the positive-hint boundary:
// a one-second hint is honored (delay well above the exponential backoff) and
// simultaneously clamped to MaxDelay (well below the literal second).
func TestDo_BoundaryRetryAfterHonoredAndClamped(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "1")
	var calls int32
	start := time.Now()
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 2, BaseDelay: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond, JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return retry.Result{StatusCode: http.StatusTooManyRequests, Headers: header}
		}
		return retry.Result{StatusCode: http.StatusOK}
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	elapsed := time.Since(start)
	// Honored: far above the 5ms exponential backoff. Clamped: far below
	// the literal 1s the header asked for.
	assert.GreaterOrEqual(t, elapsed, 18*time.Millisecond)
	assert.Less(t, elapsed, time.Second)
}

// TestDo_BoundaryBackoffShiftOverflowClampsToMaxDelay pins the arithmetic
// boundary: a BaseDelay whose shift overflows int64 on a later attempt must
// clamp to MaxDelay, never produce a negative delay (which time.After would
// treat as already-elapsed, collapsing the backoff to zero).
func TestDo_BoundaryBackoffShiftOverflowClampsToMaxDelay(t *testing.T) {
	var calls int32
	start := time.Now()
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts:  3,
		BaseDelay:    time.Duration(1) << 62, // <<1 on the second delay overflows int64
		MaxDelay:     10 * time.Millisecond,
		JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	})
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	// Both inter-attempt sleeps must be full MaxDelay sleeps: the second
	// one only lands there through the overflow guard.
	assert.GreaterOrEqual(t, time.Since(start), 18*time.Millisecond)
}

// TestDo_BoundaryIdempotencyProofOverrides pins the proof boundary on the
// unknown-outcome terminal path: a proof that allows retry turns an errored
// attempt with no execution evidence into a retryable one; a denying proof
// keeps the conservative terminal behavior.
func TestDo_BoundaryIdempotencyProofOverrides(t *testing.T) {
	t.Run("allowing proof retries the unknown outcome", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return retry.Result{Err: errors.New("connection reset"), Proof: proofFixture{allows: true}}
			}
			return retry.Result{StatusCode: http.StatusOK}
		})
		require.NoError(t, res.Err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	})

	t.Run("denying proof stays terminal", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{Err: errors.New("connection reset"), Proof: proofFixture{allows: false}}
		})
		require.Error(t, res.Err)
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
	})
}

// TestDo_BoundaryErroredResponseClassified pins the outcome boundary between
// "unknown transport outcome" and "classified response": an attempt that
// carries BOTH an error and a status code is not unknown — it goes to the
// classifier, whose transport-error rule (err != nil ⇒ candidate) dominates
// any status. Prior behavior, pinned: an errored 503 retries to success, and
// an errored 400 also retries to the attempt bound (the status only decides
// when Err == nil; the unknown-outcome terminal path is reserved for
// StatusCode == 0). MaxAttempts bounds both loops.
func TestDo_BoundaryErroredResponseClassified(t *testing.T) {
	t.Run("errored 503 retries", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return retry.Result{StatusCode: http.StatusServiceUnavailable, Err: errors.New("body read failed")}
			}
			return retry.Result{StatusCode: http.StatusOK}
		})
		require.NoError(t, res.Err)
		assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	})

	t.Run("errored 400 still retries to the bound", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{StatusCode: http.StatusBadRequest, Err: errors.New("body read failed")}
		})
		// Classifier candidate despite the final-class status: the loop
		// runs to MaxAttempts and returns the last errored result intact.
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		require.Error(t, res.Err)
		assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	})
}
