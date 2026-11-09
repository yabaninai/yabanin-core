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

// N09-P02-T08 recovery corpus, aspect pkg/retry: interruption, retry and
// resume of a bounded-retry operation, and result recovery without
// duplicates or losses. Where T07 pinned the loop's decision boundaries,
// this corpus pins what an interrupted caller and a resuming caller
// observe: an interruption is reported as the context error (never
// misattributed to the upstream — the packet's negative criterion at the
// retry layer), the interrupted attempt's outcome is preserved, a resumed
// operation starts a clean loop and delivers exactly the new attempt's
// complete result with no stale residue. All cases are deterministic:
// cancellation happens synchronously inside fn (no goroutine timing), and
// the one pending backoff is hours long so the interrupted select has
// exactly one ready case.
var errTransport = errors.New("connection reset after write")

// TestDo_InterruptedBackoffPreservesAttemptOutcome pins the mid-backoff
// interruption contract: the pending sleep is abandoned immediately, the
// returned result carries the context error so the caller knows the
// operation was interrupted, and the interrupted attempt's status is
// preserved rather than discarded — the caller can tell it almost
// succeeded, and no attempt result is lost.
func TestDo_InterruptedBackoffPreservesAttemptOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int32
	start := time.Now()
	res := retry.Do(ctx, retry.Policy{
		MaxAttempts: 5, BaseDelay: time.Hour, MaxDelay: time.Hour, JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			cancel() // interrupt while the first backoff is still pending
		}
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	})
	// The hours-long pending sleep must have been cut short by the
	// interruption; a missing interrupt path would hang past this bound.
	assert.Less(t, time.Since(start), time.Minute)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	require.ErrorIs(t, res.Err, context.Canceled)
}

// TestDo_InterruptedAttemptReportsContextError pins the misattribution
// guard: an attempt whose caller canceled mid-flight is reported as the
// context error, not as an upstream failure — on both outcome shapes.
// A canceled client's failure must never feed the upstream health signal
// (the retry storm must not amplify the outage), and the live-context
// contrast subtest pins that the replacement happens only under
// interruption.
func TestDo_InterruptedAttemptReportsContextError(t *testing.T) {
	t.Run("proven not sent, canceled mid-attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls int32
		res := retry.Do(ctx, retry.Policy{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		}, func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			cancel()
			return retry.Result{Err: errTransport, Safety: retry.OutcomeNotExecuted}
		})
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		// The interruption replaces the transport error outright: the
		// caller must not read this as an upstream problem, and the loop
		// must not retry a canceled caller.
		require.ErrorIs(t, res.Err, context.Canceled)
		require.NotErrorIs(t, res.Err, errTransport)
		assert.Zero(t, res.StatusCode)
	})

	t.Run("classified errored response, canceled mid-body", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls int32
		res := retry.Do(ctx, retry.Policy{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		}, func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			cancel()
			return retry.Result{StatusCode: http.StatusServiceUnavailable, Err: errTransport}
		})
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		require.ErrorIs(t, res.Err, context.Canceled)
		require.NotErrorIs(t, res.Err, errTransport)
		assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	})

	t.Run("live context does not replace the transport error", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		}, func(ctx context.Context) retry.Result {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return retry.Result{Err: errTransport, Safety: retry.OutcomeNotExecuted}
			}
			return retry.Result{StatusCode: http.StatusOK}
		})
		require.NoError(t, res.Err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	})
}

// TestDo_ResumeAfterInterruptionRecoversFreshResult pins the resume
// contract: after an interrupted operation, a fresh Do with a live context
// starts a clean loop (no leaked attempt state), hands the caller's live
// context to the resumed attempt, and delivers exactly that attempt's
// complete result — the interrupted attempt's outcome does not leak into
// it (no duplicated or merged state).
func TestDo_ResumeAfterInterruptionRecoversFreshResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first := retry.Do(ctx, retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Hour, MaxDelay: time.Hour, JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		cancel()
		return retry.Result{StatusCode: http.StatusServiceUnavailable}
	})
	require.ErrorIs(t, first.Err, context.Canceled)

	resumedHeader := http.Header{}
	resumedHeader.Set("X-Resumed", "1")
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		// The resumed attempt runs under a live context: nothing of the
		// interrupted operation's cancellation may leak in.
		if ctx.Err() != nil {
			return retry.Result{Err: context.Canceled}
		}
		return retry.Result{StatusCode: http.StatusOK, Headers: resumedHeader, Body: []byte("resumed")}
	})
	require.NoError(t, res.Err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "resume must start a clean loop")
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "1", res.Headers.Get("X-Resumed"))
	assert.Equal(t, []byte("resumed"), res.Body)
}

// TestDo_ResultsReplaceWithoutStaleResidue pins result integrity across
// attempts: each attempt's result replaces the previous one wholesale —
// no header, body or status residue from an earlier attempt survives into
// the delivered result, and a terminal non-retryable result arrives intact
// (nothing of the retryable failure before it is merged or lost).
func TestDo_ResultsReplaceWithoutStaleResidue(t *testing.T) {
	t.Run("success replaces the failed attempt wholesale", func(t *testing.T) {
		failedHeader := http.Header{}
		failedHeader.Set("X-Failed", "1")
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			if n := atomic.AddInt32(&calls, 1); n == 1 {
				return retry.Result{
					StatusCode: http.StatusServiceUnavailable,
					Headers:    failedHeader,
					Body:       []byte("failed-attempt-body"),
				}
			}
			okHeader := http.Header{}
			okHeader.Set("X-Ok", "1")
			return retry.Result{StatusCode: http.StatusOK, Headers: okHeader, Body: []byte("ok")}
		})
		require.NoError(t, res.Err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "1", res.Headers.Get("X-Ok"))
		assert.Empty(t, res.Headers.Get("X-Failed"), "failed attempt's headers must not survive")
		assert.Equal(t, []byte("ok"), res.Body, "failed attempt's body must not survive")
	})

	t.Run("terminal result arrives intact after a retryable failure", func(t *testing.T) {
		var calls int32
		res := retry.Do(context.Background(), retry.Policy{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, JitterFactor: 0,
		}, func(ctx context.Context) retry.Result {
			if n := atomic.AddInt32(&calls, 1); n == 1 {
				return retry.Result{
					StatusCode: http.StatusServiceUnavailable,
					Body:       []byte("overloaded"),
				}
			}
			return retry.Result{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       []byte("terminal"),
			}
		})
		assert.Equal(t, http.StatusUnprocessableEntity, res.StatusCode)
		assert.Equal(t, []byte("terminal"), res.Body, "the terminal attempt's body must not be lost")
		assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	})
}
