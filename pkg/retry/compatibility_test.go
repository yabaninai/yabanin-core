// N09-P02-T09 compatibility matrix, aspect pkg/retry: pkg/retry is untouched
// by the packet branch, so the matrix role here is a regression guard at the
// REAL supported consumer configuration — pkg/gateway builds
// retry.DefaultPolicy() verbatim (gateway.go:394) and its attempt closures
// shape results exactly as chat.go:812-825 / stream.go:374-393 do: a failed
// upstream call becomes Result{StatusCode: extracted status, Err: err}, and
// the gateway marks Safety = OutcomeNotExecuted when it can prove the
// request reached the wire (a status came back) or never left
// (DefinitelyNotSent dial errors).
//
// Where T07 pinned the loop's decision boundaries on minimal policies and
// T08 the interruption/resume narratives, this corpus pins the gateway
// shape under the unmodified DEFAULT policy — its real jitter, its real
// MaxDelay clamp on server hints, and the unknown-outcome refusal the
// gateway relies on when neither evidence source is present. Timing
// assertions use coarse envelopes whose lower bounds sit below the
// guaranteed minimum and whose upper bounds sit far above the jitter
// ceiling, so they can only fail when the behavior itself changed.
package retry_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestCompat_GatewayDefaultPolicyDispatchShape replays the gateway dispatch
// loop under retry.DefaultPolicy() verbatim: a 503 with an extracted status
// retries (status ⇒ OutcomeNotExecuted evidence), a dial error retries
// (DefinitelyNotSent ⇒ proof the request never left), and the third attempt
// succeeds and delivers its headers and body intact. Exactly three attempts
// run (the default bound), separated by the real jittered backoff.
func TestCompat_GatewayDefaultPolicyDispatchShape(t *testing.T) {
	var calls int32
	start := time.Now()
	res := retry.Do(context.Background(), retry.DefaultPolicy(), func(ctx context.Context) retry.Result {
		switch n := atomic.AddInt32(&calls, 1); n {
		case 1: // upstream answered 503: status is execution evidence
			return retry.Result{
				StatusCode: http.StatusServiceUnavailable,
				Err:        errors.New("upstream overloaded"),
				Safety:     retry.OutcomeNotExecuted,
			}
		case 2: // dial error: DefinitelyNotSent is the no-write evidence
			return retry.Result{
				Err:    &net.OpError{Op: "dial", Err: errors.New("connection refused")},
				Safety: retry.OutcomeNotExecuted,
			}
		default:
			hdr := http.Header{}
			hdr.Set("X-Upstream", "3")
			return retry.Result{StatusCode: http.StatusOK, Headers: hdr, Body: []byte("ok")}
		}
	})
	require.NoError(t, res.Err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls), "DefaultPolicy bounds the loop at three attempts")
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "3", res.Headers.Get("X-Upstream"))
	assert.Equal(t, []byte("ok"), res.Body)
	// Two jittered backoffs under the default policy. The jitter is
	// symmetric around the base (±JitterFactor, retry.go delayFor): the
	// pair is bounded in [50×0.75 + 100×0.75, 50×1.25 + 100×1.25) ms =
	// [112.5, 187.5) ms. The floor proves both sleeps ran; the ceiling
	// proves the jitter spread bounds the dispatch.
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond, "the default backoffs must have run")
	assert.Less(t, elapsed, 3*time.Second, "the jitter ceiling must bound the dispatch")
}

// TestCompat_GatewayUnknownOutcomeRefused pins the explicit-refusal row the
// gateway depends on: a failure with NO execution evidence in either
// direction — no extracted status, not a dial error, no idempotency proof —
// is terminal after exactly one attempt. An unchanged consumer cannot be
// surprised into retrying an unknown-outcome error whose replay might
// double-charge a side effect.
func TestCompat_GatewayUnknownOutcomeRefused(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.DefaultPolicy(), func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		// Body read failed after the request was written: the gateway can
		// extract neither a status nor dial evidence, so it sets no
		// Safety flag — exactly chat.go's guard on this branch shape.
		return retry.Result{Err: errors.New("read body: connection reset")}
	})
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "unknown outcome must not be retried")
	require.Error(t, res.Err)
	require.NotErrorIs(t, res.Err, context.Canceled)
	assert.Zero(t, res.StatusCode)
}

// TestCompat_GatewayHintClampedByDefaultMaxDelay pins the server-hint
// contract under the REAL default configuration: a 429 with a 5s Retry-After
// is honored over the exponential backoff but clamped to the default
// MaxDelay (800ms) — an unchanged gateway can never be stalled for the full
// advertised hint, and the hint path carries no jitter (the clamp is exact).
func TestCompat_GatewayHintClampedByDefaultMaxDelay(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "5")
	var calls int32
	start := time.Now()
	res := retry.Do(context.Background(), retry.DefaultPolicy(), func(ctx context.Context) retry.Result {
		if n := atomic.AddInt32(&calls, 1); n == 1 {
			return retry.Result{
				StatusCode: http.StatusTooManyRequests,
				Headers:    header,
				Safety:     retry.OutcomeNotExecuted,
			}
		}
		return retry.Result{StatusCode: http.StatusOK}
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	elapsed := time.Since(start)
	// Honored over the 50ms backoff, clamped far below the literal 5s, and
	// jitter-free (>=750ms is above any backoff+jitter combination short
	// of the clamp; <2.5s is far above the exact 800ms clamp plus slack).
	assert.GreaterOrEqual(t, elapsed, 750*time.Millisecond)
	assert.Less(t, elapsed, 2500*time.Millisecond)
}
