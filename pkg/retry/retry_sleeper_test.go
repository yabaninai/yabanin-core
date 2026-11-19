// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/reireirei/yabanin/internal/retryclock"
	"github.com/stretchr/testify/assert"
)

// sleeperScheduling records every scheduled delay; cancel, when non-nil,
// kills ctx from inside the pending wait — the deterministic form of a
// deadline firing mid-sleep.
func sleeperScheduling(slept *[]time.Duration, cancel context.CancelFunc) retryclock.Sleeper {
	return func(ctx context.Context, d time.Duration) {
		*slept = append(*slept, d)
		if cancel != nil {
			cancel()
			<-ctx.Done()
		}
	}
}

func TestDo_SleeperFromContextReplacesRealWait(t *testing.T) {
	var slept []time.Duration
	ctx := retryclock.With(context.Background(), sleeperScheduling(&slept, nil))
	attempts := 0
	res := Do(ctx, Policy{
		MaxAttempts:  2,
		BaseDelay:    5 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		JitterFactor: 0,
		RetryOn:      DefaultClassifier,
	}, func(context.Context) Result {
		attempts++
		return Result{StatusCode: http.StatusTooManyRequests}
	})
	assert.Equal(t, []time.Duration{5 * time.Millisecond}, slept,
		"the context-carried sleeper observes the exact scheduled backoff")
	assert.Equal(t, 2, attempts, "without cancellation both attempts run")
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
}

func TestDo_SleeperCancellationWhileWaitingIsTerminal(t *testing.T) {
	var slept []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = retryclock.With(ctx, sleeperScheduling(&slept, cancel))
	attempts := 0
	res := Do(ctx, Policy{
		MaxAttempts:  2,
		BaseDelay:    5 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		JitterFactor: 0,
		RetryOn:      DefaultClassifier,
	}, func(context.Context) Result {
		attempts++
		return Result{StatusCode: http.StatusTooManyRequests}
	})
	assert.Equal(t, []time.Duration{5 * time.Millisecond}, slept)
	assert.Equal(t, 1, attempts, "cancellation inside the pending wait stops the loop before the second attempt")
	assert.ErrorIs(t, res.Err, context.Canceled)
}

// TestDo_ErrorFromCancelledAttemptIsContextError pins the post-attempt
// cancellation substitution: when fn itself returns an error after the
// context died, Do surfaces context.Canceled instead of the attempt error.
// Safety=OutcomeNotExecuted bypasses the unsafe-transport refusal, and
// MaxAttempts=1 leaves no later pre-attempt check that could mask removal
// of that substitution branch.
func TestDo_ErrorFromCancelledAttemptIsContextError(t *testing.T) {
	sentinel := errors.New("upstream attempt failed")
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	res := Do(ctx, Policy{MaxAttempts: 1}, func(ctx context.Context) Result {
		attempts++
		cancel()
		return Result{Err: sentinel, Safety: OutcomeNotExecuted}
	})
	assert.Equal(t, 1, attempts)
	assert.ErrorIs(t, res.Err, context.Canceled)
	assert.NotErrorIs(t, res.Err, sentinel)
}
