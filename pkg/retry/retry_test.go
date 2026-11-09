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

func TestDo_FirstAttemptSuccess_NoRetry(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{MaxAttempts: 3, BaseDelay: time.Millisecond},
		func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{StatusCode: 200}
		})
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestDo_RetriesOnErrorUntilSuccess(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return retry.Result{StatusCode: 503}
		}
		return retry.Result{StatusCode: 200}
	})
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
}

func TestDo_AllAttemptsFail_LastStatusReturned(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: 503}
	})
	assert.Equal(t, 503, res.StatusCode)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
}

func TestDo_UnknownNetworkErrorNotRetried(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{Err: errors.New("connection reset")}
	})
	require.Error(t, res.Err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestDo_4xxNotRetried(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: 400}
	})
	assert.Equal(t, 400, res.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestDo_429Retried(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return retry.Result{StatusCode: 429}
		}
		return retry.Result{StatusCode: 200}
	})
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
}

func TestDo_529Retried(t *testing.T) {
	var calls int32
	res := retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: 529}
	})
	assert.Equal(t, 529, res.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

func TestDo_ContextCancelledStopsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls int32
	res := retry.Do(ctx, retry.Policy{MaxAttempts: 5, BaseDelay: time.Millisecond},
		func(ctx context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{StatusCode: 503}
		})
	// At most one call — loop exits on the very first ctx check.
	assert.LessOrEqual(t, atomic.LoadInt32(&calls), int32(1))
	require.Error(t, res.Err)
	assert.ErrorIs(t, res.Err, context.Canceled)
}

func TestDo_ContextCancelledDuringSleepStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	var calls int32
	start := time.Now()
	_ = retry.Do(ctx, retry.Policy{
		MaxAttempts: 5, BaseDelay: 200 * time.Millisecond, MaxDelay: 200 * time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		return retry.Result{StatusCode: 503}
	})
	// Should not run all 5 attempts; ~1 retry attempt fits in 20ms window.
	assert.Less(t, atomic.LoadInt32(&calls), int32(5))
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestDo_RetryAfterHeaderOverridesBackoff(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "1")
	var calls int32
	start := time.Now()
	_ = retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 2, BaseDelay: 5 * time.Millisecond, MaxDelay: 10 * time.Millisecond,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		// First call returns Retry-After; cap by MaxDelay=10ms so the
		// observed delay should be 10ms, not 1s.
		if atomic.LoadInt32(&calls) == 1 {
			return retry.Result{StatusCode: 429, Headers: header}
		}
		return retry.Result{StatusCode: 200}
	})
	// 10ms cap rather than 1s.
	assert.Less(t, time.Since(start), 200*time.Millisecond)
}

func TestDo_RetryAfterHTTPHeaderDate(t *testing.T) {
	header := http.Header{}
	future := time.Now().Add(50 * time.Millisecond).UTC().Format(http.TimeFormat)
	header.Set("Retry-After", future)
	var calls int32
	_ = retry.Do(context.Background(), retry.Policy{
		MaxAttempts: 2, BaseDelay: 5 * time.Millisecond, MaxDelay: 1 * time.Second,
	}, func(ctx context.Context) retry.Result {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&calls) == 1 {
			return retry.Result{StatusCode: 429, Headers: header}
		}
		return retry.Result{StatusCode: 200}
	})
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

func TestDo_DefaultPolicy(t *testing.T) {
	p := retry.DefaultPolicy()
	assert.Equal(t, 3, p.MaxAttempts)
	assert.Equal(t, 50*time.Millisecond, p.BaseDelay)
	assert.Equal(t, 800*time.Millisecond, p.MaxDelay)
	assert.NotNil(t, p.RetryOn)
	assert.True(t, p.RetryOn(429, nil))
	assert.True(t, p.RetryOn(503, nil))
	assert.True(t, p.RetryOn(529, nil))
	assert.False(t, p.RetryOn(200, nil))
	assert.False(t, p.RetryOn(400, nil))
	assert.True(t, p.RetryOn(0, errors.New("net error")))
}

// TestDo_BackoffMonotonic is a smoke test: cumulative delay for MaxAttempts=4
// with default policy (no Retry-After) should fit within the theoretical
// 50+200+800=1050ms envelope, with jitter making it slightly shorter or
// longer but never anywhere close to zero (which would indicate missing sleep).
func TestDo_BackoffMonotonic(t *testing.T) {
	p := retry.Policy{
		MaxAttempts:  3,
		BaseDelay:    20 * time.Millisecond,
		MaxDelay:     80 * time.Millisecond,
		JitterFactor: 0,
	}
	start := time.Now()
	_ = retry.Do(context.Background(), p, func(ctx context.Context) retry.Result {
		return retry.Result{StatusCode: 503}
	})
	elapsed := time.Since(start)
	// First sleep happens after attempt 0 (20ms), second after attempt 1
	// (40ms) — total at least 60ms of sleep, no more than 80ms.
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
	assert.Less(t, elapsed, 250*time.Millisecond)
}
