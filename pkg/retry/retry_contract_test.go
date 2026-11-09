package retry_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestDefaultClassifier pins the retry decision table: only transport errors,
// 429, 503 and Cloudflare's 529 are retryable; other 5xx (including 500) and
// all 2xx/4xx are final.
func TestDefaultClassifier(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		err   error
		retry bool
	}{
		{name: "transport error is candidate only with execution evidence", code: 0, err: context.DeadlineExceeded, retry: true},
		{name: "429 retries", code: http.StatusTooManyRequests, retry: true},
		{name: "503 retries", code: http.StatusServiceUnavailable, retry: true},
		{name: "529 cloudflare overloaded retries", code: 529, retry: true},
		{name: "500 is final by policy", code: http.StatusInternalServerError, retry: false},
		{name: "404 not retried", code: http.StatusNotFound, retry: false},
		{name: "200 success not retried", code: http.StatusOK, retry: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.retry, retry.DefaultClassifier(tt.code, tt.err))
		})
	}
}

func TestDo_UnknownTransportOutcomeIsTerminal(t *testing.T) {
	calls := 0
	res := retry.Do(context.Background(), retry.DefaultPolicy(), func(context.Context) retry.Result {
		calls++
		return retry.Result{Err: errors.New("connection reset after write")}
	})
	require.Error(t, res.Err)
	assert.Equal(t, 1, calls)
}

func TestDo_ProvenDialFailureCanRetry(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	calls := 0
	policy := retry.Policy{MaxAttempts: 2, BaseDelay: time.Nanosecond, RetryOn: retry.DefaultClassifier}
	res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
		calls++
		if calls == 1 {
			return retry.Result{Err: dialErr, Safety: retry.OutcomeNotExecuted}
		}
		return retry.Result{StatusCode: http.StatusOK}
	})
	require.NoError(t, res.Err)
	assert.Equal(t, 2, calls)
}

func TestDefinitelyNotSent(t *testing.T) {
	assert.True(t, retry.DefinitelyNotSent(&net.OpError{Op: "dial", Err: errors.New("refused")}))
	assert.False(t, retry.DefinitelyNotSent(&net.OpError{Op: "read", Err: errors.New("reset")}))
}

// TestDo_RetryAfterClampedToMaxDelay pins the P3.8 contract: a 429 with a
// long Retry-After header must be clamped to Policy.MaxDelay (never sleep for
// the requested seconds) and the retry loop must still succeed.
func TestDo_RetryAfterClampedToMaxDelay(t *testing.T) {
	policy := retry.Policy{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
		RetryOn:     retry.DefaultClassifier,
	}

	calls := 0
	start := time.Now()
	res := retry.Do(context.Background(), policy, func(ctx context.Context) retry.Result {
		calls++
		if calls == 1 {
			h := http.Header{}
			h.Set("Retry-After", "2") // two seconds — must be clamped to MaxDelay
			return retry.Result{StatusCode: http.StatusTooManyRequests, Headers: h}
		}
		return retry.Result{StatusCode: http.StatusOK}
	})
	elapsed := time.Since(start)

	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 2, calls)
	// If Retry-After were honored literally the test would take ~2s.
	assert.Less(t, elapsed, time.Second)
}
