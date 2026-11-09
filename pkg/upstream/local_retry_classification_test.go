package upstream

// Retry classification of the chat path.
// The gateway wraps every upstream attempt in retry.Do with the production
// policy (retry.DefaultPolicy, gateway.go:359) and classifies an attempt
// solely from (statusCode, err) — a plain error is retryable
// (retry.DefaultClassifier). These tests pin how the two local-endpoint
// failure modes interact with that loop, mirroring the chat.go:780-788
// closure shape:
//
//   - a per-call timeout after the request was sent has an unknown outcome and
//     is terminal; this local client error carries no proof that it was not
//     executed, so retry.Do must make exactly one attempt;
//   - a request-time SSRF refusal is a PERMANENT configuration refusal
//     (documented defect D-4: guard-on mode refuses explicitly allow-listed
//     private hosts, pkg/ssrf/ssrf.go:178-228; current refusal pinned green
//     by TestLocalEndpoint_AllowlistedPrivateEndpointRefusedAtRequestTime,
//     fix acceptance skipped via scripts/quality/skips.yaml) — yet today it
//     is classified like a transient error and retried to MaxAttempts. That
//     as-is behavior is pinned here: when the D-4 fix lands and config
//     refusals become non-retryable (single attempt), this pin and the skip
//     registry entry must be updated together.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const retryCompletionBody = `{"id":"cmpl-local-retry","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// TestRetryClassification_UnknownTimeoutIsTerminal pins the unknown-outcome
// half of the classification: the server receives the request before it
// stalls, so the timeout is not proof of non-execution and retry.Do must not
// replay it. The final typed error surfaces, never a success-shaped response.
func TestRetryClassification_UnknownTimeoutIsTerminal(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body) // drain like a real inference server
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanup order matters: unblock the handler BEFORE Close waits on it.
	t.Cleanup(func() {
		close(release)
		srv.CloseClientConnections()
		srv.Close()
	})

	client, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "llamacpp"})
	require.NoError(t, err)

	policy := retry.DefaultPolicy() // the exact policy the gateway uses (gateway.go:359)
	start := time.Now()
	res := retry.Do(context.Background(), policy, func(ctx context.Context) retry.Result {
		_, _, _, ferr := client.ForwardJSONCapturing(ctx,
			[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "", 150*time.Millisecond)
		if ferr != nil {
			return retry.Result{StatusCode: 0, Err: ferr} // chat.go:784 shape (plain errors carry no status)
		}
		return retry.Result{StatusCode: http.StatusOK}
	})
	elapsed := time.Since(start)

	assert.Equal(t, 1, int(attempts.Load()),
		"a timeout after request delivery has unknown outcome and must not be retried")
	require.Error(t, res.Err)
	require.EqualError(t, res.Err, "upstream request timeout",
		"the final attempt's typed error must surface, never a hang or a partial success")
	assert.Equal(t, 0, res.StatusCode)
	assert.Less(t, elapsed, 5*time.Second, "the retry loop must stay bounded by attempts × budget + backoff")
}

// TestRetryClassification_ProvenConnectFailureRetries verifies the opposite
// boundary: a dial failure proves the request was never sent, and remains
// retryable when that evidence is passed using the retry API's Safety field.
func TestRetryClassification_ProvenConnectFailureRetries(t *testing.T) {
	policy := retry.DefaultPolicy()
	var attempts atomic.Int64
	res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
		if attempts.Add(1) == 1 {
			return retry.Result{
				Err:    &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
				Safety: retry.OutcomeNotExecuted,
			}
		}
		return retry.Result{StatusCode: http.StatusOK}
	})

	require.NoError(t, res.Err)
	assert.Equal(t, 2, int(attempts.Load()), "proven pre-send connect failure must be retryable")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

// TestRetryClassification_AllowlistedPrivateEndpointDials pins the post-D-4
// behavior (owner decision 2026-10-13: an exact allow-list entry is an
// explicit operator pin, pkg/ssrf trustExactPins): with the guard on and the
// loopback host explicitly allow-listed, the forward DIALS and succeeds on
// the first attempt through the production retry shape — no refusal, and no
// retry storm (retry.DefaultPolicy stops at the first success). The
// pre-fix pin (request-time "reserved IP" refusal retried to MaxAttempts)
// is gone with the defect; the refusal class itself survives only for
// wildcard matches and default-mode lists, covered in pkg/ssrf tests. If
// this test fails, either the trusting-pin semantics or the retry
// classification changed — update this pin deliberately, not silently.
func TestRetryClassification_AllowlistedPrivateEndpointDials(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, retryCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	client, err := newTestClientWithAdapter(Options{
		BaseURL:          srv.URL,
		ProviderName:     "llamacpp",
		AllowedUpstreams: []string{"http://" + srv.Listener.Addr().String()},
	})
	require.NoError(t, err, "an explicitly allow-listed host must pass construction")

	policy := retry.DefaultPolicy()
	var attempts atomic.Int64
	res := retry.Do(context.Background(), policy, func(ctx context.Context) retry.Result {
		attempts.Add(1)
		_, _, _, ferr := client.ForwardJSONCapturing(ctx,
			[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "", 2*time.Second)
		if ferr != nil {
			return retry.Result{StatusCode: 0, Err: ferr} // chat.go:784 shape
		}
		return retry.Result{StatusCode: http.StatusOK}
	})

	require.NoError(t, res.Err, "an explicitly allow-listed loopback endpoint must dial through the production retry shape")
	assert.Equal(t, 1, int(attempts.Load()),
		"first-attempt success must stop the retry loop: no retry storm behind a healthy pinned endpoint")
	assert.Equal(t, 1, mock.CallCount(), "exactly one request reaches the pinned endpoint")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
