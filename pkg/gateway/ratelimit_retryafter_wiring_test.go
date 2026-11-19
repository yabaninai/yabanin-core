package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
)

// RATELIMIT-FALLBACK P1: the decision layer must carry the failed attempt's
// captured response headers into retry scheduling, so an upstream 429's
// Retry-After hint (seconds or HTTP-date) takes precedence over the
// exponential backoff exactly as the pkg/retry boundary corpus pins. The
// discriminator is deterministic: the request deadline (10ms) sits between
// the unhinted backoff (5ms) and the clamped hinted delay (20ms = MaxDelay),
// and retry.Do's sleep is context-aware — a hint reaches the scheduler
// exactly when the retry stops before the second dial.

// n07rlUpstreamRateLimited answers every dial with 429 (+ optional
// Retry-After) and counts dials.
func n07rlUpstreamRateLimited(t *testing.T, hint string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var dials atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dials.Add(1)
		if hint != "" {
			w.Header().Set("Retry-After", hint)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &dials
}

// n07rlRetryGateway mirrors the n07t08 retry-gateway wiring with a
// deterministic no-jitter policy tuned for the deadline discriminator.
func n07rlRetryGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := n03p6t06ChatGateway(t, upstreamURL)
	gw.retryPolicy = retry.Policy{
		MaxAttempts:  2,
		BaseDelay:    5 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		JitterFactor: 0,
		RetryOn:      retry.DefaultClassifier,
	}
	return gw
}

func n07rlPostChatWithDeadline(t *testing.T, gw *gateway, body string, deadline time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	t.Cleanup(cancel)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func TestRetryAfterWiring_ChatHintFeedsRetryScheduler(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "1") // clamped to MaxDelay=20ms > 10ms deadline

	gw := n07rlRetryGateway(t, up.URL)
	start := time.Now()
	rec := n07rlPostChatWithDeadline(t, gw, n03p6t06OpenAIPlainBody, 10*time.Millisecond)
	elapsed := time.Since(start)

	assert.Equal(t, int64(1), dials.Load(),
		"a 1s hint clamped to 20ms exceeds the 10ms deadline: the scheduler must stop before the second dial")
	assert.GreaterOrEqual(t, elapsed, 9*time.Millisecond,
		"the deadline governs: the hinted sleep was still pending when it fired")
	assert.Less(t, elapsed, 2*time.Second, "sanity bound against a wedged scheduler")
	assert.NotEqual(t, http.StatusOK, rec.Code, "the request still fails; only scheduling changes")
}

func TestRetryAfterWiring_ChatNoHintUsesExponentialBackoff(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "") // no header: 5ms backoff < 10ms deadline

	gw := n07rlRetryGateway(t, up.URL)
	rec := n07rlPostChatWithDeadline(t, gw, n03p6t06OpenAIPlainBody, 10*time.Millisecond)

	assert.Equal(t, int64(2), dials.Load(),
		"without a header the 5ms exponential backoff fits before the deadline: the second dial fires")
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestRetryAfterWiring_StreamHintFeedsRetryScheduler(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "1")

	gw := n07rlRetryGateway(t, up.URL)
	streamBody := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"summarize"}]}`
	rec := n07rlPostChatWithDeadline(t, gw, streamBody, 10*time.Millisecond)

	assert.Equal(t, int64(1), dials.Load(),
		"the stream path must honor the captured hint the same way (clamped 20ms > 10ms deadline)")
	assert.Contains(t, rec.Body.String(), "data:",
		"the connect-phase failure is rendered as an SSE error frame")
}

func TestRetryAfterWiring_UpstreamFailureHeaders_Helper(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "7")

	assert.Nil(t, upstreamFailureHeaders(nil), "no error: no headers")
	assert.Nil(t, upstreamFailureHeaders(errors.New("plain failure")),
		"a non-upstream failure (refusal carrier, transport error) quotes nothing")
	assert.Nil(t, upstreamFailureHeaders(fmt.Errorf("hop m2: %w", errors.New("wrapped plain"))))

	uerr := &upstream.Error{Status: http.StatusTooManyRequests, Body: "busy", Header: h}
	assert.Equal(t, h, upstreamFailureHeaders(uerr))
	assert.Equal(t, h, upstreamFailureHeaders(fmt.Errorf("hop m2: %w", uerr)),
		"errors.As must reach captured headers through the fallback wrapping")
}
