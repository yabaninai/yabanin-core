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
	"github.com/reireirei/yabanin/internal/retryclock"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
)

// RATELIMIT-FALLBACK P1: the decision layer must carry the failed attempt's
// captured response headers into retry scheduling, so an upstream 429's
// Retry-After hint (seconds or HTTP-date) takes precedence over the
// exponential backoff exactly as the pkg/retry boundary corpus pins. The
// discriminator is the scheduled delay itself, recorded through the
// context-carried retryclock sleeper: an unhinted 429 must yield the exact
// exponential backoff, a hinted one the MaxDelay-clamped hint, and hinted
// cases cancel the request from inside the pending wait — the deterministic
// form of a deadline firing mid-sleep. No assertion races wall-clock
// against machine speed.

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
// deterministic no-jitter policy tuned for exact scheduled-delay oracles.
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

// n07rlPostChat issues the same real chi-router request the production
// handler serves, with the caller's context so a retryclock sleeper carried
// on it reaches retry.Do's scheduling.
func n07rlPostChat(t *testing.T, gw *gateway, body string, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Org-Id", "org-test") // durable accounting binds org_id NOT NULL
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// n07rlScheduling records the scheduled delay, then optionally kills the
// request context from inside the pending wait — the deterministic form of
// a deadline firing mid-sleep. Cancelling from inside the seam guarantees
// the first attempt (and its captured headers) fully preceded the abort,
// which no wall-clock deadline can promise under load.
func n07rlScheduling(slept *[]time.Duration, cancel context.CancelFunc) retryclock.Sleeper {
	return func(ctx context.Context, d time.Duration) {
		*slept = append(*slept, d)
		if cancel != nil {
			cancel()
			<-ctx.Done()
		}
	}
}

func TestRetryAfterWiring_ChatHintFeedsRetryScheduler(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "1") // 1s hint clamps to MaxDelay=20ms

	gw := n07rlRetryGateway(t, up.URL)
	var slept []time.Duration
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctx, guard := context.WithTimeout(ctx, 2*time.Second)
	t.Cleanup(guard)
	ctx = retryclock.With(ctx, n07rlScheduling(&slept, cancel))
	rec := n07rlPostChat(t, gw, n03p6t06OpenAIPlainBody, ctx)

	assert.Equal(t, []time.Duration{20 * time.Millisecond}, slept,
		"the captured 1s hint clamped to MaxDelay=20ms feeds the scheduler — not the 5ms exponential backoff")
	assert.Equal(t, int64(1), dials.Load(),
		"the request dies while the hinted sleep is still pending: the scheduler stops before the second dial")
	assert.NotEqual(t, http.StatusOK, rec.Code, "the request still fails; only scheduling changes")
}

func TestRetryAfterWiring_ChatNoHintUsesExponentialBackoff(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "") // no header: exponential backoff

	gw := n07rlRetryGateway(t, up.URL)
	var slept []time.Duration
	// The timeout is only a wedged-scheduler guard; with the sleeper
	// carried on the request context no assertion races it.
	ctx, guard := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(guard)
	ctx = retryclock.With(ctx, n07rlScheduling(&slept, nil))
	rec := n07rlPostChat(t, gw, n03p6t06OpenAIPlainBody, ctx)

	assert.Equal(t, []time.Duration{5 * time.Millisecond}, slept,
		"without a captured hint the scheduler must pick the exponential backoff (BaseDelay<<attempt 0), never a Retry-After-derived delay")
	assert.Equal(t, int64(2), dials.Load(),
		"the unhinted exponential backoff is the only wait: the second dial fires")
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestRetryAfterWiring_StreamHintFeedsRetryScheduler(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "1") // clamped to MaxDelay=20ms

	gw := n07rlRetryGateway(t, up.URL)
	streamBody := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"summarize"}]}`
	var slept []time.Duration
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctx, guard := context.WithTimeout(ctx, 2*time.Second)
	t.Cleanup(guard)
	ctx = retryclock.With(ctx, n07rlScheduling(&slept, cancel))
	rec := n07rlPostChat(t, gw, streamBody, ctx)

	assert.Equal(t, []time.Duration{20 * time.Millisecond}, slept,
		"the stream path must honor the captured hint the same way (1s clamped to MaxDelay=20ms)")
	assert.Equal(t, int64(1), dials.Load(),
		"the stream request dies while the hinted sleep is still pending")
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
