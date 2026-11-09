package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RATELIMIT-FALLBACK P2: the exhausted decision-bearing render must surface
// the provider's own Retry-After hint to the caller — only on a legitimate
// upstream rate limit (last upstream status 429), only from the captured
// attempt headers, in whole seconds, never fabricated. A missing or garbage
// hint means the header is OMITTED, so the frozen response envelope is
// unchanged for every provider that does not send hints.

func hintHeader(k, v string) http.Header {
	h := http.Header{}
	h.Set(k, v)
	return h
}

func TestClientRetryAfterSeconds_Table(t *testing.T) {
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)

	for _, tc := range []struct {
		name    string
		code    int
		err     error
		want    int
		wantAny bool // assert > 0 without pinning a moving HTTP-date value
	}{
		{"429 seconds hint", 429, &upstream.Error{Status: 429, Body: "busy", Header: hintHeader("Retry-After", "12")}, 12, false},
		{"429 hint wrapped through fallback chain", 429, fmt.Errorf("hop m2: %w", &upstream.Error{Status: 429, Header: hintHeader("Retry-After", "3")}), 3, false},
		{"429 future http-date", 429, &upstream.Error{Status: 429, Header: hintHeader("Retry-After", future)}, 0, true},
		{"429 hint above ceiling clamps to 60", 429, &upstream.Error{Status: 429, Header: hintHeader("Retry-After", "120")}, 60, false},
		{"429 zero hint is unknown", 429, &upstream.Error{Status: 429, Header: hintHeader("Retry-After", "0")}, 0, false},
		{"429 negative hint is unknown", 429, &upstream.Error{Status: 429, Header: hintHeader("Retry-After", "-5")}, 0, false},
		{"429 garbage hint is unknown", 429, &upstream.Error{Status: 429, Header: hintHeader("Retry-After", "soon")}, 0, false},
		{"429 no captured headers", 429, &upstream.Error{Status: 429, Body: "busy"}, 0, false},
		{"429 without typed upstream error", 429, errors.New("transport exploded"), 0, false},
		{"429 nil error", 429, nil, 0, false},
		{"503 never surfaces a hint", 503, &upstream.Error{Status: 503, Header: hintHeader("Retry-After", "12")}, 0, false},
		{"500 with nil error", 500, nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := clientRetryAfterSeconds(tc.code, tc.err)
			if tc.wantAny {
				assert.Positive(t, got, "a live future-date hint must survive the ceil")
				assert.LessOrEqual(t, got, clientRetryAfterCeiling)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// n07rlChatGateway: chat gateway with a single-attempt policy — the first
// 429 exhausts immediately, so the client-facing render sees the attempt's
// captured headers with no retry noise.
func n07rlChatGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := n03p6t06ChatGateway(t, upstreamURL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	return gw
}

func TestClientRetryAfterHeader_ChatExhaustedSurfacesHint(t *testing.T) {
	up, dials := n07rlUpstreamRateLimited(t, "7")
	gw := n07rlChatGateway(t, up.URL)

	rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, int64(1), dials.Load(), "single-attempt policy: one dial exhausts")
	got := rec.Header().Get("Retry-After")
	secs, err := strconv.Atoi(got)
	require.NoError(t, err, "the header must be the plain seconds form SDK clients parse")
	assert.Equal(t, 7, secs, "the provider hint is surfaced verbatim (ceil of 7s)")
	assert.Contains(t, rec.Body.String(), "rate_limit_exceeded")
}

func TestClientRetryAfterHeader_ChatUnknownHintOmitted(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint string
	}{
		{"no header at all", ""},
		{"garbage form", "soon"},
		{"negative form", "-5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, _ := n07rlUpstreamRateLimited(t, tc.hint)
			gw := n07rlChatGateway(t, up.URL)

			rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)

			require.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Empty(t, rec.Header().Get("Retry-After"),
				"an unknown hint must OMIT the header — never fabricated")
			assert.Contains(t, rec.Body.String(), "rate_limit_exceeded")
		})
	}
}

// TestClientRetryAfterHeader_NonRateLimitedNeverHints pins the gate: a
// provider hint on a NON-429 failure is never surfaced — the client-facing
// Retry-After is reserved for genuine rate limits (503 maps to the 502
// upstream envelope, unchanged).
func TestClientRetryAfterHeader_NonRateLimitedNeverHints(t *testing.T) {
	var dials int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dials++
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"overloaded"}}`))
	}))
	defer up.Close()
	gw := n07rlChatGateway(t, up.URL)

	rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)

	require.Equal(t, http.StatusBadGateway, rec.Code, "503 maps to the 502 upstream envelope")
	assert.Empty(t, rec.Header().Get("Retry-After"))
}

// TestClientRetryAfterHeader_StreamExhaustedSurfacesHint pins SSE parity:
// the connect-phase exhaustion render sets the header before the error
// frames — nothing has been flushed yet, so the header reaches the client.
func TestClientRetryAfterHeader_StreamExhaustedSurfacesHint(t *testing.T) {
	up, _ := n07rlUpstreamRateLimited(t, "3")
	gw := n07rlChatGateway(t, up.URL)

	streamBody := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"summarize"}]}`
	rec := n03p6t06PostChat(t, gw, streamBody)

	assert.Equal(t, "3", rec.Header().Get("Retry-After"))
	body := rec.Body.String()
	assert.True(t, strings.HasPrefix(body, "data:"),
		"the SSE error frame still leads the payload: got %.80q", body)
	assert.Contains(t, body, "rate_limit_exceeded")
}

// TestClientRetryAfterHeader_StreamUnknownHintOmitted: SSE parity for the
// omission rule.
func TestClientRetryAfterHeader_StreamUnknownHintOmitted(t *testing.T) {
	up, _ := n07rlUpstreamRateLimited(t, "")
	gw := n07rlChatGateway(t, up.URL)

	streamBody := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"summarize"}]}`
	rec := n03p6t06PostChat(t, gw, streamBody)

	assert.Empty(t, rec.Header().Get("Retry-After"))
	assert.Contains(t, rec.Body.String(), "data:")
}
