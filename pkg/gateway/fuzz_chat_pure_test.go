package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: the chat-path pure helpers — header identity,
// bounded sampling, whitelist resolution, upstream error extraction, the
// Retry-After client hint, the unknown-outcome refusal, the chat retry
// classifier and the cache document contract (FIX-10 read probe).
func TestChatPureHelpers(t *testing.T) {
	for i := range uint8(12) {
		if i < 6 {
			chatPureEarlyCase(t, int(i))
			continue
		}
		chatPureLateCase(t, int(i))
	}
}

// upstream429 builds the typed upstream failure the retry/header helpers
// consume.
func upstream429(header http.Header) *upstream.Error {
	if header == nil {
		header = http.Header{}
	}
	return &upstream.Error{Status: http.StatusTooManyRequests, Body: "{}", Header: header}
}

// chatPureEarlyCase covers cases 0-5.
func chatPureEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// The session key id is read from the trusted identity header the
		// auth middleware maintains.
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		require.Empty(t, headerSessionKeyID(r))
		r.Header.Set("X-Session-Key-Id", "sk-123")
		require.Equal(t, "sk-123", headerSessionKeyID(r))
	case 1:
		// boundedSample truncates with the explicit in-flight marker.
		require.Equal(t, "abc", boundedSample([]byte("abc"), 10))
		require.Equal(t, "abc", boundedSample([]byte("abc"), 3))
		require.Equal(t, "ab"+"\n…[truncated in flight]", boundedSample([]byte("abc"), 2))
		require.Equal(t, ""+"\n…[truncated in flight]", boundedSample([]byte("abc"), 0))
	case 2:
		// whitelistModel resolves an alias to its registry target; a direct
		// name is checked as the client sent it.
		require.Equal(t, "gpt-4o", whitelistModel(resolver.ModelInfo{Alias: "cheap", ModelName: "gpt-4o"}, "cheap"))
		require.Equal(t, "gpt-4o", whitelistModel(resolver.ModelInfo{}, "gpt-4o"))
	case 3:
		// extractUpstreamStatus surfaces only typed upstream failures.
		require.Equal(t, 0, extractUpstreamStatus(nil))
		require.Equal(t, 503, extractUpstreamStatus(&upstream.Error{Status: 503}))
		require.Equal(t, 503, extractUpstreamStatus(fmt.Errorf("wrapped: %w", &upstream.Error{Status: 503})))
		require.Equal(t, 0, extractUpstreamStatus(errors.New("transport boom")))
	case 4:
		// upstreamFailureHeaders quotes only a captured response's headers.
		h := http.Header{"Retry-After": {"7"}}
		require.Equal(t, http.Header(nil), upstreamFailureHeaders(nil))
		require.Equal(t, "7", upstreamFailureHeaders(upstream429(h)).Get("Retry-After"))
		require.Nil(t, upstreamFailureHeaders(errors.New("not sent")))
	case 5:
		// clientRetryAfterSeconds: the hint surfaces only for a 429 with a
		// parseable positive hint, rounded up and capped at 60s.
		past := time.Now().UTC().Add(-time.Minute).Format(http.TimeFormat)
		far := time.Now().UTC().Add(90 * time.Second).Format(http.TimeFormat)
		require.Equal(t, 0, clientRetryAfterSeconds(503, upstream429(http.Header{"Retry-After": {"7"}})))
		require.Equal(t, 0, clientRetryAfterSeconds(http.StatusTooManyRequests, nil))
		require.Equal(t, 0, clientRetryAfterSeconds(http.StatusTooManyRequests, upstream429(nil)))
		require.Equal(t, 7, clientRetryAfterSeconds(http.StatusTooManyRequests, upstream429(http.Header{"Retry-After": {"7"}})))
		require.Equal(t, 60, clientRetryAfterSeconds(http.StatusTooManyRequests, upstream429(http.Header{"Retry-After": {"3600"}})))
		require.Equal(t, 60, clientRetryAfterSeconds(http.StatusTooManyRequests, upstream429(http.Header{"Retry-After": {far}})))
		require.Equal(t, 0, clientRetryAfterSeconds(http.StatusTooManyRequests, upstream429(http.Header{"Retry-After": {past}})))
		require.Equal(t, 0, clientRetryAfterSeconds(http.StatusTooManyRequests, errors.New("boom")))
	default:
		t.Fatalf("unknown early chat-pure case %d", index)
	}
}

// chatPureLateCase covers cases 6-11.
func chatPureLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 6:
		// unknownOutcomeError carries a terminal 502 policy refusal and
		// exposes it via Unwrap/errors.As.
		err := unknownOutcomeError(errors.New("mid-stream reset"))
		require.Contains(t, err.Error(), "upstream outcome unknown: mid-stream reset")
		var policyErr *router.PolicyError
		require.ErrorAs(t, err, &policyErr)
		require.Equal(t, http.StatusBadGateway, policyErr.Status)
		require.Equal(t, "upstream_outcome_unknown", policyErr.ErrCode)
		require.Equal(t, policyErr, err.(interface{ Unwrap() error }).Unwrap())
	case 7:
		// chatRetryPolicy with the default inner classifier: policy refusals
		// and unsupported features never retry; transport errors and 429/503
		// do.
		p := chatRetryPolicy(retry.Policy{})
		require.True(t, p.RetryOn(0, errors.New("transport boom")))
		require.True(t, p.RetryOn(http.StatusTooManyRequests, nil))
		require.True(t, p.RetryOn(http.StatusServiceUnavailable, nil))
		require.False(t, p.RetryOn(http.StatusBadRequest, nil))
		require.False(t, p.RetryOn(http.StatusTooManyRequests, &router.PolicyError{Status: 403}))
		require.False(t, p.RetryOn(0, fmt.Errorf("wrap: %w", &router.PolicyError{Status: 503})))
		require.False(t, p.RetryOn(429, &provider.UnsupportedFeatureError{Provider: "openai", Reason: "no tools"}))
	case 8:
		// cachedCompletionUsable (FIX-10 read probe): decodable JSON with at
		// least one fully terminated choice.
		doc, err := cachedCompletionUsable([]byte(`{"choices":[{"finish_reason":"stop"}]}`))
		require.NoError(t, err)
		require.Len(t, doc.Choices, 1)
		_, err = cachedCompletionUsable([]byte(`torn`))
		require.Error(t, err)
		_, err = cachedCompletionUsable([]byte(`{"choices":[]}`))
		require.EqualError(t, err, "cache hit document has no choices")
		_, err = cachedCompletionUsable([]byte(`{"choices":[{"finish_reason":null}]}`))
		require.EqualError(t, err, "cache hit document has no finish_reason (truncated stream refused)")
		_, err = cachedCompletionUsable([]byte(`{"choices":[{"finish_reason":"stop"},{"finish_reason":null}]}`))
		require.EqualError(t, err, "cache hit document has no finish_reason (truncated stream refused)")
	case 9:
		// cachedUsageCounterfactual prices only usable documents with a
		// non-zero usage object; unknown prices fail closed to 0.
		require.Zero(t, cachedUsageCounterfactual([]byte(`torn`), "openai", "gpt-4o"))
		require.Zero(t, cachedUsageCounterfactual([]byte(`{"choices":[{"finish_reason":"stop"}]}`), "openai", "gpt-4o"))
		require.Zero(t, cachedUsageCounterfactual(
			[]byte(`{"choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0}}`), "openai", "gpt-4o"))
		withUsage := []byte(`{"choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500}}`)
		require.Positive(t, cachedUsageCounterfactual(withUsage, "openai", "gpt-4o"))
		require.Zero(t, cachedUsageCounterfactual(withUsage, "openai", "no-such-model"))
	case 10:
		// comparableResponseText (TP-04): only a full non-empty text answer
		// is judgeable; tool-only or empty answers are not.
		text, ok := comparableResponseText([]byte(`{"choices":[{"message":{"content":"answer"}}]}`))
		require.True(t, ok)
		require.Equal(t, "answer", text)
		_, ok = comparableResponseText([]byte(`torn`))
		require.False(t, ok)
		_, ok = comparableResponseText([]byte(`{}`))
		require.False(t, ok)
		_, ok = comparableResponseText([]byte(`{"choices":[{"message":{"content":null}}]}`))
		require.False(t, ok)
		_, ok = comparableResponseText([]byte(`{"choices":[{"message":{"content":"   "}}]}`))
		require.False(t, ok)
	case 11:
		// A configured inner classifier is honored for ordinary outcomes but
		// refusals still never retry.
		never := chatRetryPolicy(retry.Policy{RetryOn: func(int, error) bool { return false }})
		require.False(t, never.RetryOn(http.StatusTooManyRequests, nil))
		require.False(t, never.RetryOn(0, errors.New("boom")))
		require.False(t, never.RetryOn(429, &router.PolicyError{Status: 403}))
		always := chatRetryPolicy(retry.Policy{RetryOn: func(int, error) bool { return true }})
		require.True(t, always.RetryOn(http.StatusBadRequest, nil))
		require.False(t, always.RetryOn(0, &router.PolicyError{Status: 400}))
	default:
		t.Fatalf("unknown late chat-pure case %d", index)
	}
}
