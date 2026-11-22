package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: endpoint-level usage extraction and response
// shaping — embeddings/moderations usage, the realtime SSE usage relay, the
// Responses error envelope and its dropped-field header.
func TestEndpointUsageFacts(t *testing.T) {
	for i := range uint8(10) {
		if i < 5 {
			endpointUsageEarlyCase(t, int(i))
			continue
		}
		endpointUsageLateCase(t, int(i))
	}
}

// recorderFor builds a fresh response recorder for one endpoint write.
func recorderFor(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return httptest.NewRecorder()
}

// endpointUsageEarlyCase covers cases 0-4.
func endpointUsageEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// embeddingsUsage: the provider block wins; a zero prompt_tokens
		// falls back to total_tokens; no parseable block estimates from the
		// request bytes (~4 bytes/token).
		n, src := embeddingsUsage([]byte(`{"usage":{"prompt_tokens":7,"total_tokens":9}}`), []byte("abcd"))
		require.Equal(t, int64(7), n)
		require.Equal(t, provider.UsageSourceProvider, src)
		n, src = embeddingsUsage([]byte(`{"usage":{"prompt_tokens":0,"total_tokens":9}}`), []byte("abcd"))
		require.Equal(t, int64(9), n)
		require.Equal(t, provider.UsageSourceProvider, src)
		n, src = embeddingsUsage([]byte(`torn`), []byte("abcd"))
		require.Equal(t, int64(1), n)
		require.Equal(t, provider.UsageSourceEstimated, src)
		n, src = embeddingsUsage([]byte(`{"choices":[]}`), []byte("abcdefg"))
		require.Equal(t, int64(2), n)
		require.Equal(t, provider.UsageSourceEstimated, src)
	case 1:
		// moderationsInputValid: a non-empty string or a bounded array is
		// valid; everything else is refused with a 400 envelope.
		ok := moderationsInputValid(recorderFor(t), json.RawMessage(`"hello"`))
		require.True(t, ok)
		ok = moderationsInputValid(recorderFor(t), json.RawMessage(`[{"text":"a"},{"text":"b"}]`))
		require.True(t, ok)
		w := recorderFor(t)
		require.False(t, moderationsInputValid(w, nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "input is required")
		w = recorderFor(t)
		require.False(t, moderationsInputValid(w, json.RawMessage(`null`)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		w = recorderFor(t)
		require.False(t, moderationsInputValid(w, json.RawMessage(`""`)))
		require.Contains(t, w.Body.String(), "non-empty string")
		w = recorderFor(t)
		require.False(t, moderationsInputValid(w, json.RawMessage(`5`)))
		require.Contains(t, w.Body.String(), "array of items")
		w = recorderFor(t)
		require.False(t, moderationsInputValid(w, json.RawMessage(`[]`)))
		require.Contains(t, w.Body.String(), "must not be empty")
		w = recorderFor(t)
		tooMany := "[" + strings.TrimSuffix(strings.Repeat(`"x",`, 257), ",") + "]"
		require.False(t, moderationsInputValid(w, json.RawMessage(tooMany)))
		require.Contains(t, w.Body.String(), "the limit is 256")
	case 2:
		// moderationsUsage: absent or malformed blocks yield the zero usage
		// (no fabricated estimate); a present block is parsed.
		require.Equal(t, provider.Usage{}, moderationsUsage([]byte(`{}`)))
		require.Equal(t, provider.Usage{}, moderationsUsage([]byte(`torn`)))
		u := moderationsUsage([]byte(`{"usage":{"prompt_tokens":3,"total_tokens":3}}`))
		require.Equal(t, int64(3), u.PromptTokens)
		require.Equal(t, int64(3), u.TotalTokens)
	case 3:
		// realtimeUsageFromEvent: a top-level usage block or the nested
		// response.usage feeds the shared parser; anything else reports no
		// usage.
		u, ok := realtimeUsageFromEvent([]byte(`{"usage":{"total_tokens":11}}`))
		require.True(t, ok)
		require.Equal(t, int64(11), u.TotalTokens)
		u, ok = realtimeUsageFromEvent([]byte(`{"response":{"usage":{"total_tokens":12}}}`))
		require.True(t, ok)
		require.Equal(t, int64(12), u.TotalTokens)
		_, ok = realtimeUsageFromEvent([]byte(`{"other":1}`))
		require.False(t, ok)
		_, ok = realtimeUsageFromEvent([]byte(`torn`))
		require.False(t, ok)
		_, ok = realtimeUsageFromEvent([]byte(`{"usage":null}`))
		require.False(t, ok)
	case 4:
		// The realtime relay abort marker carries its operator-facing text.
		require.Equal(t, "upstream stream exceeds the realtime size limit", errRealtimeStreamTooLarge{}.Error())
	default:
		t.Fatalf("unknown early endpoint-usage case %d", index)
	}
}

// endpointUsageLateCase covers cases 5-9.
func endpointUsageLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 5:
		// WebSocket upgrades are refused (realtime is SSE-only).
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/realtime", nil)
		require.False(t, isWebSocketUpgrade(r))
		r.Header.Set("Upgrade", "WebSocket")
		require.True(t, isWebSocketUpgrade(r))
		r.Header.Set("Upgrade", "h2c")
		require.False(t, isWebSocketUpgrade(r))
	case 6:
		// firstTokenMsOrZero stamps only observed samples.
		require.Equal(t, int64(42), firstTokenMsOrZero(42, true))
		require.Equal(t, int64(0), firstTokenMsOrZero(42, false))
		require.Equal(t, int64(0), firstTokenMsOrZero(0, true))
	case 7:
		// unsupportedHeader renders dropped field names, bounded at 1024
		// bytes with an explicit truncation suffix.
		require.Empty(t, unsupportedHeader(nil))
		require.Equal(t, "a,b", unsupportedHeader([]string{"a", "b"}))
		require.Equal(t, strings.Repeat("x", 1024), unsupportedHeader([]string{strings.Repeat("x", 1024)}))
		long := unsupportedHeader([]string{strings.Repeat("x", 2000)})
		require.Len(t, long, 1024)
		require.True(t, strings.HasSuffix(long, ",…"))
	case 8:
		// writeResponsesError: status 0 degrades to 400, an empty type to
		// the canonical invalid_request_error; the envelope quotes code and
		// message.
		w := recorderFor(t)
		writeResponsesError(w, 400, "invalid_request_error", "bad_field", "nope")
		require.Equal(t, 400, w.Code)
		require.Contains(t, w.Header().Get("Content-Type"), "application/json")
		var env struct {
			Error struct {
				Message string  `json:"message"`
				Type    string  `json:"type"`
				Param   *string `json:"param"`
				Code    *string `json:"code"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.Equal(t, "nope", env.Error.Message)
		require.Equal(t, "invalid_request_error", env.Error.Type)
		require.NotNil(t, env.Error.Code)
		require.Equal(t, "bad_field", *env.Error.Code)
		require.Nil(t, env.Error.Param)
		w = recorderFor(t)
		writeResponsesError(w, 0, "", "", "m2")
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.Equal(t, "invalid_request_error", env.Error.Type)
		require.Nil(t, env.Error.Code)
	case 9:
		// providerListed matches case-insensitively on trimmed names; an
		// empty provider never matches.
		require.True(t, providerListed([]string{" anthropic ", "OpenAI"}, "OpenAI"))
		require.False(t, providerListed([]string{"anthropic"}, "openai"))
		require.False(t, providerListed(nil, "openai"))
		require.False(t, providerListed([]string{"openai"}, ""))
	default:
		t.Fatalf("unknown late endpoint-usage case %d", index)
	}
}
