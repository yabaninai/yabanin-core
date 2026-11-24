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

// FuzzEndpointUsageParsers feeds changing bodies — well-formed, typed wrong
// and torn — into the endpoint usage parsers and checks every output against
// an independent re-derivation of the documented contract, never against the
// parsers' own code path.
func FuzzEndpointUsageParsers(f *testing.F) {
	f.Add([]byte(`{"usage":{"prompt_tokens":7,"total_tokens":9}}`), []byte("abcd"))
	f.Add([]byte(`{"usage":{"prompt_tokens":0,"total_tokens":9}}`), []byte("abcdefg"))
	f.Add([]byte(`{"usage":{}}`), []byte("abcd"))
	f.Add([]byte(`{"usage":null}`), []byte("abcd"))
	f.Add([]byte(`{"usage":5}`), []byte("abcd"))
	f.Add([]byte(`{"usage":{"prompt_tokens":-7,"total_tokens":1}}`), []byte(""))
	f.Add([]byte(`{"usage":{"input_tokens":3,"completion_tokens":4}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"input_tokens":2,"output_tokens":5,"total_tokens":99,"cached_tokens":1}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"prompt_tokens":8,"prompt_tokens_details":{"cached_tokens":2}}}`), []byte("x"))
	f.Add([]byte(`{"response":{"usage":{"total_tokens":12}}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"total_tokens":4},"response":{"usage":{"total_tokens":99}}}`), []byte("x"))
	f.Add([]byte(`{"response":{"usage":7}}`), []byte("x"))
	f.Add([]byte(`{"response":{}}`), []byte("x"))
	f.Add([]byte(`{"response":5}`), []byte("x"))
	f.Add([]byte(`{"response":{"usage":"x"}}`), []byte("x"))
	f.Add([]byte(`{"usage":false}`), []byte("x"))
	f.Add([]byte(`{"usage":1e999}`), []byte("abcd"))
	// Deterministic malformed-field seeds, one per documented usage field:
	// each wrong type must make the whole block unusable, never crash the
	// oracle or fabricate a partial usage.
	f.Add([]byte(`{"usage":{"prompt_tokens":"x"}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"input_tokens":[]}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"output_tokens":{}}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"completion_tokens":true}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"total_tokens":"9"}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"cached_tokens":1.5}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"prompt_tokens_details":5}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"input_token_details":[]}}`), []byte("x"))
	// Typed decoding merges case-insensitive and duplicate keys with
	// encoding/json's documented rules; the oracle must match them.
	f.Add([]byte(`{"usage":{"PROMPT_TOKENS":3,"Total_Tokens":0}}`), []byte("abcd"))
	f.Add([]byte(`{"usage":{"Prompt_Tokens_Details":{"CACHED_TOKENS":4}}}`), []byte("x"))
	f.Add([]byte(`{"usage":5,"usage":{"prompt_tokens":1}}`), []byte("x"))
	f.Add([]byte(`{"usage":{"prompt_tokens":1,"prompt_tokens":2}}`), []byte("x"))
	f.Add([]byte(`[1,2]`), []byte(""))
	f.Add([]byte(`torn`), []byte("abcd"))
	f.Fuzz(func(t *testing.T, body []byte, input []byte) {
		// embeddingsUsage: a decodable non-null usage object wins with
		// prompt_tokens (falling back to total_tokens); otherwise the
		// estimate is ceil(len(input)/4) of the raw request bytes.
		n, src := embeddingsUsage(body, input)
		var doc struct {
			Usage *struct {
				PromptTokens int64 `json:"prompt_tokens"`
				TotalTokens  int64 `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &doc); err == nil && doc.Usage != nil {
			require.Equal(t, provider.UsageSourceProvider, src)
			want := doc.Usage.PromptTokens
			if want == 0 {
				want = doc.Usage.TotalTokens
			}
			require.Equal(t, want, n)
		} else {
			require.Equal(t, provider.UsageSourceEstimated, src)
			require.Equal(t, int64((len(input)+3)/4), n)
		}

		// moderationsUsage never fabricates a block: an unusable or
		// absent usage object yields the zero usage.
		mu := moderationsUsage(body)
		wantMu, wantMok := expectedUsageBlock(t, body)
		if wantMok {
			require.Equal(t, wantMu, mu)
		} else {
			require.Equal(t, provider.Usage{}, mu)
		}

		// realtimeUsageFromEvent resolves the top-level usage first, then
		// the response-nested one, and reports absence honestly.
		ru, rok := realtimeUsageFromEvent(body)
		wantRu, wantRok := expectedRealtimeUsage(t, body)
		require.Equal(t, wantRok, rok)
		if rok {
			require.Equal(t, wantRu, ru)
		}
	})
}

// usageLeaf mirrors the parsers' typed decode shape: every documented
// usage field, decoded in one strict pass. A wrong-typed field — or a bad
// duplicate whose decode error encoding/json records even when a later
// duplicate decodes — fails the whole pass, exactly like the production
// single-unmarshal gate.
type usageLeaf struct {
	Prompt        *int64 `json:"prompt_tokens"`
	Input         *int64 `json:"input_tokens"`
	Output        *int64 `json:"output_tokens"`
	Completion    *int64 `json:"completion_tokens"`
	Total         *int64 `json:"total_tokens"`
	Cached        *int64 `json:"cached_tokens"`
	PromptDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_token_details"`
}

// expectedUsageIO re-derives the documented in/out pair from a usable
// usage leaf: the prompt_tokens/input_tokens split names the input count,
// the output_tokens/completion_tokens split the output count.
func expectedUsageIO(leaf *usageLeaf) (int64, int64) {
	var in int64
	switch {
	case leaf.Prompt != nil:
		in = *leaf.Prompt
	case leaf.Input != nil:
		in = *leaf.Input
	}
	var out int64
	switch {
	case leaf.Output != nil:
		out = *leaf.Output
	case leaf.Completion != nil:
		out = *leaf.Completion
	}
	return in, out
}

// expectedUsageTotalCached re-derives the documented total (total_tokens
// wins over the in+out sum) and cached-token resolution (the flat
// cached_tokens field, then prompt_tokens_details, then
// input_token_details).
func expectedUsageTotalCached(leaf *usageLeaf, in, out int64) (int64, int64) {
	total := int64(0)
	if leaf.Total != nil {
		total = *leaf.Total
	}
	if total == 0 {
		total = in + out
	}
	var cached int64
	switch {
	case leaf.Cached != nil:
		cached = *leaf.Cached
	case leaf.PromptDetails != nil:
		cached = leaf.PromptDetails.CachedTokens
	case leaf.InputDetails != nil:
		cached = leaf.InputDetails.CachedTokens
	}
	return total, cached
}

// expectedUsageBlock re-derives the usage-block contract from the raw
// bytes with the parsers' single-pass typed decode: a missing usage
// object or any decode error — malformed usage data is an expected fuzz
// input whose documented result is an unusable block, never an oracle
// crash — reports false; a usable one assembles in/out, total and cached
// per the documented rules, with key matching following encoding/json
// (case-insensitive, last duplicate wins, first decode error persists).
func expectedUsageBlock(t *testing.T, body []byte) (provider.Usage, bool) {
	t.Helper()
	var probe struct {
		Usage *usageLeaf `json:"usage"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || probe.Usage == nil {
		return provider.Usage{}, false
	}
	in, out := expectedUsageIO(probe.Usage)
	total, cached := expectedUsageTotalCached(probe.Usage, in, out)
	return provider.Usage{
		PromptTokens:     in,
		CompletionTokens: out,
		TotalTokens:      total,
		CacheReadTokens:  cached,
		Source:           provider.UsageSourceProvider,
	}, true
}

// expectedRealtimeUsage re-derives the realtime event contract: the
// top-level usage block wins; when absent, a present response object's
// usage is consulted; either way the leaf must decode as a usage block.
func expectedRealtimeUsage(t *testing.T, body []byte) (provider.Usage, bool) {
	t.Helper()
	var doc struct {
		Usage    json.RawMessage `json:"usage"`
		Response *struct {
			Usage json.RawMessage `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return provider.Usage{}, false
	}
	raw := doc.Usage
	if len(raw) == 0 && doc.Response != nil {
		raw = doc.Response.Usage
	}
	if len(raw) == 0 {
		return provider.Usage{}, false
	}
	return expectedUsageBlock(t, []byte(`{"usage":`+string(raw)+`}`))
}
