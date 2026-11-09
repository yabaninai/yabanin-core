package provider

// N08-P03-T07 regression corpus: boundary pins for the packet's three
// aspects, so the observable errors and previous behavior delivered by
// T03–T06 stay fixed:
//
//  1. native auth project/location — binding-key boundaries, envelope
//     model→URL-path guard, credentials regex edges;
//  2. streaming/tools/usage/model mapping — finishReason fold boundaries,
//     the in-band Google error surfacing (2d12f19, stream arm),
//     tool-call index sequencing, usage-fold boundaries;
//  3. ADC workload identity refresh — JWT audience/lifetime claims,
//     token-response TTL edges, cooldown lapse recovery, in-skew
//     concurrent refresh deduplication.
//
// Everything is hermetic (httptest doubles via the established seams) and
// deterministic: assertions are exact counts/identities, never sleeps.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// — Aspect 1: native auth project/location boundaries —

// TestVertexRegression_BindingKeyBoundaries pins the cache-key composition
// on the SUCCESS path (T05 pins the refusal path): one shared adapter, one
// ambient credential, three bindings that differ by project only, location
// only, and both. Each binding's cold request performs exactly one exchange
// and carries exactly its own token on the wire; interleaved warm requests
// are served from the per-binding cache with zero new exchanges and no
// token ever crossing a binding boundary. A regression that flattens the
// key (source-only), drops the location component, or reorders the key
// parts flips one of these exact identities.
func TestVertexRegression_BindingKeyBoundaries(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()
	envelope := mustTranslate(t, v, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`)

	bindings := []struct{ name, creds, auth string }{
		{"proj A / us-central1", `{"project":"api-proj-0001","location":"us-central1"}`, "Bearer VT-1"},
		{"proj B / us-central1 (adjacent project id)", `{"project":"api-proj-0002","location":"us-central1"}`, "Bearer VT-2"},
		{"proj A / europe-west4 (same project, other location)", `{"project":"api-proj-0001","location":"europe-west4"}`, "Bearer VT-3"},
	}

	// Cold phase: each binding exchanges exactly once and rides its own
	// token — including the adjacent project id (key-truncation guard) and
	// the shared-project/different-location pair (key-composition guard).
	// The recorder mints a fresh token per binding so identities differ.
	for i, b := range bindings {
		rig.tokenSrv.bodyToken.Store(strings.TrimPrefix(b.auth, "Bearer "))
		req, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, b.creds, false)
		require.NoError(t, err, b.name)
		assert.Equal(t, b.auth, req.Header.Get("Authorization"), b.name)
		require.Equal(t, int64(i+1), rig.tokenSrv.hits.Load(), "%s: exchange count after cold request", b.name)
	}

	// Warm phase: interleaved re-requests are cache hits with unchanged
	// token identity — zero new exchanges.
	for _, i := range []int{2, 0, 1, 0, 2, 1} {
		req, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, bindings[i].creds, false)
		require.NoError(t, err, bindings[i].name)
		assert.Equal(t, bindings[i].auth, req.Header.Get("Authorization"), bindings[i].name)
	}
	require.Equal(t, int64(3), rig.tokenSrv.hits.Load(), "warm re-requests must not exchange")

	// Cache inventory: exactly one entry per (source, project, location).
	v.adc.mu.Lock()
	entries := len(v.adc.tokens)
	v.adc.mu.Unlock()
	require.Equal(t, 3, entries, "one cache entry per binding")
}

// TestVertexRegression_EnvelopeModelPathBoundaries pins the envelope's
// model guard: the model becomes a URL path segment in PrepareRequest, so
// every separator/traversal class is rejected at the envelope boundary
// before any credential or network work, while the legal boundary values
// (dots and hyphens in Gemini model names, surrounding whitespace) pass —
// and the TRIMMED name is what the matrix lookup and the URL path see.
func TestVertexRegression_EnvelopeModelPathBoundaries(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()

	rejects := []struct{ name, model string }{
		{"slash traversal", "gemini-2.5-flash/../../admin"},
		{"backslash", `gemini-2.5-flash\evil`},
		{"query separator", "gemini-2.5-flash?alt=nope"},
		{"fragment separator", "gemini-2.5-flash#frag"},
		{"colon (action separator)", "gemini-2.5-flash:generateContent"},
		{"bare dot-segments", ".."},
		{"leading dot-segments", "../gemini-2.5-flash"},
	}
	for _, tc := range rejects {
		body := `{"model":` + strconv.Quote(tc.model) + `,"gemini":{"contents":[]}}`
		_, err := parseVertexEnvelope([]byte(body))
		require.ErrorContains(t, err, "URL path separators", tc.name)
	}

	// Whitespace-only model: the trim runs before the emptiness check, so
	// a blank model is the no-model refusal, not a path segment.
	_, err := parseVertexEnvelope([]byte(`{"model":"   ","gemini":{"contents":[]}}`))
	require.ErrorContains(t, err, "envelope has no model")

	// A separator-free non-family name passes the envelope guard and is
	// rejected by the OUTER boundary (the capability matrix) with the
	// model named — the two layers compose, not overlap.
	_, err = parseVertexEnvelope([]byte(`{"model":"imagen-3.0-generate-001","gemini":{"contents":[]}}`))
	require.NoError(t, err, "envelope guard must not swallow matrix jurisdiction")
	_, err = v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false),
		mustTranslate(t, v, `{"model":"imagen-3.0-generate-001","messages":[{"role":"user","content":"hi"}]}`),
		rig.credsJSON, false)
	require.ErrorContains(t, err, `model "imagen-3.0-generate-001" is not in the capability matrix`)
	require.Zero(t, rig.tokenSrv.hits.Load(), "matrix rejection before any credential work")

	// Valid boundary: whitespace around the model is trimmed, the trimmed
	// form drives the matrix lookup AND the URL path.
	envelope := overrideEnvelopeModel(t,
		mustTranslate(t, v, `{"model":"whatever-client-said","messages":[{"role":"user","content":"hi"}]}`),
		"  gemini-2.5-pro  ")
	req, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, rig.credsJSON, false)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(req.URL.Path, "/publishers/google/models/gemini-2.5-pro:generateContent"),
		"URL path must carry the trimmed model, got %q", req.URL.Path)
	require.Equal(t, int64(1), rig.tokenSrv.hits.Load(), "exactly the one valid request exchanged")
}

// TestVertexRegression_CredentialsRegexBoundaries pins the exact length and
// character-class edges of ParseVertexCredentials (the values are baked
// into URL segments, so the regex IS the injection boundary). Length edges:
// project 6..30, location >= 2. Class edges: no dots, no leading/trailing
// hyphens.
func TestVertexRegression_CredentialsRegexBoundaries(t *testing.T) {
	t.Parallel()

	okCases := []struct{ name, blob string }{
		{"6-char project (min)", `{"project":"abc123","location":"us"}`},
		{"30-char project (max)", `{"project":"` + strings.Repeat("a", 29) + `1","location":"us"}`},
		{"2-char location (min)", `{"project":"api-proj-0001","location":"us"}`},
		{"multi-region token", `{"project":"api-proj-0001","location":"eu"}`},
	}
	for _, tc := range okCases {
		_, err := ParseVertexCredentials(tc.blob)
		require.NoError(t, err, tc.name)
	}

	errCases := []struct{ name, blob, wantErr string }{
		{"5-char project (under min)", `{"project":"abc12","location":"us"}`, "not a valid Google project ID"},
		{"31-char project (over max)", `{"project":"` + strings.Repeat("a", 31) + `","location":"us"}`, "not a valid Google project ID"},
		{"1-char location (under min)", `{"project":"api-proj-0001","location":"u"}`, "not a valid Vertex location"},
		{"leading hyphen project", `{"project":"-abc123","location":"us"}`, "not a valid Google project ID"},
		{"trailing hyphen project", `{"project":"abc123-","location":"us"}`, "not a valid Google project ID"},
		{"dot in project", `{"project":"a.bcde1","location":"us"}`, "not a valid Google project ID"},
		{"dot in location", `{"project":"api-proj-0001","location":"us.central1"}`, "not a valid Vertex location"},
	}
	for _, tc := range errCases {
		_, err := ParseVertexCredentials(tc.blob)
		require.ErrorContains(t, err, tc.wantErr, tc.name)
	}
}

// — Aspect 2: streaming / tools / usage / model mapping boundaries —

// TestVertexRegression_FinishReasonBoundaries completes the vertexFinishReason
// fold pins on both wires. The T03 table pins the non-stream rows except
// IMAGE_SAFETY (the seventh safety family); the stream pins cover STOP,
// tool_calls and MALFORMED_FUNCTION_CALL only. This corpus closes both gaps:
// the same fold must map IMAGE_SAFETY → content_filter non-stream and
// MAX_TOKENS/SAFETY/unknown identically on the SSE path.
func TestVertexRegression_FinishReasonBoundaries(t *testing.T) {
	t.Parallel()

	// Non-stream: IMAGE_SAFETY joins the safety family.
	out, err := (&Vertex{}).TranslateResponse([]byte(
		`{"candidates":[{"content":{"parts":[{"text":"blocked"}]},"finishReason":"IMAGE_SAFETY"}]}`))
	require.NoError(t, err)
	var translated map[string]any
	require.NoError(t, json.Unmarshal(out, &translated))
	assert.Equal(t, "content_filter", vertexChoice(t, translated)["finish_reason"])

	// Stream: finishReason events on the SSE wire.
	streamCases := []struct{ name, finish, want string }{
		{"MAX_TOKENS", "MAX_TOKENS", "length"},
		{"SAFETY", "SAFETY", "content_filter"},
		{"unknown family keeps stop", "OTHER_REASON", "stop"},
	}
	for _, tc := range streamCases {
		sse := "data: " + `{"candidates":[{"finishReason":` + strconv.Quote(tc.finish) + `}]}` + "\n\n"
		resp := newSSEResponse(sse)
		defer resp.Body.Close()
		w, buf := newRecorder()
		usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
		require.NoError(t, err, tc.name)
		frames := parseVertexStreamFrames(t, buf.String())
		require.Len(t, frames, 2, "%s: finish chunk + usage-only chunk", tc.name)
		assert.Equal(t, tc.want, vertexChoice(t, frames[0])["finish_reason"], tc.name)
		assert.Equal(t, Usage{Source: UsageSourceNone}, usage, tc.name)
	}
}

// TestVertexRegression_StreamInBandErrorWins pins the stream arm of the
// 2d12f19 product fix (the non-stream arm is pinned by
// TestVertexNegative_NonStreamUpstreamErrorSurfaced): a Google error object
// inside a chunk must surface verbatim and must never be masked as a
// successful response — not even when candidates ride in the same event,
// and not after content has already been streamed. The client-visible
// contract: error text carrying the Google status, zero fabricated success,
// and never a terminal [DONE].
func TestVertexRegression_StreamInBandErrorWins(t *testing.T) {
	t.Parallel()

	// Error object in the SAME event as complete candidates: the error
	// wins, nothing is written to the client.
	w, buf := newRecorder()
	sse := `data: {"candidates":[{"content":{"parts":[{"text":"half-success"}]},"finishReason":"STOP"}],` +
		`"error":{"code":429,"message":"quota exceeded","status":"RESOURCE_EXHAUSTED"}}` + "\n\n"
	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").
		HandleStream(context.Background(), w, w, resp)
	require.ErrorContains(t, err, "vertex stream error (status RESOURCE_EXHAUSTED): quota exceeded")
	assert.NotContains(t, err.Error(), "no candidates", "must not degrade into the no-candidates refusal")
	assert.Equal(t, Usage{}, usage, "a failed stream reports no provider usage")
	assert.Empty(t, buf.String(), "error-wins event writes nothing — no role/content/finish/[DONE]")

	// Mid-stream refusal: prior content stays flushed (already on the
	// wire), the error surfaces, and the stream never completes cleanly.
	w, buf = newRecorder()
	sse = "data: " + `{"candidates":[{"content":{"parts":[{"text":"visible"}]},"role":"model"}]}` + "\n\n" +
		`data: {"error":{"code":403,"message":"request denied","status":"PERMISSION_DENIED"}}` + "\n\n"
	resp = newSSEResponse(sse)
	defer resp.Body.Close()
	_, err = NewStreamHandler("vertex", "gemini-2.0-flash").
		HandleStream(context.Background(), w, w, resp)
	require.ErrorContains(t, err, "vertex stream error (status PERMISSION_DENIED): request denied")
	out := buf.String()
	assert.Contains(t, out, "visible", "already-flushed content is not rewritten")
	assert.NotContains(t, out, "[DONE]", "a refused stream never sends the completion marker")
}

// TestVertexRegression_StreamToolCallIndexSequence pins multi-call tool
// streaming: functionCall parts increment the OpenAI tool_call index across
// events, absent args become "{}" verbatim, and the stream closes with
// finish_reason tool_calls (the single-call/args-round-trip pins live in
// the T03 stream tests).
func TestVertexRegression_StreamToolCallIndexSequence(t *testing.T) {
	t.Parallel()

	sse := "data: " + `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"Moscow"}}}]}}]}` + "\n\n" +
		"data: " + `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_time"}}]}}]}` + "\n\n" +
		"data: " + `{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1}}` + "\n\n"

	w, buf := newRecorder()
	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").
		HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	frames := parseVertexStreamFrames(t, buf.String())
	require.Len(t, frames, 5, "role + tool(0) + tool(1) + finish + usage-only, got:\n%s", buf.String())

	callOf := func(t *testing.T, chunk map[string]any) map[string]any {
		t.Helper()
		choice := vertexChoice(t, chunk)
		calls, ok := choice["delta"].(map[string]any)["tool_calls"].([]any)
		require.True(t, ok, "delta = %v", choice["delta"])
		require.Len(t, calls, 1)
		call, ok := calls[0].(map[string]any)
		require.True(t, ok)
		return call
	}

	first := callOf(t, frames[1])
	assert.InDelta(t, float64(0), first["index"], 1e-9, "first call carries index 0")
	fn, ok := first["function"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "get_weather", fn["name"])
	assert.JSONEq(t, `{"city":"Moscow"}`, fn["arguments"].(string))

	second := callOf(t, frames[2])
	assert.InDelta(t, float64(1), second["index"], 1e-9, "second call carries index 1")
	fn, ok = second["function"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "get_time", fn["name"])
	assert.Equal(t, "{}", fn["arguments"], "absent args → {}")

	assert.Equal(t, "tool_calls", vertexChoice(t, frames[3])["finish_reason"], "tool stream finishes with tool_calls")
	assert.Equal(t, Usage{PromptTokens: 5, CompletionTokens: 1, TotalTokens: 6, Source: UsageSourceProvider}, usage)
}

// TestVertexRegression_NonStreamUsageBoundaries pins the non-stream usage
// fold boundaries (the stream side is pinned by the usage-chunk tests):
// cachedContentTokenCount 0 suppresses the prompt_tokens_details block but
// keeps the usage block; all-zero counts are still provider metering
// (present usageMetadata is a fact — only an ABSENT block is omitted);
// translated bodies keep parsing through the gateway's ParseUsage.
func TestVertexRegression_NonStreamUsageBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("zero cache read omits details but keeps block", func(t *testing.T) {
		t.Parallel()
		out, err := (&Vertex{}).TranslateResponse([]byte(`{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}],` +
			`"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":3,"totalTokenCount":15,"cachedContentTokenCount":0}}`))
		require.NoError(t, err)
		var body map[string]any
		require.NoError(t, json.Unmarshal(out, &body))
		usage, ok := body["usage"].(map[string]any)
		require.True(t, ok, "usage block present")
		_, hasDetails := usage["prompt_tokens_details"]
		assert.False(t, hasDetails, "cachedContentTokenCount 0 must not mint a details block")
		got := (*Vertex)(nil).ParseUsage(out)
		assert.Equal(t, Usage{PromptTokens: 12, CompletionTokens: 3, TotalTokens: 15, Source: UsageSourceProvider}, got)
	})

	t.Run("all-zero counts are provider metering", func(t *testing.T) {
		t.Parallel()
		out, err := (&Vertex{}).TranslateResponse([]byte(`{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}],` +
			`"usageMetadata":{"promptTokenCount":0,"candidatesTokenCount":0}}`))
		require.NoError(t, err)
		got := (*Vertex)(nil).ParseUsage(out)
		assert.Equal(t, Usage{Source: UsageSourceProvider}, got,
			"present usageMetadata with zeros is a reported fact, not absence")
	})
}

// — Aspect 3: ADC workload identity refresh boundaries —

// TestVertexRegression_JWTAudienceBoundary pins the SA grant's signed JWT
// audience semantics (the packet negative: "audience mismatch must not fall
// back to foreign credentials"): the aud claim is EXACTLY the key file's
// token_uri — the OAuth endpoint that must check it, never the Vertex
// endpoint, never the project — with the full vertexJWTTTL lifetime and the
// RS256 signing algorithm. TestVertexPrepareRequest_MockedAuth pins
// iss/scope; this corpus pins the audience/lifetime half.
func TestVertexRegression_JWTAudienceBoundary(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()
	envelope := mustTranslate(t, v, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`)
	_, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, rig.credsJSON, false)
	require.NoError(t, err)

	assertion := rig.tokenSrv.form(t).Get("assertion")
	require.NotEmpty(t, assertion, "grant_type urn:ietf:params:oauth:grant-type:jwt-bearer carries the assertion")

	header := decodeVertexJWTPart(t, assertion, 0)
	assert.Equal(t, "RS256", header["alg"], "SA assertions are RS256-signed")
	assert.Equal(t, "JWT", header["typ"])

	claims := decodeVertexJWTPart(t, assertion, 1)
	assert.Equal(t, rig.tokenSrv.srv.URL, claims["aud"],
		"aud is the key file's token_uri — the endpoint that must validate it")
	lifetime, ok := claims["exp"].(float64)
	require.True(t, ok)
	issued, ok := claims["iat"].(float64)
	require.True(t, ok)
	assert.InDelta(t, vertexJWTTTL.Seconds(), lifetime-issued, 1,
		"assertion carries the full one-hour lifetime")
	assert.InDelta(t, time.Now().Unix(), issued, 300, "iat is minted now, not replayed")
}

// TestVertexRegression_TokenResponseTTLBoundaries pins the response-side TTL
// edges: expires_in absent, 0 and negative all fall back to the default
// binding TTL (25m) — comfortably outside the 5m refresh skew, so the second
// request is served from cache with no second exchange, and the stored
// expiry sits at now+default.
func TestVertexRegression_TokenResponseTTLBoundaries(t *testing.T) {
	cases := []struct{ name, body string }{
		{"expires_in omitted", `{"access_token":"VT-1"}`},
		{"expires_in zero", `{"access_token":"VT-1","expires_in":0}`},
		{"expires_in negative", `{"access_token":"VT-1","expires_in":-100}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := newVertexRawTokenServer(t)
			raw.body.Store(tc.body)
			keyPath, _, _ := writeVertexSAKeyFile(t, raw.srv.URL)
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
			adc := plainVertexADC(raw.srv)
			creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

			tok, err := adc.token(creds)
			require.NoError(t, err)
			require.Equal(t, "VT-1", tok)

			tok, err = adc.token(creds)
			require.NoError(t, err)
			require.Equal(t, "VT-1", tok, "default-TTL token is fresh on the second call")
			require.Equal(t, int64(1), raw.hits.Load(), "default TTL applies after exactly one exchange")

			key := vertexSoleCacheKey(t, adc)
			adc.mu.Lock()
			cached := adc.tokens[key]
			adc.mu.Unlock()
			delta := time.Until(cached.tokenExp)
			assert.InDelta(t, vertexTokenDefaultTTL, delta, float64(time.Minute),
				"stored expiry is the default TTL (±1m of clock noise), got %s", delta)
		})
	}
}

// TestVertexRegression_CooldownLapseReAdmitsBinding pins the recovery leg of
// the 429 park (T05 pins the park itself and its per-binding isolation):
// while the cooldown is active the binding fails fast with no network work;
// once the cooldown timestamp lapses, the very next request performs exactly
// one fresh exchange, succeeds, serves the new token and CLEARS the stale
// cooldown entry.
func TestVertexRegression_CooldownLapseReAdmitsBinding(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.status.Store(http.StatusTooManyRequests)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	_, err := adc.token(creds)
	require.ErrorContains(t, err, "rate-limited")
	require.Equal(t, int64(1), tokenSrv.hits.Load())

	// Active cooldown: fail fast, zero further HTTP.
	_, err = adc.token(creds)
	require.ErrorContains(t, err, "rate-limited", "cooldown refuses the binding before any exchange")
	require.Equal(t, int64(1), tokenSrv.hits.Load(), "cooldown fail-fast does not touch the token endpoint")

	// Force the single cooldown entry into the past (adc.mu seam).
	adc.mu.Lock()
	require.Len(t, adc.cooldowns, 1, "the park wrote exactly one entry")
	for key := range adc.cooldowns {
		adc.cooldowns[key] = time.Now().Add(-time.Second)
	}
	adc.mu.Unlock()

	tokenSrv.status.Store(0)
	tokenSrv.bodyToken.Store("VT-2")
	tok, err := adc.token(creds)
	require.NoError(t, err)
	assert.Equal(t, "VT-2", tok, "lapsed cooldown re-admits the binding")
	require.Equal(t, int64(2), tokenSrv.hits.Load(), "recovery performs exactly one exchange")

	key := vertexSoleCacheKey(t, adc)
	adc.mu.Lock()
	cooldowns := len(adc.cooldowns)
	_, pinned := adc.tokens[key]
	adc.mu.Unlock()
	assert.Zero(t, cooldowns, "the successful exchange clears the stale cooldown")
	assert.True(t, pinned, "the fresh token is cached")
}

// TestVertexRegression_InSkewRefreshSingleflight pins the concurrent refresh
// contract (TestVertexADCRefresh_OnExpiry covers it for one caller, and
// TestVertexTokenSingleflightConcurrent covers the cold-start race): with the
// cached token inside the skew window, N concurrent callers produce exactly
// ONE new exchange and every caller — winner and singleflight waiters alike —
// receives the NEW token, never the in-skew stale one.
func TestVertexRegression_InSkewRefreshSingleflight(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	tok, err := adc.token(creds)
	require.NoError(t, err)
	require.Equal(t, "VT-1", tok)

	// Force the cached token into the skew window, then slow the exchange
	// so the concurrent callers pile onto the singleflight while it runs.
	key := vertexSoleCacheKey(t, adc)
	adc.mu.Lock()
	adc.tokens[key] = vertexToken{accessToken: "VT-1", tokenExp: time.Now().Add(2 * time.Minute)}
	adc.mu.Unlock()
	tokenSrv.bodyToken.Store("VT-2")
	tokenSrv.delay.Store(80)

	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
		assert.Equal(t, "VT-2", results[i], "caller %d must receive the refreshed token", i)
	}
	require.Equal(t, int64(2), tokenSrv.hits.Load(),
		"warm exchange + exactly one in-skew refresh under concurrency")
}
