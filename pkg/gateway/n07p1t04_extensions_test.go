package cli

// N07-P01-T04 — extensions explicit pass-through (facet 3 of the packet
// scope, artifacts/internal-delivery-program/N07-P01/T01-scope-2026-10-30.md §4).
//
// The RT-04 guarantee says the guarded raw JSON body is the single source of
// truth downstream of the egress guard. rt04_guard_vertical_test.go already
// codifies that unknown fields SURVIVE (Contains-level). This file pins the
// remaining half of the guarantee at value fidelity:
//
//   - every consumer/extension field reaches the upstream with its exact
//     JSON value bytes — including integers beyond float64's 2^53 precision
//     window, which the legacy map[string]interface{} model-override
//     round-trip silently corrupts (9007199254740993 → …92);
//   - upstream RESPONSE extensions (unknown top-level keys, unknown keys
//     inside choices/messages/usage) reach the client verbatim on both the
//     JSON and SSE surfaces;
//   - the card negative ("unsupported field not silently lost") is scoped to
//     this OpenAI pass-through surface: an unmodeled request field is
//     observable at the upstream capture. Cross-API adapter surfaces
//     intentionally do not carry unmodeled fields (apiformat translate +
//     precise-rejection hooks, T03/I51) and are documented exceptions, not
//     pass-through failures.
//
// Same harness as rt04_guard_vertical_test.go (rt04Gateway / rt04Capture /
// boolJSON). No secret is embedded in these bodies, so ModeRedact guard
// no-ops; the only permitted rewrite chain is model override → optional
// effort injection → stream_options injection, each of which must stay
// value-faithful.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// n07t04BigInt is 2^53+1: representable as a JSON integer literal, NOT
// representable as a float64 (the map[string]interface{} round-trip turns it
// into 9007199254740992). Any rewrite that decodes the body through
// interface{} silently corrupts extension values.
const n07t04BigInt = "9007199254740993"

const n07t04BigIntCorrupted = "9007199254740992"

// n07t04Body is a chat request whose payload a narrow typed projection would
// destroy: unknown top-level fields (scalar, nested object with a big int,
// string), unknown per-message fields and a tools array.
func n07t04Body(stream bool) []byte {
	return []byte(`{
		"model": "gpt-4o-mini",
		"messages": [
			{"role": "system", "content": "system context", "x_custom_msg": "msg-keep"},
			{"role": "user", "content": "please process patient-record"}
		],
		"stream": ` + boolJSON(stream) + `,
		"my_custom_field": "keep-me",
		"x_ext_cfg": {"retries": ` + n07t04BigInt + `, "nested": {"flag": true, "tag": "ext"}},
		"x_ext_scalar": "scalar-keep",
		"tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}]
	}`)
}

// n07t04Upstream returns an upstream double that captures request bodies and
// replies with respBody and the given content type.
func n07t04Upstream(t *testing.T, cap *rt04Capture, contentType string, respBody []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		cap.add(string(raw))
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// n07t04Compact normalizes a JSON fragment for byte comparison (RawMessage
// captures keep the encoder's exact spacing, so compare compacted forms).
func n07t04Compact(t *testing.T, v json.RawMessage) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.Compact(&buf, v))
	return buf.String()
}

// n07t04CompactBody compacts a captured upstream body for Contains-level
// assertions: RawMessage patching preserves the client's exact bytes
// (spacing and key order), so literal expectations must not depend on
// whitespace.
func n07t04CompactBody(t *testing.T, sent string) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.Compact(&buf, []byte(sent)))
	return buf.String()
}

// TestN07T04_JSON_BigIntExtensionSurvives pins value fidelity on the JSON
// path: the big-int extension value must reach the upstream with its exact
// literal, not the float64-nearest neighbour.
func TestN07T04_JSON_BigIntExtensionSurvives(t *testing.T) {
	cap := &rt04Capture{}
	resp := []byte(`{"id":"cmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	up := n07t04Upstream(t, cap, "application/json", resp)

	vert := &rt04MaskVertical{masking: false}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(n07t04Body(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	require.Equal(t, 1, cap.count())

	sent := n07t04CompactBody(t, cap.last())
	assert.Contains(t, sent, `"retries":`+n07t04BigInt,
		"extension integer beyond 2^53 must reach the upstream with its exact literal")
	assert.NotContains(t, sent, n07t04BigIntCorrupted,
		"the float64-corrupted value must never appear in the upstream payload")
}

// TestN07T04_SSE_BigIntExtensionSurvives pins the same value fidelity on the
// streaming path (serveStream applies its own per-hop model override).
func TestN07T04_SSE_BigIntExtensionSurvives(t *testing.T) {
	const sse = "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	cap := &rt04Capture{}
	up := n07t04Upstream(t, cap, "text/event-stream", []byte(sse))

	vert := &rt04MaskVertical{masking: false}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(n07t04Body(true))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	require.Equal(t, 1, cap.count())

	sent := n07t04CompactBody(t, cap.last())
	assert.Contains(t, sent, `"retries":`+n07t04BigInt,
		"extension integer beyond 2^53 must reach the upstream with its exact literal on the SSE path")
	assert.NotContains(t, sent, n07t04BigIntCorrupted)
}

// TestN07T04_EffortInjection_PreservesValueFidelity pins the effort-injection
// exception (T01 scope §1.7): injecting reasoning_effort re-encodes the body,
// and that re-encode must stay value-faithful for extension fields.
func TestN07T04_EffortInjection_PreservesValueFidelity(t *testing.T) {
	in := []byte(`{"model":"gpt-5.2","x_ext_cfg":{"retries":` + n07t04BigInt + `},"x_ext_scalar":"scalar-keep"}`)

	t.Run("unit-level injectReasoningEffort", func(t *testing.T) {
		out := injectReasoningEffort(in, "medium")
		assert.Contains(t, string(out), `"reasoning_effort":"medium"`, "effort must be injected")
		assert.Contains(t, string(out), `"retries":`+n07t04BigInt,
			"extension integer must survive the effort-injection re-encode exactly")
		assert.NotContains(t, string(out), n07t04BigIntCorrupted)
		assert.Contains(t, string(out), `"x_ext_scalar":"scalar-keep"`)
	})

	t.Run("gateway-level maybeInjectEffort", func(t *testing.T) {
		gw := newEffortTestGateway(t, true, "o3,o4-mini,gpt-5", []string{"o3", "o4-mini", "gpt-5"})
		out := gw.maybeInjectEffort(in, resolver.ModelInfo{Provider: "openai", ModelName: "gpt-5.2"}, classifier.ClassMedium)
		assert.Contains(t, string(out), `"reasoning_effort":"medium"`)
		assert.Contains(t, string(out), `"retries":`+n07t04BigInt)
		assert.NotContains(t, string(out), n07t04BigIntCorrupted)
	})
}

// TestN07T04_UnknownFieldsValueFidelity_GuardVertical codifies the RT-04
// contract at value fidelity: with guard redaction and an active vertical
// mask in the chain, every extension field still reaches the upstream with
// its exact value bytes while the content patches apply.
func TestN07T04_UnknownFieldsValueFidelity_GuardVertical(t *testing.T) {
	cap := &rt04Capture{}
	resp := []byte(`{"id":"cmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	up := n07t04Upstream(t, cap, "application/json", resp)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(n07t04Body(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	require.Equal(t, 1, cap.count())

	// RawMessage patching preserves the client's exact bytes (spacing and key
	// order included), so compare on the compacted form.
	sentCompact := n07t04CompactBody(t, cap.last())
	// Content patches (the documented re-encode exceptions) still apply…
	assert.Contains(t, sentCompact, "[MASKED-PROMPT]", "vertical mask must apply to the last message")
	assert.NotContains(t, sentCompact, "patient-record")
	// …and every extension field keeps its exact value bytes.
	assert.Contains(t, sentCompact, `"x_custom_msg":"msg-keep"`, "unknown per-message field")
	assert.Contains(t, sentCompact, `"my_custom_field":"keep-me"`, "unknown top-level scalar field")
	assert.Contains(t, sentCompact, "get_weather", "tools must survive")
	assert.Contains(t, sentCompact, `"retries":`+n07t04BigInt, "nested big-int extension value")
	assert.NotContains(t, sentCompact, n07t04BigIntCorrupted)

	// Structural check of the nested extension object: captured bytes must
	// compact to exactly the object the client sent (source key order and
	// value literals preserved; only surrounding whitespace normalizes).
	var root map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(cap.last()), &root))
	require.Contains(t, root, "x_ext_cfg")
	// Byte-exact comparison is the point: JSONEq decodes through float64 and
	// cannot distinguish 9007199254740993 from the corrupted 9007199254740992,
	// so semantic JSON equality is exactly what this assertion proves
	// insufficient for extension-value fidelity.
	assert.Equal(t, `{"retries":`+n07t04BigInt+`,"nested":{"flag":true,"tag":"ext"}}`, //nolint:testifylint // JSONEq collapses >2^53 ints through float64; byte fidelity is the property under test
		n07t04Compact(t, root["x_ext_cfg"]),
		"nested extension object must reach the upstream value-identical")
}

// TestN07T04_ResponseExtensionsForwardedVerbatim_JSON pins the response leg:
// unknown upstream top-level keys and unknown keys inside choices/messages/
// usage reach the OpenAI-format client byte-for-byte (verbatim forwarding,
// no policy post-processing in this fixture).
func TestN07T04_ResponseExtensionsForwardedVerbatim_JSON(t *testing.T) {
	respBody := []byte(`{"id":"cmpl-ext","object":"chat.completion","created":1760000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok","x_upstream_msg":"msg-ext"},"x_upstream_choice":"choice-ext","logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"x_upstream_usage":42},"system_fingerprint":"fp-ext","x_provider_ext":{"tier":"gold","rank":` + n07t04BigInt + `}}`)
	cap := &rt04Capture{}
	up := n07t04Upstream(t, cap, "application/json", respBody)

	vert := &rt04MaskVertical{masking: false}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(n07t04Body(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	assert.Equal(t, string(respBody), w.Body.String(),
		"upstream response extensions must reach the client byte-for-byte on the JSON surface")
}

// TestN07T04_ResponseExtensionsForwardedVerbatim_SSE pins the response leg on
// the streaming surface: unknown chunk-level and delta-level keys are passed
// through verbatim to the client.
func TestN07T04_ResponseExtensionsForwardedVerbatim_SSE(t *testing.T) {
	const frame1 = "data: {\"id\":\"c1\",\"x_chunk_ext\":\"chunk-keep\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\",\"x_delta_ext\":\"delta-keep\"},\"finish_reason\":null}]}\n\n"
	const frame2 = "data: {\"id\":\"c1\",\"x_chunk_ext\":\"usage-frame\",\"choices\":[],\"usage\":{\"total_tokens\":3,\"x_usage_ext\":\"usage-keep\"}}\n\n"
	const done = "data: [DONE]\n\n"
	cap := &rt04Capture{}
	up := n07t04Upstream(t, cap, "text/event-stream", []byte(frame1+frame2+done))

	vert := &rt04MaskVertical{masking: false}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(n07t04Body(true))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	out := w.Body.String()
	assert.Contains(t, out, frame1, "chunk frame with extension keys must reach the client verbatim")
	assert.Contains(t, out, frame2, "usage frame with extension keys must reach the client verbatim")
	assert.Contains(t, out, done, "client stream must terminate")
}

// TestN07T04_UnsupportedFieldObservableUpstream is the card negative
// ("unsupported field not silently lost"), explicitly scoped per T01 scope
// §6 to the OpenAI pass-through surface: a field the gateway does not model
// is observable at the upstream capture on both surfaces. Cross-API adapter
// surfaces intentionally do not carry unmodeled fields; there the packet's
// precise-rejection contract (I51) applies instead of silent pass-through.
func TestN07T04_UnsupportedFieldObservableUpstream(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		cap := &rt04Capture{}
		resp := []byte(`{"id":"cmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
		up := n07t04Upstream(t, cap, "application/json", resp)
		vert := &rt04MaskVertical{masking: false}
		gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(string(n07t04Body(false))))
		r.Header.Set("X-Org-Id", "org-1")
		w := httptest.NewRecorder()
		gw.chatCompletions(w, r)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, n07t04CompactBody(t, cap.last()), `"my_custom_field":"keep-me"`,
			"an unsupported request field must be observable at the upstream, not silently lost")
	})

	t.Run("sse", func(t *testing.T) {
		const sse = "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
		cap := &rt04Capture{}
		up := n07t04Upstream(t, cap, "text/event-stream", []byte(sse))
		vert := &rt04MaskVertical{masking: false}
		gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(string(n07t04Body(true))))
		r.Header.Set("X-Org-Id", "org-1")
		w := httptest.NewRecorder()
		gw.chatCompletions(w, r)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, n07t04CompactBody(t, cap.last()), `"my_custom_field":"keep-me"`)
	})
}
