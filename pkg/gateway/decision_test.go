package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// --- decision.go unit tests -------------------------------------------------

func TestRoutingDecision_JSONDeterministicAndCompact(t *testing.T) {
	d := routingDecision{
		Source:     decisionSourceTierRouter,
		Class:      "hard",
		Confidence: 0.87,
		Threshold:  0.6,
		Affinity:   "used",
		Preferred:  "glm-5.3",
		From:       "auto",
		To:         "glm-5.3",
	}
	b1, err := json.Marshal(d)
	require.NoError(t, err)
	b2, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Equal(t, b1, b2, "same decision must marshal identically")
	// Compact: no spaces/newlines in the marshaled form.
	assert.NotContains(t, string(b1), " ")
	assert.NotContains(t, string(b1), "\n")
}

func TestRoutingDecision_OmitEmpty(t *testing.T) {
	d := routingDecision{Source: decisionSourcePassthrough, From: "gpt-4o-mini"}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, map[string]any{"source": decisionSourcePassthrough, "from": "gpt-4o-mini"}, m)
}

func TestDecisionSourceCacheHit(t *testing.T) {
	assert.Equal(t, decisionSourceCacheExact, decisionSourceCacheHit("exact"))
	assert.Equal(t, decisionSourceCacheSemantic, decisionSourceCacheHit("semantic"))
	// Unknown source types are conservative: treated as exact.
	assert.Equal(t, decisionSourceCacheExact, decisionSourceCacheHit("weird"))
}

// quality_eval carries the snapshot version; non-quality decisions omit the
// field entirely (compact wire form stays unchanged for every other source).
func TestRoutingDecision_QualityEvalFields(t *testing.T) {
	d := routingDecision{
		Source:         decisionSourceQualityEval,
		Class:          "hard",
		Confidence:     0.87,
		Threshold:      0.6,
		From:           "auto",
		To:             "glm-5.3",
		QualityVersion: "9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33",
	}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	assert.NotContains(t, string(b), " ", "compact wire form")
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, decisionSourceQualityEval, m["source"])
	assert.Equal(t, "9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33", m["quality_version"])

	// quality_version is omitempty: the tier_router wire form is unchanged.
	b, err = json.Marshal(routingDecision{Source: decisionSourceTierRouter, Class: "easy"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "quality_version")
}

// CORE-TRACE-04: the optional rule identity rides the decision payload as a
// nested rule ref (namespace routing / id / content version). It must be
// present exactly when stamped and compact on the wire.
func TestRoutingDecision_RuleRef(t *testing.T) {
	d := routingDecision{
		Source: decisionSourceRuleOverride,
		From:   "auto",
		To:     "premium",
		Rule: &DecisionRuleRef{
			Namespace: "routing",
			ID:        "aaaa1111-0000-0000-0000-000000000001",
			Version:   "9b1deb4d3b7d4bec",
		},
	}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	assert.NotContains(t, string(b), " ", "compact wire form")
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	rule, ok := m["rule"].(map[string]any)
	require.True(t, ok, "rule ref must be a nested object: %s", b)
	assert.Equal(t, "routing", rule["namespace"])
	assert.Equal(t, "aaaa1111-0000-0000-0000-000000000001", rule["id"])
	assert.Equal(t, "9b1deb4d3b7d4bec", rule["version"])
}

// Byte-compat pin: a decision without a rule ref must serialize exactly like
// before CORE-TRACE-04 — no "rule" key, no shape change for legacy consumers
// (header parsers, the event pipeline, the request history reader).
func TestRoutingDecision_RuleOmittedWithoutRef(t *testing.T) {
	d := routingDecision{Source: decisionSourceRuleOverride, From: "auto", To: "premium"}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"rule":`, "no rule key at all when unstamped")
	assert.NotContains(t, string(b), "namespace", "no identity keys at all when unstamped")

	// Same pin on the serialization path used by header and event.
	gw := &gateway{cfg: config.Gateway{DecisionHeaderEnabled: true, DecisionEventEnabled: true}}
	hdr := gw.decisionJSON(decisionSourceRuleOverride, d)
	assert.NotContains(t, hdr, `"rule":`)
}

// --- gateway decisionJSON flag tests -----------------------------------------

func TestDecisionJSON_Enabled(t *testing.T) {
	gw := &gateway{cfg: config.Gateway{DecisionEventEnabled: true}}
	got := gw.decisionJSON(decisionSourceTierRouter, routingDecision{Source: decisionSourceTierRouter, Class: "hard"})
	require.NotEmpty(t, got)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(got), &m))
	assert.Equal(t, "hard", m["class"])
}

func TestDecisionJSON_DisabledOrEmptySource(t *testing.T) {
	gwOff := &gateway{cfg: config.Gateway{DecisionEventEnabled: false}}
	assert.Empty(t, gwOff.decisionJSON(decisionSourceTierRouter, routingDecision{Source: "tier_router"}))
	gwOn := &gateway{cfg: config.Gateway{DecisionEventEnabled: true}}
	assert.Empty(t, gwOn.decisionJSON("", routingDecision{Source: "x"}))
}

// --- header tests (full chatCompletions path, passthrough branch) ------------

// decisionTestPool makes the resolver fall back to the requested model name
// (no DB row) so the request goes through the plain passthrough branch —
// exactly the branch the X-Yabanin-Decision header documents.
type decisionTestPool struct{}

func (decisionTestPool) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return decisionTestRow{}
}

func (decisionTestPool) Close() {}

type decisionTestRow struct{}

func (decisionTestRow) Scan(dest ...interface{}) error { return pgx.ErrNoRows }

func decisionTestGateway(upstreamURL string) *gateway {
	gw := streamTestGateway(upstreamURL)
	gw.res = resolver.NewResolver(decisionTestPool{}, "smart", 0, gw.log)
	return gw
}

func TestChatCompletions_DecisionHeaderPresentAndParsable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	gw := decisionTestGateway(srv.URL)
	gw.cfg.DecisionHeaderEnabled = true
	gw.cfg.DecisionEventEnabled = true

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	hdr := rec.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, hdr, "X-Yabanin-Decision header must be set by default")
	var d routingDecision
	require.NoError(t, json.Unmarshal([]byte(hdr), &d), "header must parse: %q", hdr)
	assert.Equal(t, decisionSourcePassthrough, d.Source, "no classifier/rule wired → passthrough")
	assert.Equal(t, "gpt-4o-mini", d.From)
}

func TestChatCompletions_DecisionHeaderDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	gw := decisionTestGateway(srv.URL)
	gw.cfg.DecisionHeaderEnabled = false
	gw.cfg.DecisionEventEnabled = false

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get(decisionHeaderKey), "header must be absent when disabled")
}

// --- stream surface: decision header + event field ----------------------------

// TestServeStream_DecisionHeaderAndEvent: the SSE surface must carry the
// machine-readable routing decision exactly like the non-streaming path —
// header before the first flushed byte, routing_decision on the completed
// event.
func TestServeStream_DecisionHeaderAndEvent(t *testing.T) {
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.DecisionHeaderEnabled = true
	gw.cfg.DecisionEventEnabled = true
	info := resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}

	dec := routingDecision{Source: decisionSourceTierRouter, Class: "easy",
		Confidence: 0.9, Threshold: 0.6, From: "gpt-4o", To: "gpt-4o-mini"}

	w := httptest.NewRecorder()
	gw.serveStream(w, context.Background(), info,
		[]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`),
		false, "sess", "org-1", "team", "task", "req-1", gw.log, dec, "", 0.9, "", "", "", false)

	// Header present and machine-parseable (header is set before the first
	// flushed SSE byte, so it is visible in the recorder).
	raw := w.Header().Get(decisionHeaderKey)
	assert.NotEmpty(t, raw, "X-Yabanin-Decision header must be set on the SSE response")
	var parsed routingDecision
	require.NoError(t, json.Unmarshal([]byte(raw), &parsed))
	assert.Equal(t, decisionSourceTierRouter, parsed.Source)
	assert.Equal(t, "easy", parsed.Class)
	assert.Equal(t, "gpt-4o", parsed.From)
	assert.Equal(t, "gpt-4o-mini", parsed.To)

	// Streamed content still reaches the client.
	out := w.Body.String()
	assert.Contains(t, out, `"content":"hi"`, "streamed content must reach the client")
	assert.Contains(t, out, "[DONE]")
}

// TestServeStream_DecisionHeaderDisabled: with the header flag off, the SSE
// response carries no decision header. The event field is governed separately
// by DecisionEventEnabled and is only observable through the Redis stream
// (no publisher is wired in the stream tests).
func TestServeStream_DecisionHeaderDisabled(t *testing.T) {
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.DecisionHeaderEnabled = false
	gw.cfg.DecisionEventEnabled = false
	info := resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}

	dec := routingDecision{Source: decisionSourcePassthrough, From: "gpt-4o-mini"}

	w := httptest.NewRecorder()
	gw.serveStream(w, context.Background(), info,
		[]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`),
		false, "sess", "org-1", "team", "task", "req-1", gw.log, dec, "", 0, "", "", "", false)

	assert.Empty(t, w.Header().Get(decisionHeaderKey), "header must be absent when disabled")
	assert.Contains(t, w.Body.String(), `[DONE]`)
}
