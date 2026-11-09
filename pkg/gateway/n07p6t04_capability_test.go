package cli

// Capability refusals and the downgrade report, end to end through the real
// chat handlers:
//
//   - An adapter capability refusal (bedrock tools/media, the shipped
//     adapters that can refuse today) is a client-shaped 400 with the
//     stable capability_not_supported code — never a fabricated 502
//     "outcome unknown", never a transport retry, never a failover hop to
//     another model (a refusal must not silently downgrade the capability
//     away), no circuit-breaker or credential penalty, and zero upstream
//     calls. JSON and SSE both render the typed refusal.
//   - The routing decision payload carries the typed downgrade report
//     ("downgrade":"time_window") exactly on downgraded requests; every
//     other decision payload stays free of the field.
//
// Evidence level: offline httptest fixtures, not a live-provider run.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
)

const n07p6t04ToolsBody = `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{}}}}]}`

const n07p6t04StreamToolsBody = `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{}}}}]}`

// TestN07P6T04_CapabilityRefusal_JSON_ClientShaped400BeforeUpstream: a
// tool-bearing request to a bedrock model is refused 400
// invalid_request_error/capability_not_supported with the adapter's precise
// message, zero upstream calls, and no analytics event — the refusal is a
// client error, not an upstream failure.
func TestN07P6T04_CapabilityRefusal_JSON_ClientShaped400BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t) // answers 200 if ever contacted — must stay silent
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"m": {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.eventNote = func(e *eventpub.Event) { t.Errorf("refused request published %+v", e) }

	rec := rt02Post(t, gw, n07p6t04ToolsBody, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "invalid_request_error", errorType(t, rec))
	assert.Equal(t, "capability_not_supported", n07p6t02ErrorCode(t, rec))
	assert.Contains(t, rec.Body.String(), "tools/tool_choice are not supported yet")
	assert.Equal(t, 0, u.totalCalls(), "capability refusal must not touch the upstream")
}

// TestN07P6T04_CapabilityRefusal_JSON_ChainTerminalNoFailover: with a
// failover chain and a configured fallback model wired to a reachable
// upstream, the refusal terminates the chain — neither the primary nor any
// fallback candidate is called (no silent downgrade of the capability away).
func TestN07P6T04_CapabilityRefusal_JSON_ChainTerminalNoFailover(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := streamTestGateway(server.URL)
	gw.wl = &rt02Access{}
	gw.res = stubModelResolver{
		"m":     {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: server.URL, Enabled: true, FailoverModels: []string{"fb"}},
		"fb":    {ModelName: "fb-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true},
		"smart": {ModelName: "smart", Provider: "openai", UpstreamURL: server.URL, Enabled: true},
	}

	rec := rt02Post(t, gw, n07p6t04ToolsBody, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "capability_not_supported", n07p6t02ErrorCode(t, rec))
	assert.Equal(t, int64(0), calls.Load(),
		"chain-terminal refusal: primary, failover and fallback candidates must all stay uncalled")
}

// TestN07P6T04_UnsupportedFeature_JSON_ImagePart: an image-bearing request
// carries the typed unsupported_feature answer (the adapter's media refusal
// is an UnsupportedFeatureError — N07-RECON restore; the
// capability_not_supported code stays reserved for the streaming/tools
// refusals pinned above).
func TestN07P6T04_UnsupportedFeature_JSON_ImagePart(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"m": {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: u.srv.URL, Enabled: true},
	}

	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}]}]}`
	rec := rt02Post(t, gw, body, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "unsupported_feature", n07p6t02ErrorCode(t, rec))
	assert.Contains(t, rec.Body.String(), "image inputs are not supported yet")
	assert.Equal(t, 0, u.totalCalls())
}

// TestN07P6T04_CapabilityRefusal_SSE_TerminalFrameBeforeUpstream: the same
// refusal on the streaming transport renders the structured SSE error frame
// (invalid_request_error + capability_not_supported + precise message)
// followed by [DONE], with zero upstream calls.
func TestN07P6T04_CapabilityRefusal_SSE_TerminalFrameBeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"m": {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: u.srv.URL, Enabled: true},
	}

	rec := rt02Post(t, gw, n07p6t04StreamToolsBody, nil)

	out := rec.Body.String()
	assert.Contains(t, out, `"type":"invalid_request_error"`)
	assert.Contains(t, out, `"code":"capability_not_supported"`)
	assert.Contains(t, out, "tools/tool_choice are not supported yet")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "SSE refusal must terminate with [DONE], got %q", out)
	assert.Equal(t, 0, u.totalCalls(), "SSE capability refusal must not touch the upstream")
}

// TestN07P6T04_DowngradeReport_TypedFieldOnDowngradedOnly: the R2
// cheap-hours/batch downgrade reports itself in the decision payload as
// "downgrade":"time_window"; a passthrough decision carries no downgrade
// field at all.
func TestN07P6T04_DowngradeReport_TypedFieldOnDowngradedOnly(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"m":            {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"cheap-target": {ModelName: "cheap-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.timeRoutingEnabled = true
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "cheap-target", Tier: "easy", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}, nil)
	gw.cfg.DecisionHeaderEnabled = true

	// X-Yabanin-Batch forces the downgrade path regardless of the window.
	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"t04-downgraded"}]}`,
		map[string]string{"X-Yabanin-Batch": "true"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	dec := rec.Header().Get("X-Yabanin-Decision")
	assert.Contains(t, dec, `"downgrade":"time_window"`)
	assert.Contains(t, dec, `"reason":"time_window_downgrade"`)
	assert.Contains(t, dec, `"to":"cheap-target"`)
	assert.Equal(t, "cheap-target", u.modelFor("/v1/chat/completions"))

	// Plain request: passthrough decision, no downgrade report.
	u2 := newRT02Upstream(t)
	gw2 := rt02ChatGateway(t, u2, &rt02Access{})
	gw2.res = stubModelResolver{
		"m": {ModelName: "m", Provider: "openai", UpstreamURL: u2.srv.URL, Enabled: true},
	}
	gw2.cfg.DecisionHeaderEnabled = true
	rec = rt02Post(t, gw2, `{"model":"m","messages":[{"role":"user","content":"t04-passthrough"}]}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	dec = rec.Header().Get("X-Yabanin-Decision")
	assert.NotContains(t, dec, "downgrade")
	assert.Contains(t, dec, `"source":"passthrough"`)
}
