package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// Contract controls for the Claude Code Messages contract
// (docs/clients/claude-code.md, docs/compatibility.md): they bind documented
// facts to producer behavior — native tool-policy enforcement (the SSE and
// edge-case controls live in messages_claude_toolgate_test.go), the
// anthropic-version/beta header contract, unknown-field forwarding, and the
// response-header passthrough allowlist. They do not claim live-binary
// compatibility (the Claude Code CLI row stays `not verified`).

// ccNativeMessageBody is a minimal valid native /v1/messages reply the mock
// anthropic upstream serves for the header and passthrough controls.
const ccNativeMessageBody = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

// TestMessagesNative_ToolPolicyEnforced pins the native-surface TOOL-02
// contract end to end on one gateway with one wired deny engine: a `bash`
// deny policy strips the denied tool_use block from the native Anthropic
// reply while the allowed calculator survives with its id and input intact
// and the stop_reason stays tool_use (a survivor keeps the client tool loop
// alive); the SAME engine strips the tool call on the translated chat route,
// proving the engine was active for these requests. The ledger bills the
// ORIGINAL usage exactly once (CP-C02-02, docs/clients/claude-code.md).
func TestMessagesNative_ToolPolicyEnforced(t *testing.T) {
	const nativeBody = `{"id":"msg_2","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"working"},{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}},{"type":"tool_use","id":"toolu_2","name":"calculator","input":{"expr":"2+2"}}],"stop_reason":"tool_use","usage":{"input_tokens":3,"output_tokens":4}}`
	const adaptedBody = `{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{}"}},{"id":"c2","type":"function","function":{"name":"calculator","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

	var nativePathHit bool
	nativeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nativePathHit = r.URL.Path == "/v1/messages"
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, nativeBody)
	}))
	defer nativeServer.Close()

	adaptedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, adaptedBody)
	}))
	defer adaptedServer.Close()

	gw := responsesTestGateway(t, adaptedServer.URL)
	gw.res = stubModelResolver{
		"claude-3-5-sonnet": {ModelName: "claude-upstream", Provider: "anthropic", UpstreamURL: nativeServer.URL, UpstreamAPIKey: "upstream-key", Enabled: true},
		"m":                 {ModelName: "m", Provider: "openai", UpstreamURL: adaptedServer.URL, Enabled: true},
	}
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	terminal, events := ccCaptureNativeLedger(t)

	// Native branch: the deny policy removes the bash tool_use; the allowed
	// calculator (id + input) and the text block survive untouched.
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if !nativePathHit {
		t.Fatal("native branch was not served")
	}
	ccAssertNativeGated(t, rec)
	ccAssertNativeLedger(t, terminal(), events(), 3, 4)

	// Adapted contrast on the same gateway and engine: the identical deny
	// strips the call on the translated chat route.
	rec = postMessages(t, gw, `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	ccAssertAdaptedGate(t, rec)
}

// ccHeaderObserver captures the anthropic headers an upstream mock received.
type ccHeaderObserver struct {
	version, workspace string
	beta               []string
}

func (o *ccHeaderObserver) handler(w http.ResponseWriter, r *http.Request) {
	o.version = r.Header.Get("anthropic-version")
	o.workspace = r.Header.Get("anthropic-workspace-id")
	o.beta = r.Header["Anthropic-Beta"]
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, ccNativeMessageBody)
}

// TestMessagesNative_AnthropicHeaderDefaults pins the default branch of
// pkg/gateway/messages_native.go anthropicExtraHeaders: absent
// anthropic-version becomes 2023-06-01, absent anthropic-beta reaches the
// upstream as no header at all (the empty-value Set is deleted by upstream
// applyExtraHeaders, which also clears any adapter-default beta), and
// anthropic-workspace-id is not invented.
func TestMessagesNative_AnthropicHeaderDefaults(t *testing.T) {
	var obs ccHeaderObserver
	server := httptest.NewServer(http.HandlerFunc(obs.handler))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if obs.version != "2023-06-01" {
		t.Fatalf("default anthropic-version %q", obs.version)
	}
	if obs.beta != nil {
		t.Fatalf("absent client beta must not reach the upstream, got %v", obs.beta)
	}
	if obs.workspace != "" {
		t.Fatalf("workspace must not be invented, got %q", obs.workspace)
	}
}

// TestMessagesNative_AnthropicHeaderPassthrough pins the passthrough branch
// of anthropicExtraHeaders: client-supplied anthropic-version,
// anthropic-beta and anthropic-workspace-id ride to the upstream verbatim.
func TestMessagesNative_AnthropicHeaderPassthrough(t *testing.T) {
	var obs ccHeaderObserver
	server := httptest.NewServer(http.HandlerFunc(obs.handler))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2099-01-01")
	req.Header.Set("anthropic-beta", "interleaved-thinking-2025-05-14")
	req.Header.Set("anthropic-workspace-id", "ws_42")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if obs.version != "2099-01-01" || obs.workspace != "ws_42" {
		t.Fatalf("passthrough version %q workspace %q", obs.version, obs.workspace)
	}
	if len(obs.beta) != 1 || obs.beta[0] != "interleaved-thinking-2025-05-14" {
		t.Fatalf("passthrough beta %v", obs.beta)
	}
}

// TestMessagesNative_UnknownFieldsForwarded pins the native forward
// contract: request fields the gateway does not model (thinking,
// vendor extensions) survive the model remap and reach the anthropic
// upstream, and an upstream reply carrying unknown top-level fields is
// forwarded byte-identically.
func TestMessagesNative_UnknownFieldsForwarded(t *testing.T) {
	const reply = `{"id":"msg_9","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","vendor_hint":{"n":1},"usage":{"input_tokens":1,"output_tokens":1}}`
	var gotUpstream []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpstream, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	body := `{"model":"claude-3-5-sonnet","max_tokens":8,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Hi"}],"thinking":{"type":"enabled","budget_tokens":1024},"x_vendor_field":{"keep":true}}`
	rec := postMessages(t, gw, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	for _, field := range []string{"thinking", "x_vendor_field"} {
		want := ccJSONField(t, []byte(body), field)
		if have := ccJSONField(t, gotUpstream, field); !reflect.DeepEqual(want, have) {
			t.Fatalf("%s must reach the upstream intact: client %s upstream %s", field, want, have)
		}
	}
	assertNativeModelAndSystem(t, []byte(body), gotUpstream)
	if rec.Body.String() != reply {
		t.Fatalf("reply must be forwarded byte-identically, got %s", rec.Body.String())
	}
}

// ccJSONField decodes the named top-level member of a JSON object so field
// comparisons do not depend on wire formatting.
func ccJSONField(t *testing.T, body []byte, field string) interface{} {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(raw[field], &v); err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return v
}

// TestMessagesNative_ResponseHeaderPassthrough pins the response-header
// allowlist of pkg/gateway/messages_native.go copyAnthropicPassthrough on a
// 200 native reply: request-id, x-should-retry and
// anthropic-ratelimit-unified-* are relayed to the client; any other
// upstream header is not.
func TestMessagesNative_ResponseHeaderPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Request-Id", "req_native_1")
		w.Header().Set("X-Should-Retry", "false")
		w.Header().Set("Anthropic-Ratelimit-Unified-Reset", "5")
		w.Header().Set("X-Provider-Only", "internal")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, ccNativeMessageBody)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Request-Id") != "req_native_1" ||
		rec.Header().Get("X-Should-Retry") != "false" ||
		rec.Header().Get("Anthropic-Ratelimit-Unified-Reset") != "5" {
		t.Fatalf("allowlisted headers %#v", rec.Header())
	}
	if rec.Header().Get("X-Provider-Only") != "" {
		t.Fatalf("non-allowlisted upstream header leaked: %#v", rec.Header())
	}
}
