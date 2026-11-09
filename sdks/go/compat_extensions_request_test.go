package yabanin

// N07-P01-T04 — request extensions via the own SDK's Extra mechanism
// (facet 3, artifacts/internal-delivery-program/N07-P01/T01-scope-2026-10-30.md §4).
//
// The request-side counterpart to compat_extensions_test.go: a consumer of
// the own SDK sends provider extensions (extra_body semantics) through
// ChatRequest.Extra and they reach the wire verbatim — the same bytes the
// gateway's RT-04 pass-through then carries upstream (boundary pinned in
// pkg/gateway/n07p1t04_extensions_test.go). Extension integers beyond
// float64's 2^53 window must keep their exact literal.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestChatRequest_ExtraMarshalsProviderExtensions pins the request-side
// mechanism: Extra keys are merged into the top-level body verbatim, typed
// fields still marshal, and an explicit Extra key overrides a same-named
// typed field.
func TestChatRequest_ExtraMarshalsProviderExtensions(t *testing.T) {
	req := ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Extra: map[string]json.RawMessage{
			"x_request_ext":    json.RawMessage(`{"retries":9007199254740993,"tag":"ext"}`),
			"reasoning_effort": json.RawMessage(`"low"`),
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request with extensions: %v", err)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("marshaled body is not a JSON object: %v (%s)", err, body)
	}
	if got := string(root["x_request_ext"]); got != `{"retries":9007199254740993,"tag":"ext"}` {
		t.Errorf("extension object must marshal verbatim, got %s", got)
	}
	if got := string(root["reasoning_effort"]); got != `"low"` {
		t.Errorf("extension scalar must marshal verbatim, got %s", got)
	}
	if got := string(root["model"]); got != `"gpt-4o-mini"` {
		t.Errorf("typed model field lost, got %s", got)
	}
	if _, ok := root["messages"]; !ok {
		t.Errorf("typed messages field lost")
	}
	if _, dup := root["Extra"]; dup {
		t.Errorf("Extra itself must never appear on the wire")
	}
}

// TestChatRequest_ExtraOverridesTypedField pins precedence: an explicit
// Extra key wins over the same-named typed field (documented extra_body
// semantics).
func TestChatRequest_ExtraOverridesTypedField(t *testing.T) {
	req := ChatRequest{
		Model: "typed-model",
		Extra: map[string]json.RawMessage{"model": json.RawMessage(`"ext-model"`)},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("marshaled body is not a JSON object: %v", err)
	}
	if got := string(root["model"]); got != `"ext-model"` {
		t.Errorf("explicit Extra key must override the typed field, got %s", got)
	}
}

// TestChatRequest_NoExtra_MarshalUnchanged pins backward compatibility: a
// request without Extra marshals exactly as the typed struct always did
// (omitempty semantics preserved).
func TestChatRequest_NoExtra_MarshalUnchanged(t *testing.T) {
	req := ChatRequest{Messages: []Message{{Role: "user", Content: "hi"}}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	want := `{"messages":[{"role":"user","content":"hi"}]}`
	if string(body) != want {
		t.Errorf("plain request marshal changed, got %s want %s", body, want)
	}
}

// TestChat_ExtraReachesGatewayAndResponseCaptures is the end-to-end SDK
// proof for the facet-3 acceptance line: the pinned mechanism pair —
// request Extra marshals extensions onto the wire, response Extra captures
// the extensions the gateway forwards back.
func TestChat_ExtraReachesGatewayAndResponseCaptures(t *testing.T) {
	var gotExt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var root map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&root); err != nil {
			t.Errorf("gateway-side decode failed: %v", err)
		}
		gotExt = string(root["x_request_ext"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(extensionsCompletionBody))
	}))
	t.Cleanup(srv.Close)

	c, err := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp, err := c.Chat(context.Background(), ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Extra:    map[string]json.RawMessage{"x_request_ext": json.RawMessage(`{"retries":9007199254740993}`)},
	})
	if err != nil {
		t.Fatalf("chat round-trip: %v", err)
	}

	if gotExt != `{"retries":9007199254740993}` {
		t.Errorf("request extension must reach the gateway body verbatim, got %s", gotExt)
	}
	if got := compactRaw(t, resp.Extra["x_provider_ext"]); got != `{"tier":"gold","rank":9007199254740993}` {
		t.Errorf("response extension must be captured verbatim, got %s", got)
	}
}
