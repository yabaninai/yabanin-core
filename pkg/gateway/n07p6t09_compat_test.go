package cli

// N07-P06-T09 — compatibility pins: real supported consumers of the packet
// surfaces are the legacy OpenAI-shaped clients (old request bodies without
// any packet-era fields, old SDK error models). Pins:
//
//   - legacy minimal rerank/moderations bodies (no top_n, string input)
//     keep working verbatim on the new gateway;
//   - legacy chat bodies (no tools/stream fields) keep working on a
//     compat provider;
//   - refusal envelopes stay legacy-parseable: error.type + error.message
//     are present and sufficient for an old SDK error struct; the packet's
//     machine `code` is additive only (unknown fields ignorable).
//
// Supported-consumer inventory (grep evidence, T01 §2): in-repo sdks/go is
// exercised by its own suite (run recorded in the T09 record); dashboard
// (web/) and sdks/node+python do not call rerank/moderations/realtime —
// nothing to break there. Unsupported cases carry explicit errors by the
// T02/T04/T05/T06 pins (never silent).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// t06Gateway/t06CountingUpstream are defined in n07p6t06_refusal_consistency_test.go.

// t09LegacyError mirrors a pre-packet SDK error struct: type+message only,
// no knowledge of the `code` field.
type t09LegacyError struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// TestN07P6T09_LegacyBodiesOnPacketSurfaces: minimal pre-packet request
// bodies (no packet-era fields) succeed verbatim on rerank and moderations.
func TestN07P6T09_LegacyBodiesOnPacketSurfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"legacy":true}`))
	}))
	t.Cleanup(server.Close)

	info := resolver.ModelInfo{ModelName: "compat-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}
	gw := r105TestGateway(t, info)

	for _, tc := range []struct {
		name, path, legacyBody string
	}{
		{"rerank without top_n", "/v1/rerank", `{"model":"m","query":"q","documents":["d"]}`},
		{"moderations string input", "/v1/moderations", `{"model":"m","input":"legacy text"}`},
	} {
		rec := postR105(t, gw, tc.path, tc.legacyBody, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: legacy body rejected with status %d body=%s — old consumers must keep working",
				tc.name, rec.Code, rec.Body.String())
		}
		if rec.Body.String() != `{"legacy":true}` {
			t.Fatalf("%s: passthrough mutated: %q", tc.name, rec.Body.String())
		}
	}
}

// TestN07P6T09_LegacyChatBodyOnCompatProvider: a chat body with only the
// historical fields (model+messages, no tools/tool_choice/stream) succeeds
// on a compat provider — packet additions are opt-in, not breaking.
func TestN07P6T09_LegacyChatBodyOnCompatProvider(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"m": {ModelName: "compat-canon", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	rec := rt02Post(t, gw, `{"model":"m","messages":[{"role":"user","content":"legacy"}]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy chat body: status %d body=%s — must keep working on a compat provider", rec.Code, rec.Body.String())
	}
	var out struct {
		Object string `json:"object"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Object != "chat.completion" {
		t.Fatalf("legacy chat response not chat.completion: %q err=%v", rec.Body.String(), err)
	}
}

// TestN07P6T09_RefusalEnvelopeLegacyParseable: the packet refusal envelope
// decoded by a legacy SDK struct yields type+message; the machine `code`
// rides along as an ignorable extra field (old error rendering keeps
// working; new consumers get the precise code).
func TestN07P6T09_RefusalEnvelopeLegacyParseable(t *testing.T) {
	server, _ := t06CountingUpstream(t)
	gw := t06Gateway(t, server.URL, "strict")

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["d"]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	var legacy t09LegacyError
	if err := json.Unmarshal(rec.Body.Bytes(), &legacy); err != nil {
		t.Fatalf("legacy error struct cannot parse refusal envelope: %v — body %s", err, rec.Body.String())
	}
	if legacy.Error.Type != "invalid_request_error" || legacy.Error.Message == "" {
		t.Fatalf("legacy fields empty: type=%q message=%q — old SDK error rendering breaks", legacy.Error.Type, legacy.Error.Message)
	}
	if got := n07p6t02ErrorCode(t, rec); got != "rerank_not_supported_for_provider" {
		t.Fatalf("additive code lost for new consumers: %q", got)
	}
}
