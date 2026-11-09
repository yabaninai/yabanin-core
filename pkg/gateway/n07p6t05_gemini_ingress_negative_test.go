package cli

// N07-P06-T05 — negative ingress pins for native Gemini client traffic on
// the Vertex/Bedrock adapters (packet N07-P06 negative: "Vertex/Bedrock do
// not auto-declare native Gemini ingress; a test fixture is not live-client
// evidence"). Owner decisions I50 (native Gemini client ingress deferred)
// and I51 (explicit refusal, no silent reinterpretation/downgrade): a
// native generateContent body must never be reinterpreted as an OpenAI
// request, and no Gemini-shaped route may exist.
//
// Level note: these are offline fixture pins (real handler stack, stub
// upstream). Live-client evidence is recorded separately by T06/T07 — this
// file never claims it.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// geminiNativeBody is a minimal native Gemini generateContent payload:
// `contents` + `generationConfig`, no OpenAI `messages` field anywhere.
const geminiNativeBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"temperature":0.5}}`

// geminiIngressPaths enumerates the route shapes a native Gemini client
// would try: the packet's gateway-prefix forms. None of them may exist.
var geminiIngressPaths = []string{
	"/v1/gemini/v1beta/models/gemini-2.0-flash:generateContent",
	"/v1/gemini/v1beta/models/gemini-2.0-flash:streamGenerateContent",
	"/v1beta/models/gemini-2.0-flash:generateContent",
}

// newT05StubUpstream returns a stub upstream that counts every hit; the
// negative scenarios must leave the counter at zero (no upstream attempt
// may follow a refusal — T03/T04 contract §1).
func newT05StubUpstream(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(server.Close)
	return server, func() int { return calls }
}

// TestN07P6T05_NoGeminiIngressRoute pins the negative "no native Gemini
// ingress path exists" on both native adapters: every Gemini-shaped route
// attempt is a plain 404 (mux default — not a fabricated JSON/SSE error,
// not a proxied passthrough) and the upstream is never contacted. Zero
// upstream calls is the load-bearing half: a 404 with a leaked egress
// attempt would mean the request was interpreted before being refused.
func TestN07P6T05_NoGeminiIngressRoute(t *testing.T) {
	for _, provider := range []string{"vertex", "bedrock"} {
		server, count := newT05StubUpstream(t)
		gw := r105TestGateway(t, resolver.ModelInfo{
			ModelName: "gemini-2.0-flash-canon", Provider: provider,
			UpstreamURL: server.URL, Enabled: true,
		})

		for _, path := range geminiIngressPaths {
			rec := postR105(t, gw, path, geminiNativeBody, nil)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status %d, want 404 (no native Gemini ingress route may exist; body=%s)",
					provider, path, rec.Code, rec.Body.String())
			}
		}
		if n := count(); n != 0 {
			t.Fatalf("%s: upstream contacted %d times on refused Gemini ingress (must be zero)", provider, n)
		}
	}
}

// TestN07P6T05_GeminiBodyViaChatRefused pins the negative "native Gemini
// payload via an existing route is refused, not reinterpreted": the
// generateContent body posted to /v1/chat/completions fails the OpenAI
// admission parse (`messages is required`) and returns a JSON
// invalid_request_error — before any upstream egress and before any stream
// is opened (stream:true must not flip the refusal into an SSE error
// stream; the refusal is terminal JSON on both variants).
func TestN07P6T05_GeminiBodyViaChatRefused(t *testing.T) {
	for _, provider := range []string{"vertex", "bedrock"} {
		for _, stream := range []bool{false, true} {
			body := geminiNativeBody
			label := "non-stream"
			if stream {
				body = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"stream":true}`
				label = "stream:true"
			}

			server, count := newT05StubUpstream(t)
			gw := r105TestGateway(t, resolver.ModelInfo{
				ModelName: "gemini-2.0-flash-canon", Provider: provider,
				UpstreamURL: server.URL, Enabled: true,
			})

			rec := postR105(t, gw, "/v1/chat/completions", body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s: status %d, want 400 invalid_request_error (native Gemini body must be refused, not reinterpreted); body=%s",
					provider, label, rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct == "text/event-stream" {
				t.Fatalf("%s %s: refusal leaked as an SSE stream (must be terminal JSON)", provider, label)
			}
			if n := count(); n != 0 {
				t.Fatalf("%s %s: upstream contacted %d times on refused Gemini body (must be zero)", provider, label, n)
			}
		}
	}
}
