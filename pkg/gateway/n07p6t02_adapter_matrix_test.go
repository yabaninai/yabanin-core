package cli

// N07-P06-T02 confirmation matrix: the supported OpenAI-compatible
// rerank/moderation adapters and their usage/error semantics, consolidated
// from the per-cell wire pins into one executable table (scope note —
// the confirmed remainder was exactly this matrix; no wire change).
//
// The compat admission decision (openai-compat option A) admits exactly the
// openAICompatProvider vocabulary (embeddings_endpoint.go) to the non-chat
// transport surface. Every other pkg/provider factory adapter is refused
// before any upstream call with a machine-readable reason: zai-coding by the
// RT-02 data-boundary gate, everything else by the D2 gate itself — nothing
// is silently accepted, and upstream-only Vertex/Bedrock translators never
// auto-declare client-facing rerank/moderation/realtime support (I49/I50/
// I51; T01 §1.4/§2). Usage follows D3: provider tokens when reported
// (either token vocabulary), honest none/no_usage when not, unknown_price
// without price rows — never a fabricated estimate.
//
// Evidence level: offline httptest fixtures — NOT a live-client or
// live-upstream run; a fixture must never be cited as live.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// n07p6t02CompatVocabulary is the D2 FINAL adapter matrix — the exact
// openAICompatProvider seam (embeddings_endpoint.go): the only provider
// names admitted to rerank/moderations/realtime(SSE). "" is the unset
// provider default (openai adapter).
var n07p6t02CompatVocabulary = []string{"openai", "openai-compat", "", "vllm", "ollama", "llamacpp", "mistral"}

// n07p6t02NonCompatAdapters enumerates every other adapter the provider
// factory can build (factory.go) — names that must stay OUTSIDE the
// non-chat transport matrix. zai-coding is asserted separately below: its
// refusal is owned by the RT-02 data-boundary gate, not the D2 gate.
var n07p6t02NonCompatAdapters = []string{
	"anthropic", "vertex", "bedrock", "azure-openai", "tgi",
	"yandex", "sber", "sakana", "sarvam", "krutrim", "naver", "falcon", "jais",
}

// n07p6t02Label renders the unset provider default readably in subtest names.
func n07p6t02Label(name string) string {
	if name == "" {
		return "(default)"
	}
	return name
}

// n07p6t02ErrorCode extracts error.code from an apierrors envelope.
func n07p6t02ErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("error envelope: %v — body %s", err, rec.Body.String())
	}
	return env.Error.Code
}

// TestN07P6T02_SupportedAdapterMatrix walks the whole D2 vocabulary through
// rerank and moderations: every admitted adapter reaches the OpenAI-compat
// upstream exactly once with the canonical model, the response passes
// through byte-identically, and usage accounting matches the endpoint
// contract — rerank bills provider tokens under either token vocabulary
// (input_tokens here) at unknown_price (no rerank price rows, D3);
// moderations carries no usage block and stays none/no_usage, never a
// fabricated estimate.
func TestN07P6T02_SupportedAdapterMatrix(t *testing.T) {
	const rerankResponse = `{"id":"rr","model":"rr-canon","results":[{"index":1,"relevance_score":0.9}],"usage":{"input_tokens":8,"output_tokens":2,"total_tokens":10}}`
	const moderationsResponse = `{"id":"mod","model":"mod-canon","results":[{"flagged":false,"categories":{},"category_scores":{}}]}`

	for _, prov := range n07p6t02CompatVocabulary {
		t.Run("adapter="+n07p6t02Label(prov), func(t *testing.T) {
			var rerankCalls, moderationsCalls atomic.Int64
			var rerankUpstreamBody, moderationsUpstreamBody atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				switch r.URL.Path {
				case "/v1/rerank":
					rerankCalls.Add(1)
					rerankUpstreamBody.Store(string(raw))
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(rerankResponse))
				case "/v1/moderations":
					moderationsCalls.Add(1)
					moderationsUpstreamBody.Store(string(raw))
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(moderationsResponse))
				default:
					t.Errorf("unexpected upstream path %q", r.URL.Path)
				}
			}))
			defer server.Close()

			gw := &gateway{
				cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
				log:  slog.New(slog.DiscardHandler),
				auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
				res: stubModelResolver{
					"rr":  {ModelName: "rr-canon", Provider: prov, UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true},
					"mod": {ModelName: "mod-canon", Provider: prov, UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true},
				},
				pool: upstream.NewPool(upstream.Options{}),
			}

			// Rerank row: admitted → exactly one upstream call, canonical
			// model, byte-honest passthrough, provider usage (input_tokens
			// vocabulary) with honest unknown_price.
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }
			rec := postR105(t, gw, "/v1/rerank", `{"model":"rr","query":"q","documents":["a","b"]}`, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("rerank status %d %s", rec.Code, rec.Body.String())
			}
			if strings.TrimSpace(rec.Body.String()) != rerankResponse {
				t.Fatalf("rerank passthrough %q", rec.Body.String())
			}
			if calls := rerankCalls.Load(); calls != 1 {
				t.Fatalf("rerank upstream calls %d, want 1", calls)
			}
			if body, _ := rerankUpstreamBody.Load().(string); !strings.Contains(body, `"model":"rr-canon"`) {
				t.Fatalf("rerank upstream body %q lacks canonical model", body)
			}
			if ev == nil {
				t.Fatal("rerank: no request.completed event")
			}
			if ev.Endpoint != "rerank" || ev.TokensIn != 8 || ev.TokensOut != 2 ||
				ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" || ev.ModelUsed != "rr-canon" {
				t.Fatalf("rerank event accounting: %+v", ev)
			}

			// Moderations row: admitted → exactly one upstream call, byte-
			// honest passthrough, and the no-usage-block contract (none /
			// no_usage — OpenAI moderations carry no usage).
			ev = nil
			rec = postR105(t, gw, "/v1/moderations", `{"model":"mod","input":"classify me"}`, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("moderations status %d %s", rec.Code, rec.Body.String())
			}
			if strings.TrimSpace(rec.Body.String()) != moderationsResponse {
				t.Fatalf("moderations passthrough %q", rec.Body.String())
			}
			if calls := moderationsCalls.Load(); calls != 1 {
				t.Fatalf("moderations upstream calls %d, want 1", calls)
			}
			if body, _ := moderationsUpstreamBody.Load().(string); !strings.Contains(body, `"model":"mod-canon"`) {
				t.Fatalf("moderations upstream body %q lacks canonical model", body)
			}
			if ev == nil {
				t.Fatal("moderations: no request.completed event")
			}
			if ev.Endpoint != "moderations" || ev.TokensIn != 0 ||
				ev.UsageSource != "none" || ev.CostStatus != "no_usage" || ev.ModelUsed != "mod-canon" {
				t.Fatalf("moderations event accounting: %+v", ev)
			}
		})
	}
}

// TestN07P6T02_UnsupportedAdapterRefusedBeforeUpstream walks every factory
// adapter outside the D2 vocabulary through all three non-chat transports:
// each is refused with its exact machine-readable reason and ZERO upstream
// calls — the D2 gate's <feature>_not_supported_for_provider for the plain
// non-compat adapters (including upstream-only vertex/bedrock translators,
// which never auto-declare client-facing support), and the RT-02
// data-boundary gate for zai-coding while the plan is disabled. No
// unsupported transport is silently accepted.
func TestN07P6T02_UnsupportedAdapterRefusedBeforeUpstream(t *testing.T) {
	rows := []struct {
		feature    string
		path       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"rerank", "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, http.StatusBadRequest, "rerank_not_supported_for_provider"},
		{"moderations", "/v1/moderations", `{"model":"m","input":"x"}`, http.StatusBadRequest, "moderations_not_supported_for_provider"},
		{"realtime", "/v1/realtime", `{"model":"m"}`, http.StatusBadRequest, "realtime_not_supported_for_provider"},
	}

	run := func(t *testing.T, prov string, codeOverride string, statusOverride int) {
		t.Helper()
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
		}))
		defer server.Close()

		gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "m-canon", Provider: prov, UpstreamURL: server.URL, Enabled: true})
		gw.eventNote = func(e *eventpub.Event) { t.Errorf("refused request published %+v", e) }

		for _, row := range rows {
			wantCode, wantStatus := row.wantCode, row.wantStatus
			if codeOverride != "" {
				wantCode, wantStatus = codeOverride, statusOverride
			}
			rec := postR105(t, gw, row.path, row.body, nil)
			if rec.Code != wantStatus {
				t.Fatalf("%s: status %d, want %d: %s", row.feature, rec.Code, wantStatus, rec.Body.String())
			}
			if code := n07p6t02ErrorCode(t, rec); code != wantCode {
				t.Fatalf("%s: error code %q, want %q: %s", row.feature, code, wantCode, rec.Body.String())
			}
		}
		if calls.Load() != 0 {
			t.Fatalf("upstream called %d times on refused adapters — silence boundary violated", calls.Load())
		}
	}

	for _, prov := range n07p6t02NonCompatAdapters {
		t.Run("adapter="+prov, func(t *testing.T) {
			// The D2 gate owns the refusal per feature; vertex/bedrock are
			// upstream-only translators and get no client-facing exception.
			run(t, prov, "", 0)
		})
	}

	t.Run("adapter=zai-coding", func(t *testing.T) {
		// RT-02 final-candidate gate denies inside admission, before the D2
		// gate and any upstream work: 403 provider_not_authorized on every
		// non-chat transport while the plan is disabled.
		run(t, "zai-coding", "provider_not_authorized", http.StatusForbidden)
	})
}

// TestN07P6T02_CompatSeamVocabularyPinned pins the single admission seam
// itself: openAICompatProvider admits exactly the documented D2 vocabulary
// and nothing else. Extending the allowlist is an owner decision recorded
// with the compat matrix — any silent drift of the seam fails here
// first, including near-miss names that must never re-introduce a deferred
// client-facing surface (e.g. gemini, I50).
func TestN07P6T02_CompatSeamVocabularyPinned(t *testing.T) {
	for _, name := range n07p6t02CompatVocabulary {
		if !openAICompatProvider(name) {
			t.Errorf("openAICompatProvider(%q) = false, want true (D2 FINAL vocabulary)", name)
		}
	}
	outside := append([]string{}, n07p6t02NonCompatAdapters...)
	outside = append(outside, "zai-coding",
		"openai compat", "OpenAI", "vertex-ai", "aws-bedrock", "gemini", "gcp-vertex")
	for _, name := range outside {
		if openAICompatProvider(name) {
			t.Errorf("openAICompatProvider(%q) = true, want false (outside D2 FINAL)", name)
		}
	}
}
