package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// FuzzEmbeddingsHappyPathForwarding exercises only the successful /v1/embeddings
// path: normal generated text is JSON-marshaled as the "input" string, forwarded
// to the local mock upstream, and forwarded content, response body and usage
// accounting are verified deterministically for every input.
func FuzzEmbeddingsHappyPathForwarding(f *testing.F) {
	const upstreamBody = `{"object":"list","data":[],"usage":{"prompt_tokens":3,"total_tokens":3}}`

	// Two distinct valid seeds that must stay distinguishable on the wire,
	// plus a long base64-run body (critical-go: the reservation input
	// profile's base64-strip accounting loop, exercised through the real
	// embeddings request path).
	f.Add("hello")
	f.Add("fuzz seed two")
	f.Add(strings.Repeat("QUJD", 100))

	f.Fuzz(func(t *testing.T, in string) {
		text := "embedding: " + strings.ToValidUTF8(in, "�")
		body, err := json.Marshal(struct {
			Model string `json:"model"`
			Input string `json:"input"`
		}{"m", text})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}

		var wire atomic.Value
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/embeddings" {
				t.Errorf("upstream path %s", r.URL.Path)
			}
			raw, _ := io.ReadAll(r.Body)
			wire.Store(string(raw))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(upstreamBody))
		}))
		defer server.Close()

		info := resolver.ModelInfo{ModelName: "embed-a", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
		gw := &gateway{
			cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
			log:  slog.Default(),
			auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
			res:  stubModelResolver{"m": info},
			pool: upstream.NewPool(upstream.Options{}),
			// KV-cache session affinity: the happy path already records
			// usage through accountUsage, so wiring the tracker exercises
			// the affinity recording arm without changing behavior. The
			// min-token gate is lowered so the probe's cache-read count
			// actually sticks the model (zero values would default to 512).
			sessionAffinity: fallbackrouter.NewSessionAffinity(0, 1, 0),
		}
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postEmbeddings(t, gw, string(body))
		validateEmbeddingsResponse(t, rec, upstreamBody)

		validateEmbeddingsForwardedContent(t, &wire, "embed-a", text)

		if ev == nil || ev.Endpoint != "embeddings" || ev.TokensIn != 3 || ev.TokensOut != 0 || ev.UsageSource != "provider" {
			t.Fatalf("event %+v", ev)
		}

		// Critical-go direct probes (unreachable through the embeddings
		// pipeline itself): the session-affinity recording branch of
		// accountUsage, the beforeAttest hook and attestModel override of
		// finishRequest, and the client-cancel classification of
		// completionTermination.
		ctx := context.Background()
		gw.accountUsage(ctx, httptest.NewRecorder(), usageRecord{
			orgID:         "org-fz",
			sessionID:     "s-fz",
			affinityModel: "embed-a",
			usage:         provider.Usage{PromptTokens: 1, CompletionTokens: 2, CacheReadTokens: 7},
		})
		if got := gw.sessionAffinity.Preferred(ctx, "org-fz", "s-fz"); got != "embed-a" {
			t.Fatalf("session affinity not recorded: preferred %q", got)
		}
		var hooked *eventpub.Event
		finEv := gw.finishRequest(ctx, requestFinish{
			base:        eventBase{EventType: "request.completed", RequestID: "fz-finish", OrgID: "org-fz", ModelUsed: "m"},
			attestModel: "embed-b",
			info:        info,
			noSettle:    true,
		}, func(e *eventpub.Event) { hooked = e })
		if hooked == nil || finEv == nil || hooked != finEv {
			t.Fatalf("finishRequest hook/order broken: hooked %v, returned %v", hooked, finEv)
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if completionTermination(cctx) != budget.TerminationClientCancel {
			t.Fatal("canceled context must classify as client cancel")
		}
		if completionTermination(ctx) != budget.TerminationCompleted {
			t.Fatal("live context must classify as completed")
		}
	})
}

func validateEmbeddingsResponse(t *testing.T, rec *httptest.ResponseRecorder, expectedBody string) {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != expectedBody {
		t.Fatalf("response body %q", rec.Body.String())
	}
}

func validateEmbeddingsForwardedContent(t *testing.T, wire *atomic.Value, model string, input string) {
	t.Helper()

	forwarded, ok := wire.Load().(string)
	if !ok {
		t.Fatalf("wire not string: %T", wire.Load())
	}

	var got struct {
		Model string `json:"model"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal([]byte(forwarded), &got); err != nil {
		t.Fatalf("forwarded body not JSON: %q", forwarded)
	}
	if got.Model != model {
		t.Fatalf("forwarded model %q want %q", got.Model, model)
	}
	if got.Input != input {
		t.Fatalf("forwarded input %q want %q", got.Input, input)
	}
}
