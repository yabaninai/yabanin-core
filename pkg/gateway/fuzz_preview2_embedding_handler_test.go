package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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
// accounting are verified deterministically for every input. The input-
// independent contracts the pipeline cannot reach from this request shape —
// session-affinity recording, the finishRequest hook order, the
// completionTermination classification — are pinned once by the named tests
// below instead of inside every fuzz iteration.
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
		}
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postEmbeddings(t, gw, string(body))
		validateEmbeddingsResponse(t, rec, upstreamBody)

		validateEmbeddingsForwardedContent(t, &wire, "embed-a", text)

		if ev == nil || ev.Endpoint != "embeddings" || ev.TokensIn != 3 || ev.TokensOut != 0 || ev.UsageSource != "provider" {
			t.Fatalf("event %+v", ev)
		}
	})
}

// TestEmbeddingsSessionAffinityRecorded pins the session-affinity recording
// arm of accountUsage. The embeddings pipeline never sets affinityModel on
// its usageRecord (the arm only fires for a non-empty model), so no
// happy-path request can produce a preference — the arm is exercised
// through the shared accountUsage entry point with the min-token gate
// lowered to 1 so the probe's cache-read count sticks the model.
func TestEmbeddingsSessionAffinityRecorded(t *testing.T) {
	gw := &gateway{log: fuzzDiscardLogger(), sessionAffinity: fallbackrouter.NewSessionAffinity(0, 1, 0)}
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
}

// TestEmbeddingsFinishRequestHookOrder pins the finishRequest contracts the
// embeddings finisher relies on: the beforeAttest hook receives the very
// event the call returns, and it runs BEFORE the eventNote hook and the
// publish observer (build → trace stamp → pre-attestation hook → lineage
// attestation → reservation settle → eventNote → publish). attestModel
// ("embed-b") stays distinct from base.ModelUsed ("m") to pin its event-
// level consequence: the winning candidate is attested without rewriting
// the event's model field. The attestation value itself is recorded by the
// DB-backed lineage stores, which a bare gateway cannot wire (attachLineage
// early-returns unwired; the wired behavior is integration-pinned), so this
// unit probe covers exactly the observable order and pointer contracts.
func TestEmbeddingsFinishRequestHookOrder(t *testing.T) {
	gw := &gateway{log: fuzzDiscardLogger()}
	var (
		order  []string
		hooked *eventpub.Event
	)
	restore := observeEvent(func(*eventpub.Event) { order = append(order, "publish") })
	defer restore()
	gw.eventNote = func(*eventpub.Event) { order = append(order, "event_note") }

	finEv := gw.finishRequest(context.Background(), requestFinish{
		base:        eventBase{EventType: "request.completed", RequestID: "fz-finish", OrgID: "org-fz", ModelUsed: "m"},
		attestModel: "embed-b",
		info:        resolver.ModelInfo{ModelName: "embed-b", Provider: "openai", Enabled: true},
		noSettle:    true,
		eventNote:   true,
	}, func(e *eventpub.Event) {
		order = append(order, "before_attest")
		hooked = e
	})

	if hooked == nil || finEv == nil || hooked != finEv {
		t.Fatalf("beforeAttest hook must receive the returned event: hooked %v, returned %v", hooked, finEv)
	}
	if finEv.ModelUsed != "m" {
		t.Fatalf("attestModel override must not rewrite the event model: %q", finEv.ModelUsed)
	}
	if want := []string{"before_attest", "event_note", "publish"}; !slices.Equal(order, want) {
		t.Fatalf("finishRequest hook order = %v, want %v", order, want)
	}
}

// TestCompletionTerminationClassification pins the §5.3 Finalize
// classification: a dead request context is a client cancel, a live one a
// completed request.
func TestCompletionTerminationClassification(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		want budget.Termination
	}{
		{"canceled context is client cancel", canceled, budget.TerminationClientCancel},
		{"live context is completed", context.Background(), budget.TerminationCompleted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := completionTermination(tt.ctx); got != tt.want {
				t.Fatalf("completionTermination = %v, want %v", got, tt.want)
			}
		})
	}
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
