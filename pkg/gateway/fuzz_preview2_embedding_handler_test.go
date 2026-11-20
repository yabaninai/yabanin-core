package cli

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

// FuzzEmbeddingsHappyPathForwarding exercises only the successful /v1/embeddings
// path: normal generated text is JSON-marshaled as the "input" string, forwarded
// to the local mock upstream, and forwarded content, response body and usage
// accounting are verified deterministically for every input.
func FuzzEmbeddingsHappyPathForwarding(f *testing.F) {
	const upstreamBody = `{"object":"list","data":[],"usage":{"prompt_tokens":3,"total_tokens":3}}`

	// Two distinct valid seeds that must stay distinguishable on the wire.
	f.Add("hello")
	f.Add("fuzz seed two")

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
