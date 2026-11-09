package cli

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func postCompletions(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func TestCompletions_NonStreamSuffixAndEvent(t *testing.T) {
	const upstreamBody = `{"id":"cmpl","choices":[{"text":"world"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/completions" {
			t.Errorf("path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"suffix":"def"`) {
			t.Errorf("suffix missing: %s", raw)
		}
		if !strings.Contains(string(raw), `"prompt":"abc"`) {
			t.Errorf("prompt missing: %s", raw)
		}
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postCompletions(t, gw, `{"model":"m","prompt":"abc","suffix":"def","max_tokens":8}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != upstreamBody {
		t.Fatalf("body %q", rec.Body.String())
	}
	if ev == nil || ev.Endpoint != "completions" || ev.TokensIn != 4 || ev.TokensOut != 1 {
		t.Fatalf("event %+v", ev)
	}
}

func TestCompletions_StreamPassthroughSuppressesUsage(t *testing.T) {
	const content = "data: {\"choices\":[{\"text\":\"hi\"}]}\n\n"
	const usage = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n"
	const done = "data: [DONE]\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"suffix":"()"`) {
			t.Errorf("suffix missing: %s", raw)
		}
		if !strings.Contains(string(raw), `"include_usage":true`) {
			t.Errorf("usage flag missing: %s", raw)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(content + usage + done))
	}))
	defer server.Close()

	gw := &gateway{
		cfg:                  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:                  slog.Default(),
		auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool:                 upstream.NewPool(upstream.Options{}),
		streamUsageProviders: map[string]bool{"openai": true},
		streamIdleTimeout:    0,
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postCompletions(t, gw, `{"model":"m","prompt":"fn","suffix":"()","stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !rec.Flushed {
		t.Fatal("stream was not flushed")
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"text":"hi"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("body %q", body)
	}
	if strings.Contains(body, `"prompt_tokens"`) {
		t.Fatalf("usage chunk reached the client: %s", body)
	}
	if ev == nil || ev.Endpoint != "completions" || ev.TokensIn != 2 || ev.TokensOut != 1 || ev.UsageSource != "provider" {
		t.Fatalf("event %+v", ev)
	}
}

func TestCompletions_StreamOutlivesTimeout(t *testing.T) {
	for _, tc := range nativeStreamSurvivalVariants() {
		t.Run(tc.name, func(t *testing.T) {
			var want strings.Builder
			for i := 0; i < tc.chunks; i++ {
				fmt.Fprintf(&want, "data: {\"id\":\"cmpl\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"chunk-%d\"}}]}\n\n", i)
			}
			want.WriteString("data: [DONE]\n\n")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				flusher := w.(http.Flusher)
				for i := 0; i < tc.chunks; i++ {
					_, _ = fmt.Fprintf(w, "data: {\"id\":\"cmpl\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"chunk-%d\"}}]}\n\n", i)
					flusher.Flush()
					time.Sleep(tc.chunkInterval)
				}
				_, _ = io.WriteString(w, "data: [DONE]\n\n")
			}))
			defer server.Close()

			gw := &gateway{
				cfg:                  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
				log:                  slog.Default(),
				auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
				res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: tc.upstreamTimeout, Enabled: true}},
				pool:                 upstream.NewPool(upstream.Options{}),
				streamUsageProviders: map[string]bool{"openai": true},
				streamIdleTimeout:    0,
			}

			rec := postCompletions(t, gw, `{"model":"m","prompt":"fn","stream":true,"max_tokens":8}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != want.String() {
				t.Fatalf("stream truncated: got %d bytes, want %d; tail %q", len(got), want.Len(), got[max(0, len(got)-200):])
			}
		})
	}
}

func TestCompletions_NonStreamUpstreamTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = io.WriteString(w, `{"id":"cmpl","choices":[{"text":"late"}]}`)
	}))
	defer server.Close()

	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: time.Second, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}

	rec := postCompletions(t, gw, `{"model":"m","prompt":"fn","max_tokens":8}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream request failed") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// --- w17-06: usage seam honesty on the legacy /v1/completions JSON path ---
//
// completionsUsage must consume the shared provider parser so transparent
// prompt-cache fields (prompt_tokens_details.cached_tokens, legacy
// prompt_cache_hit_tokens) reach billing instead of being dropped at this
// seam (N03-P06-T04 follow-up).

func TestCompletionsUsage_CachedTokensFlowThrough(t *testing.T) {
	const body = `{"id":"cmpl","object":"text_completion","choices":[{"text":"hi","index":0,"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,` +
		`"prompt_tokens_details":{"cached_tokens":7}}}`
	for name, adapter := range map[string]provider.Provider{
		"openai":   provider.OpenAI{},
		"vllm":     provider.VLLM{},
		"zai":      provider.ZAICoding{},
		"llamacpp": provider.LlamaCPP{},
		"sakana":   provider.Sakana{},
		"mistral":  provider.Mistral{},
		"ollama":   provider.Ollama{},
		"sarvam":   provider.Sarvam{},
		"azure":    &provider.AzureOpenAI{},
	} {
		t.Run(name, func(t *testing.T) {
			u := completionsUsage([]byte(body), []byte(`{"prompt":"hi"}`), adapter)
			if u.PromptTokens != 10 || u.CompletionTokens != 2 || u.TotalTokens != 12 {
				t.Fatalf("token counts lost at the seam: %+v", u)
			}
			if u.CacheReadTokens != 7 {
				t.Fatalf("prompt_tokens_details.cached_tokens dropped at the seam: %+v", u)
			}
			if u.Source != provider.UsageSourceProvider {
				t.Fatalf("source %q, want provider", u.Source)
			}
		})
	}
}

func TestCompletionsUsage_LegacyDeepSeekCacheHitFallback(t *testing.T) {
	const body = `{"usage":{"prompt_tokens":6,"completion_tokens":1,"total_tokens":7,"prompt_cache_hit_tokens":4}}`
	u := completionsUsage([]byte(body), nil, provider.OpenAI{})
	if u.CacheReadTokens != 4 {
		t.Fatalf("legacy prompt_cache_hit_tokens dropped at the seam: %+v", u)
	}
	if u.Source != provider.UsageSourceProvider {
		t.Fatalf("source %q, want provider", u.Source)
	}
}

func TestCompletionsUsage_UnknownFieldsIgnored(t *testing.T) {
	// Unknown usage fields (today: completion_tokens_details.reasoning_tokens;
	// tomorrow: anything new) must not break the known fields' parse.
	const body = `{"id":"cmpl","service_tier":"default","unknown_future":{"nested":[1,2]},` +
		`"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,` +
		`"completion_tokens_details":{"reasoning_tokens":9},"new_field":42}}`
	u := completionsUsage([]byte(body), nil, provider.OpenAI{})
	if u.PromptTokens != 3 || u.CompletionTokens != 1 || u.TotalTokens != 4 {
		t.Fatalf("known fields mis-parsed with unknown siblings present: %+v", u)
	}
	if u.CacheReadTokens != 0 {
		t.Fatalf("unknown fields must not fabricate cache reads: %+v", u)
	}
	if u.Source != provider.UsageSourceProvider {
		t.Fatalf("source %q, want provider", u.Source)
	}
}

func TestCompletionsUsage_TotalFallbackAndEstimate(t *testing.T) {
	t.Run("provider omits total_tokens", func(t *testing.T) {
		u := completionsUsage([]byte(`{"usage":{"prompt_tokens":5,"completion_tokens":2}}`), nil, provider.OpenAI{})
		if u.TotalTokens != 7 {
			t.Fatalf("total fallback lost: %+v", u)
		}
		if u.Source != provider.UsageSourceProvider {
			t.Fatalf("source %q, want provider", u.Source)
		}
	})
	t.Run("no usage block estimates from request", func(t *testing.T) {
		u := completionsUsage([]byte(`{"choices":[{"text":"hi"}]}`), []byte(`abcd`), provider.OpenAI{})
		// (4 bytes + 3) / 4 = 1 — the pre-existing estimate contract.
		if u.PromptTokens != 1 || u.TotalTokens != 1 {
			t.Fatalf("estimate changed: %+v", u)
		}
		if u.Source != provider.UsageSourceEstimated {
			t.Fatalf("source %q, want estimated", u.Source)
		}
	})
	t.Run("malformed body estimates from request", func(t *testing.T) {
		u := completionsUsage([]byte(`not-json`), []byte(`abcdefgh`), provider.OpenAI{})
		// (8 bytes + 3) / 4 = 2.
		if u.PromptTokens != 2 || u.TotalTokens != 2 {
			t.Fatalf("estimate changed: %+v", u)
		}
		if u.Source != provider.UsageSourceEstimated {
			t.Fatalf("source %q, want estimated", u.Source)
		}
	})
}

// TestCompletions_JSON_CachedTokensHitHeader pins the end-to-end seam: an
// upstream usage block with prompt_tokens_details.cached_tokens must surface
// as a real prompt-cache hit on the JSON response (before the w17-06 fix the
// cached tokens were silently dropped here and the header said "miss").
func TestCompletions_JSON_CachedTokensHitHeader(t *testing.T) {
	const upstreamBody = `{"id":"cmpl","choices":[{"text":"hi"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"cached_tokens":7}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postCompletions(t, gw, `{"model":"m","prompt":"abc"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(PromptCacheHeader); got != "hit" {
		t.Fatalf("prompt-cache header %q, want hit — cached_tokens did not survive the usage seam", got)
	}
	if ev == nil || ev.TokensIn != 10 || ev.TokensOut != 2 || ev.UsageSource != "provider" {
		t.Fatalf("event %+v", ev)
	}
}

// --- N03-P06-T05: negative billing on the legacy completions seam -------------
//
// A client-supplied prompt-cache hint is not usage. Whatever hint shape the
// client sends, the header, the event cache-read tokens and the bill on this
// seam follow one source only: the usage the provider returned for THIS
// request.

func TestCompletions_JSON_ClientHint_BillFollowsProviderCacheOnly(t *testing.T) {
	const hint = `"cache_control":{"type":"ephemeral"}`
	fullInput := (100*2.5 + 5*10.0) / 1e6 // gpt-4o input+output at list rates

	t.Run("provider reports no cache → miss and full rate", func(t *testing.T) {
		var sentUpstream []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			sentUpstream = append([]byte(nil), raw...)
			_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"text":"hi"}],"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}}`))
		}))
		defer server.Close()

		gw := &gateway{
			cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
			log:  slog.Default(),
			auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
			res:  stubModelResolver{"m": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
			pool: upstream.NewPool(upstream.Options{}),
		}
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postCompletions(t, gw, `{"model":"m","prompt":"abc",`+hint+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if got := strings.Count(string(sentUpstream), "cache_control"); got > 1 {
			t.Fatalf("the gateway manufactured cache markers beyond the client's one hint: %d in %s", got, sentUpstream)
		}
		if got := rec.Header().Get(PromptCacheHeader); got != "miss" {
			t.Fatalf("prompt-cache header %q, want miss — a client hint is not a provider-reported hit", got)
		}
		if ev == nil || ev.CacheReadTokens != 0 {
			t.Fatalf("event must carry zero cache reads: %+v", ev)
		}
		want := provider.ComputeCost(provider.Usage{
			PromptTokens: 100, CompletionTokens: 5, TotalTokens: 105, Source: provider.UsageSourceProvider,
		}, "openai", "gpt-4o").EstimatedCostUSD
		if d := ev.EstimatedCostUSD - want; d < -1e-12 || d > 1e-12 {
			t.Fatalf("billed %.3e, want the full list-rate %.3e — the hint must not reduce the bill", ev.EstimatedCostUSD, want)
		}
		if d := ev.EstimatedCostUSD - fullInput; d < -1e-9 || d > 1e-9 {
			t.Fatalf("billed %.3e, want full list rate %.3e", ev.EstimatedCostUSD, fullInput)
		}
	})

	t.Run("provider reports cache → hit and honest discount", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"text":"hi"}],"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":30}}}`))
		}))
		defer server.Close()

		gw := &gateway{
			cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
			log:  slog.Default(),
			auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
			res:  stubModelResolver{"m": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
			pool: upstream.NewPool(upstream.Options{}),
		}
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postCompletions(t, gw, `{"model":"m","prompt":"abc",`+hint+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get(PromptCacheHeader); got != "hit" {
			t.Fatalf("prompt-cache header %q, want hit from the provider usage", got)
		}
		if ev == nil || ev.CacheReadTokens != 30 {
			t.Fatalf("event must carry exactly the provider-reported cache reads: %+v", ev)
		}
		want := provider.ComputeCost(provider.Usage{
			PromptTokens: 100, CompletionTokens: 5, TotalTokens: 105,
			CacheReadTokens: 30, Source: provider.UsageSourceProvider,
		}, "openai", "gpt-4o").EstimatedCostUSD
		if d := ev.EstimatedCostUSD - want; d < -1e-12 || d > 1e-12 {
			t.Fatalf("billed %.3e, want the provider-usage discount %.3e", ev.EstimatedCostUSD, want)
		}
		if ev.EstimatedCostUSD >= fullInput-1e-12 {
			t.Fatalf("a provider-reported cache read must produce a real discount: %.3e >= full %.3e", ev.EstimatedCostUSD, fullInput)
		}
	})
}

func TestCompletions_Stream_ClientHint_TrailerAndBillFollowProviderCacheOnly(t *testing.T) {
	const hint = `"cache_control":{"type":"ephemeral"}`
	fullInput := (100*2.5 + 5*10.0) / 1e6

	for _, tc := range []struct {
		name        string
		usageChunk  string
		wantTrailer string
		wantCached  int64
	}{
		{
			name:        "no provider cache → miss trailer, full rate",
			usageChunk:  `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}`,
			wantTrailer: "miss",
			wantCached:  0,
		},
		{
			name:        "provider cache → hit trailer, honest discount",
			usageChunk:  `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":30}}`,
			wantTrailer: "hit",
			wantCached:  30,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const content = "data: {\"choices\":[{\"text\":\"hi\"}]}\n\n"
			const done = "data: [DONE]\n\n"
			usage := "data: {\"choices\":[],\"usage\":" + tc.usageChunk + "}\n\n"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if got := strings.Count(string(raw), "cache_control"); got > 1 {
					t.Errorf("the gateway manufactured cache markers beyond the client's one hint: %d in %s", got, raw)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(content + usage + done))
			}))
			defer server.Close()

			gw := &gateway{
				cfg:                  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
				log:                  slog.Default(),
				auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
				res:                  stubModelResolver{"m": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
				pool:                 upstream.NewPool(upstream.Options{}),
				streamUsageProviders: map[string]bool{"openai": true},
				streamIdleTimeout:    0,
			}
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }

			rec := postCompletions(t, gw, `{"model":"m","prompt":"abc","stream":true,`+hint+`}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get(promptCacheTrailerKey); got != tc.wantTrailer {
				t.Fatalf("prompt-cache trailer %q, want %q", got, tc.wantTrailer)
			}
			if ev == nil || ev.CacheReadTokens != tc.wantCached {
				t.Fatalf("event must carry exactly the provider-reported cache reads: %+v", ev)
			}
			want := provider.ComputeCost(provider.Usage{
				PromptTokens: 100, CompletionTokens: 5, TotalTokens: 105,
				CacheReadTokens: tc.wantCached, Source: provider.UsageSourceProvider,
			}, "openai", "gpt-4o").EstimatedCostUSD
			if d := ev.EstimatedCostUSD - want; d < -1e-12 || d > 1e-12 {
				t.Fatalf("billed %.3e, want %.3e computed from the provider usage", ev.EstimatedCostUSD, want)
			}
			if tc.wantCached == 0 {
				if ev.EstimatedCostUSD < fullInput-1e-12 || ev.EstimatedCostUSD > fullInput+1e-12 {
					t.Fatalf("billed %.3e, want the full list rate %.3e — the hint must not reduce the bill", ev.EstimatedCostUSD, fullInput)
				}
			} else if ev.EstimatedCostUSD >= fullInput-1e-12 {
				t.Fatalf("a provider-reported cache read must produce a real discount: %.3e >= full %.3e", ev.EstimatedCostUSD, fullInput)
			}
		})
	}
}
