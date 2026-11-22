package cli

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/require"
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
		cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:         slog.Default(),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
		res:         stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: &fakeInvocationStore{},
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
		auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
		res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool:                 upstream.NewPool(upstream.Options{}),
		invocations:          &fakeInvocationStore{},
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
				auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
				res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: tc.upstreamTimeout, Enabled: true}},
				pool:                 upstream.NewPool(upstream.Options{}),
				invocations:          &fakeInvocationStore{},
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
		cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:         slog.Default(),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
		res:         stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: time.Second, Enabled: true}},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: &fakeInvocationStore{},
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
		cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:         slog.Default(),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
		res:         stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: &fakeInvocationStore{},
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
	checkCompletionCacheBilling(t, false)
}

func TestCompletions_Stream_ClientHint_TrailerAndBillFollowProviderCacheOnly(t *testing.T) {
	checkCompletionCacheBilling(t, true)
}

func checkCompletionCacheBilling(t *testing.T, stream bool) {
	t.Helper()
	// The gateway test tariff is $2.50/M input, $1.25/M cached input and $10/M output.
	for _, tc := range []struct {
		header    string
		usage     string
		cacheRead int64
		costUSD   float64
	}{
		{"miss", `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}`, 0, (100*2.5 + 5*10) / 1e6},
		{"hit", `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":30}}`, 30, (70*2.5 + 30*1.25 + 5*10) / 1e6},
	} {
		t.Run(tc.header, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("reading provider request: %v", err)
					return
				}
				if n := strings.Count(string(raw), "cache_control"); n > 1 {
					t.Errorf("provider received %d cache markers for one client hint", n)
				}
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "data: {\"choices\":[{\"text\":\"hi\"}]}\n\ndata: {\"choices\":[],\"usage\":%s}\n\ndata: [DONE]\n\n", tc.usage)
				} else {
					fmt.Fprintf(w, `{"id":"cmpl","choices":[{"text":"hi"}],"usage":%s}`, tc.usage)
				}
			}))
			defer server.Close()
			cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL}
			store := &fakeInvocationStore{}
			gw := &gateway{
				cfg: cfg, log: slog.Default(), auth: NewAuthMiddleware(cfg, newTestResolver("org-test", nil)),
				res:  stubModelResolver{"m": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
				pool: upstream.NewPool(upstream.Options{}), invocations: store,
				streamUsageProviders: map[string]bool{"openai": true},
			}
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }
			rec := postCompletions(t, gw, fmt.Sprintf(`{"model":"m","prompt":"abc","stream":%t,"cache_control":{"type":"ephemeral"}}`, stream))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			header := PromptCacheHeader
			if stream {
				header = promptCacheTrailerKey
			}
			require.Equal(t, tc.header, rec.Header().Get(header))
			require.NotNil(t, ev)
			require.EqualValues(t, 100, ev.TokensIn)
			require.EqualValues(t, 5, ev.TokensOut)
			require.Equal(t, tc.cacheRead, ev.CacheReadTokens)
			require.InDelta(t, tc.costUSD, ev.EstimatedCostUSD, 1e-12)
			require.Len(t, store.admitted, 1)
			require.Len(t, store.facts, 1)
			require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
		})
	}
}

func TestCompletionsBufferedResponseLimit(t *testing.T) {
	const document = `{"id":"bounded","choices":[{"text":"ok"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`
	for _, tc := range []struct {
		name       string
		size       int
		wantStatus int
	}{{"at limit", embeddingsResponseLimit, http.StatusOK}, {"over limit", embeddingsResponseLimit + 1, http.StatusBadGateway}} {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.Repeat(" ", tc.size-len(document)) + document
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, payload)
			}))
			defer server.Close()
			gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
			store := &fakeInvocationStore{}
			gw.invocations = store
			rec := postCompletions(t, gw, `{"model":"m","prompt":"hello"}`)
			require.Equal(t, tc.wantStatus, rec.Code)
			require.EqualValues(t, 1, hits.Load())
			require.Len(t, store.admitted, 1)
			if tc.wantStatus == http.StatusOK {
				require.True(t, rec.Body.String() == payload, "at-limit completion changed")
				require.Len(t, store.facts, 1)
				require.Equal(t, "7", store.facts[0].Fields["tokens_in"])
				require.Equal(t, "3", store.facts[0].Fields["tokens_out"])
				return
			}
			require.Empty(t, store.facts, "truncated input cannot establish completed usage")
			require.Contains(t, rec.Body.String(), "upstream response too large")
			require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
		})
	}
}

func TestCompletionsInterruptedPaidResponse(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, `{"choices":[{"text":"partial-provider-content"}]`)
	}))
	defer server.Close()
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	store := &fakeInvocationStore{}
	gw.invocations = store
	var events int
	gw.eventNote = func(*eventpub.Event) { events++ }

	rec := postCompletions(t, gw, `{"model":"m","prompt":"hello"}`)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to read upstream response")
	require.NotContains(t, rec.Body.String(), "partial-provider-content")
	require.EqualValues(t, 1, hits.Load())
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
	require.Zero(t, events)
	require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
}
