package cli

// N03-P06-T06 — joint user scenario for provider prompt cache and usage/
// billing: a user sends real traffic (caching and non-caching providers,
// hits and misses, hints present and absent) and the console savings plus
// the billing ledger must follow the provider-reported usage and nothing
// else. The four card clauses pinned here:
//
//  1. provider-reported cache hit/miss → displayed savings and billed cost
//     use exactly those numbers (no double counting, no invented savings),
//     on the anthropic-style and the OpenAI-style provider contract, in
//     JSON and SSE shapes;
//  2. a cache hint the provider does not (yet) honor → the request still
//     succeeds with the full body, no error, and NO discount is applied or
//     displayed;
//  3. mixed traffic → per-request and aggregate savings reconcile to
//     Σ(provider-reported cached tokens × rate deltas), and billed Σ
//     matches the per-request provider-usage formulas exactly;
//  4. a provider-reported hit on a request that asked for NO caching still
//     shows the real savings — the provider is the only source of truth.
//
// The fakes are contract-accurate: an anthropic-style upstream reports
// input_tokens EXCLUDING cache tokens plus cache_read_input_tokens /
// cache_creation_input_tokens; an OpenAI-style upstream reports
// prompt_tokens INCLUDING cached_tokens via prompt_tokens_details. Billing
// expectations are hand-computed from pkg/pricing list rates
// (anthropic:claude-sonnet-4-5 = 3/15/3.75/0.3, openai:gpt-4o =
// 2.5/10/0/1.25 $/1M), never read back from ComputeCost on the same shape
// the code path uses (that would be tautological) — the hand formulas below
// are the independent oracle.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// --- contract-accurate upstream fixtures -------------------------------------

const n03p6t06AnthropicHitJSON = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
	`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
	`"usage":{"input_tokens":1000,"output_tokens":200,"cache_read_input_tokens":600,"cache_creation_input_tokens":150}}`

const n03p6t06AnthropicMissJSON = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
	`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
	`"usage":{"input_tokens":1000,"output_tokens":200}}`

const n03p6t06AnthropicHitSSE = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":400}}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
	"event: message_delta\n" +
	"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":80,\"cache_read_input_tokens\":200,\"cache_creation_input_tokens\":50}}\n\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

const n03p6t06OpenAIHitJSON = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":800,"completion_tokens":120,"total_tokens":920,` +
	`"prompt_tokens_details":{"cached_tokens":300}}}`

const n03p6t06OpenAIMissJSON = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":800,"completion_tokens":120,"total_tokens":920}}`

const n03p6t06OpenAIHitSSE = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"1\",\"choices\":[],\"usage\":{\"prompt_tokens\":800,\"completion_tokens\":120,\"total_tokens\":920,\"prompt_tokens_details\":{\"cached_tokens\":300}}}\n\n" +
	"data: [DONE]\n\n"

const n03p6t06OpenAIMissSSE = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"1\",\"choices\":[],\"usage\":{\"prompt_tokens\":500,\"completion_tokens\":60,\"total_tokens\":560}}\n\n" +
	"data: [DONE]\n\n"

// Client bodies: hinted variants carry anthropic-style ephemeral markers,
// plain variants carry no cache hint at all.
const n03p6t06AnthropicHintBody = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
	`"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],` +
	`"messages":[{"role":"user","content":[{"type":"text","text":"summarize","cache_control":{"type":"ephemeral"}}]}]}`

const n03p6t06AnthropicPlainBody = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
	`"messages":[{"role":"user","content":"summarize"}]}`

const n03p6t06OpenAIHintBody = `{"model":"gpt-4o",` +
	`"messages":[{"role":"user","content":[{"type":"text","text":"summarize","cache_control":{"type":"ephemeral"}}]}]}`

const n03p6t06OpenAIPlainBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"summarize"}]}`

const n03p6t06OpenAIStreamPlainBody = `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"summarize"}]}`

const n03p6t06AnthropicStreamPlainBody = `{"model":"claude-sonnet-4-5","max_tokens":64,"stream":true,` +
	`"messages":[{"role":"user","content":"summarize"}]}`

// --- independent billing oracle (hand-computed list-rate formulas) -----------

// n03p6t06AnthropicBilled prices an anthropic-style request by hand:
// nonCacheInput×3 + out×15 + create×3.75 + read×0.3, all $/1M → USD.
// nonCacheInput is the upstream input_tokens (anthropic excludes cache).
func n03p6t06AnthropicBilled(nonCacheInput, out, create, read float64) float64 {
	return (nonCacheInput*3 + out*15 + create*3.75 + read*0.3) / 1e6
}

// n03p6t06AnthropicFullList prices the same usage as if every input-side
// token (including cache reads and creations) were charged at the plain
// input rate — the counterfactual "no cache" bill the savings compare to.
func n03p6t06AnthropicFullList(nonCacheInput, out, create, read float64) float64 {
	return ((nonCacheInput+create+read)*3 + out*15) / 1e6
}

// n03p6t06AnthropicDiscount is the expected savings: Σ(cached tokens ×
// rate delta) — reads save (input − read-rate), creations cost
// (input − write-rate), which is NEGATIVE for anthropic (the write
// premium) and must show up honestly, not be hidden.
func n03p6t06AnthropicDiscount(create, read float64) float64 {
	return (read*(3-0.3) + create*(3-3.75)) / 1e6
}

// n03p6t06OpenAIBilled prices an OpenAI-style request by hand:
// (prompt−cached)×2.5 + out×10 + cached×1.25, all $/1M → USD.
func n03p6t06OpenAIBilled(prompt, out, cached float64) float64 {
	return ((prompt-cached)*2.5 + out*10 + cached*1.25) / 1e6
}

func n03p6t06OpenAIFullList(prompt, out float64) float64 {
	return (prompt*2.5 + out*10) / 1e6
}

func n03p6t06OpenAIDiscount(cached float64) float64 {
	return cached * (2.5 - 1.25) / 1e6
}

// --- harness ------------------------------------------------------------------

// n03p6t06PricedDefault builds the deterministic default pricer the billing
// oracles in this packet assume: a small file snapshot pinning the exact
// rates the hand formulas encode (the historical bundled rates for
// claude-sonnet-4-5, gpt-4o and gpt-4o-mini). Since CORE-REF-04 the shipped
// default serves the reference catalog projection (the three verified
// nebius arms) — the billing oracles must not depend on which snapshot
// ships, so the fixture carries its rates explicitly instead.
func n03p6t06PricedDefault(t *testing.T) *pricing.FilePricer {
	t.Helper()
	p, err := pricing.NewFilePricer(pricing.PriceFile{
		Source: "n03p6t06 fixture (pinned rates)", Date: "2026-11-02",
		Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{
			{Provider: "anthropic", Model: "claude-sonnet-4-5", Input: 3, Output: 15, CacheW: 3.75, CacheR: 0.3},
			{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10, CacheR: 1.25},
			{Provider: "openai", Model: "gpt-4o-mini", Input: 0.15, Output: 0.6, CacheR: 0.075},
		},
	}, "sha256:n03p6t06-fixture")
	if err != nil {
		t.Fatalf("n03p6t06 fixture pricer: %v", err)
	}
	return p
}

// n03p6t06ResetDefaultPricer pins the process-global default pricer to the
// deterministic fixture snapshot for the duration of the test. Other tests
// in this binary (buildGateway integration boots over wireTestDeps'
// dead-pool pgxpool) replace the global with a DBPricer and never restore
// it; after that, DefaultLookup silently degrades to the hardcoded fallback
// table and fixture-only models (anthropic:claude-sonnet-4-5) price as
// unknown_price — order-dependent. Installing the fixture default restores
// exact oracle rates; cross-facet defect documented in T06 record §2
// (pinned, owned by the model-pack/buildGateway wiring).
func n03p6t06ResetDefaultPricer(t *testing.T) {
	t.Helper()
	pricing.SetDefaultPricer(n03p6t06PricedDefault(t))
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })
}

// n03p6t06AnthropicGateway wires the native /v1/messages pipeline to a
// resolved claude-sonnet-4-5 (present in pkg/pricing) on an anthropic-style
// upstream — unlike nativeMessagesGateway's unpriced "claude-upstream" name,
// so billing exercises the real price table.
func n03p6t06AnthropicGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	n03p6t06ResetDefaultPricer(t)
	gw := responsesTestGateway(t, upstreamURL)
	gw.res = stubModelResolver{
		"claude-sonnet-4-5": {
			ModelName:      "claude-sonnet-4-5",
			Provider:       "anthropic",
			UpstreamURL:    upstreamURL,
			UpstreamAPIKey: "upstream-key",
			Enabled:        true,
		},
	}
	return gw
}

// n03p6t06ChatGateway wires the OpenAI-compat /v1/chat/completions pipeline
// with provider stream-usage parsing enabled (production default for openai)
// so SSE usage chunks bill exactly like JSON usage blocks.
func n03p6t06ChatGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	n03p6t06ResetDefaultPricer(t)
	gw := goldenChatGateway(t, upstreamURL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai"})
	gw.auth = NewAuthMiddleware(gw.cfg, nil)
	return gw
}

func n03p6t06PostChat(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// n03p6t06Upstream serves scripted JSON/SSE bodies in sequence — a
// contract-accurate provider whose cache state (and even caching support)
// varies per request, like real mixed traffic does.
type n03p6t06Upstream struct {
	bodies []string
	calls  atomic.Int32
	sent   atomic.Value // last raw request body received
}

func newN03P6T06Upstream(bodies ...string) *n03p6t06Upstream {
	return &n03p6t06Upstream{bodies: bodies}
}

func (u *n03p6t06Upstream) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.sent.Store(string(raw))
		i := int(u.calls.Add(1)) - 1
		if !assert.Lessf(t, i, len(u.bodies), "unexpected upstream call %d", i+1) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if strings.Contains(u.bodies[i], "event: message") || strings.Contains(u.bodies[i], "data: {") {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write([]byte(u.bodies[i]))
	}
}

// n03p6t06AssertBilled pins the billing oracle on one captured event: the
// billed cost equals the hand formula for the provider-reported usage, the
// full-list counterfactual minus the bill equals the cached-tokens×rate-delta
// savings, and a real discount is present iff the provider reported a read.
func n03p6t06AssertBilled(t *testing.T, name string, ev *eventpub.Event, billed, fullList, discount float64) {
	t.Helper()
	assert.InDelta(t, billed, ev.EstimatedCostUSD, 1e-15,
		"%s: billed cost must equal the hand-computed provider-usage formula", name)
	assert.InDelta(t, discount, fullList-billed, 1e-12,
		"%s: savings must reconcile to Σ(provider-reported cached tokens × rate deltas)", name)
	if discount > 0 {
		assert.Less(t, ev.EstimatedCostUSD, fullList,
			"%s: a provider-reported cache read must show as a real discount", name)
	}
}

// --- clause 1: provider-reported usage bills exactly (both contracts) --------

func TestN03P6T06_ProviderReportedCache_BillsExactly(t *testing.T) {
	t.Run("anthropic-json", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06AnthropicHitJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06AnthropicGateway(t, up.URL)
		cap := captureAll(t)

		rec := postMessages(t, gw, n03p6t06AnthropicHintBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), `"cache_read_input_tokens":600`,
			"the client sees the provider's honest usage in the passthrough envelope")
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		// Anthropic reports input EXCLUDING cache; the canonical event
		// prompt count includes both cache classes.
		assert.Equal(t, int64(1750), ev.TokensIn)
		assert.Equal(t, int64(200), ev.TokensOut)
		assert.Equal(t, int64(600), ev.CacheReadTokens)
		assert.Equal(t, int64(150), ev.CacheCreationTokens)
		assert.Equal(t, "provider", ev.UsageSource)
		assert.Equal(t, "priced", ev.CostStatus)
		assert.Equal(t, "messages", ev.Endpoint)

		billed := n03p6t06AnthropicBilled(1000, 200, 150, 600) // 0.0067425
		full := n03p6t06AnthropicFullList(1000, 200, 150, 600) // 0.00825
		disc := n03p6t06AnthropicDiscount(150, 600)            // 0.0015075
		n03p6t06AssertBilled(t, "anthropic-json", ev, billed, full, disc)
	})

	t.Run("anthropic-sse", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			printSSEFixture(t, w, n03p6t06AnthropicHitSSE)
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06AnthropicGateway(t, up.URL)
		cap := captureAll(t)

		rec := postMessages(t, gw, n03p6t06AnthropicStreamPlainBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey),
			"streaming native messages must report the provider outcome as a trailer")

		ev := cap.last(t)
		assert.Equal(t, int64(650), ev.TokensIn) // 400 + 200 + 50
		assert.Equal(t, int64(80), ev.TokensOut)
		assert.Equal(t, int64(200), ev.CacheReadTokens)
		assert.Equal(t, int64(50), ev.CacheCreationTokens)
		assert.Equal(t, "provider", ev.UsageSource)

		billed := n03p6t06AnthropicBilled(400, 80, 50, 200)
		full := n03p6t06AnthropicFullList(400, 80, 50, 200)
		disc := n03p6t06AnthropicDiscount(50, 200)
		n03p6t06AssertBilled(t, "anthropic-sse", ev, billed, full, disc)
	})

	t.Run("openai-json", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06OpenAIHitJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIHintBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), `"cached_tokens":300`)
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		// OpenAI reports prompt INCLUDING cached; no creation class exists.
		assert.Equal(t, int64(800), ev.TokensIn)
		assert.Equal(t, int64(120), ev.TokensOut)
		assert.Equal(t, int64(300), ev.CacheReadTokens)
		assert.Equal(t, int64(0), ev.CacheCreationTokens,
			"no cache-creation tokens may be invented on the OpenAI contract")
		assert.Equal(t, "provider", ev.UsageSource)
		assert.Equal(t, "priced", ev.CostStatus)

		billed := n03p6t06OpenAIBilled(800, 120, 300) // 0.002825
		full := n03p6t06OpenAIFullList(800, 120)      // 0.0032
		disc := n03p6t06OpenAIDiscount(300)           // 0.000375
		n03p6t06AssertBilled(t, "openai-json", ev, billed, full, disc)
	})

	t.Run("openai-sse", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			printSSEFixture(t, w, n03p6t06OpenAIHitSSE)
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIStreamPlainBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey))

		ev := cap.last(t)
		assert.Equal(t, int64(800), ev.TokensIn)
		assert.Equal(t, int64(120), ev.TokensOut)
		assert.Equal(t, int64(300), ev.CacheReadTokens)
		assert.Equal(t, int64(0), ev.CacheCreationTokens)
		assert.Equal(t, "provider", ev.UsageSource)

		billed := n03p6t06OpenAIBilled(800, 120, 300)
		full := n03p6t06OpenAIFullList(800, 120)
		disc := n03p6t06OpenAIDiscount(300)
		n03p6t06AssertBilled(t, "openai-sse", ev, billed, full, disc)
	})
}

// --- clause 2: unsupported hint → success, full body, no discount -------------

func TestN03P6T06_UnsupportedHint_NoDiscountNoBreak(t *testing.T) {
	t.Run("hint-to-provider-without-cache-support", func(t *testing.T) {
		// An OpenAI-style upstream that never reports cached tokens (no
		// explicit caching support on this deployment). The client asked for
		// caching in an anthropic-shaped hint; the request must still
		// succeed with the full body and the FULL list-rate bill.
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06OpenAIMissJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIHintBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), `"content":"ok"`,
			"the full response body must reach the client")
		assert.NotContains(t, rec.Body.String(), `"error"`)
		assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
			"no hit may be displayed when the provider reported no cached tokens")

		ev := cap.last(t)
		assert.Equal(t, int64(0), ev.CacheReadTokens)
		assert.Equal(t, int64(0), ev.CacheCreationTokens)
		n03p6t06AssertBilled(t, "unsupported-hint", ev,
			n03p6t06OpenAIBilled(800, 120, 0), n03p6t06OpenAIFullList(800, 120), 0)
	})

	t.Run("hint-honored-but-cache-cold", func(t *testing.T) {
		// The anthropic-style provider accepted the hint (it is forwarded
		// on the native path) but nothing was cached yet: usage carries no
		// cache fields. Miss, full list, success — a hint is never a discount.
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06AnthropicMissJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06AnthropicGateway(t, up.URL)
		cap := captureAll(t)

		rec := postMessages(t, gw, n03p6t06AnthropicHintBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		assert.Equal(t, int64(1000), ev.TokensIn)
		assert.Equal(t, int64(0), ev.CacheReadTokens)
		assert.Equal(t, int64(0), ev.CacheCreationTokens)
		n03p6t06AssertBilled(t, "cold-cache", ev,
			n03p6t06AnthropicBilled(1000, 200, 0, 0), n03p6t06AnthropicFullList(1000, 200, 0, 0), 0)
	})
}

// --- clause 4: provider-reported hit without any client hint -------------------

func TestN03P6T06_ProviderHitWithoutClientHint_SavingsFollowProvider(t *testing.T) {
	t.Run("anthropic-auto-cache", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			assert.NotContains(t, string(raw), "cache_control",
				"the client sent no hint — none may appear upstream")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06AnthropicHitJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06AnthropicGateway(t, up.URL)
		cap := captureAll(t)

		rec := postMessages(t, gw, n03p6t06AnthropicPlainBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
			"the provider reported a hit — savings must follow the provider, not the hint")

		ev := cap.last(t)
		assert.Equal(t, int64(600), ev.CacheReadTokens)
		assert.Equal(t, int64(150), ev.CacheCreationTokens)
		n03p6t06AssertBilled(t, "anthropic-no-hint-hit", ev,
			n03p6t06AnthropicBilled(1000, 200, 150, 600),
			n03p6t06AnthropicFullList(1000, 200, 150, 600),
			n03p6t06AnthropicDiscount(150, 600))
	})

	t.Run("openai-implicit-cache", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			assert.NotContains(t, string(raw), "cache_control")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(n03p6t06OpenAIHitJSON))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		assert.Equal(t, int64(300), ev.CacheReadTokens)
		n03p6t06AssertBilled(t, "openai-no-hint-hit", ev,
			n03p6t06OpenAIBilled(800, 120, 300), n03p6t06OpenAIFullList(800, 120),
			n03p6t06OpenAIDiscount(300))
	})
}

// --- clause 3: mixed traffic reconciles per request and in aggregate ----------

func TestN03P6T06_MixedTraffic_ReconcilesPerRequestAndAggregate(t *testing.T) {
	// One user, one session, six requests: both provider contracts, hits and
	// misses, hints present and absent, JSON and SSE — the traffic shape a
	// real day produces. Requests 2/4/6 go to upstreams that never report
	// cached tokens (providers without caching support).
	anthro := newN03P6T06Upstream(
		n03p6t06AnthropicHitJSON,  // 1: hinted hit
		n03p6t06AnthropicMissJSON, // 2: hinted miss (cold)
		n03p6t06AnthropicHitSSE,   // 5: un-hinted auto-cache hit (SSE)
	)
	anthroSrv := httptest.NewServer(anthro.handler(t))
	t.Cleanup(anthroSrv.Close)

	openai := newN03P6T06Upstream(
		n03p6t06OpenAIHitJSON,  // 3: hinted hit
		n03p6t06OpenAIMissJSON, // 4: hinted miss (no cache support)
		n03p6t06OpenAIMissSSE,  // 6: un-hinted miss (SSE)
	)
	openaiSrv := httptest.NewServer(openai.handler(t))
	t.Cleanup(openaiSrv.Close)

	gwAnthro := n03p6t06AnthropicGateway(t, anthroSrv.URL)
	gwChat := n03p6t06ChatGateway(t, openaiSrv.URL)
	cap := captureAll(t)

	type want struct {
		name        string
		endpoint    string
		tokensIn    int64
		tokensOut   int64
		cacheRead   int64
		cacheCreate int64
		billed      float64
		fullList    float64
		discount    float64
	}
	wants := []want{
		{
			name: "anthropic-json-hit", endpoint: "messages",
			tokensIn: 1750, tokensOut: 200, cacheRead: 600, cacheCreate: 150,
			billed:   n03p6t06AnthropicBilled(1000, 200, 150, 600),
			fullList: n03p6t06AnthropicFullList(1000, 200, 150, 600),
			discount: n03p6t06AnthropicDiscount(150, 600),
		},
		{
			name: "anthropic-json-miss", endpoint: "messages",
			tokensIn: 1000, tokensOut: 200, cacheRead: 0, cacheCreate: 0,
			billed:   n03p6t06AnthropicBilled(1000, 200, 0, 0),
			fullList: n03p6t06AnthropicFullList(1000, 200, 0, 0), discount: 0,
		},
		{
			name: "openai-json-hit", endpoint: "chat.completions",
			tokensIn: 800, tokensOut: 120, cacheRead: 300, cacheCreate: 0,
			billed:   n03p6t06OpenAIBilled(800, 120, 300),
			fullList: n03p6t06OpenAIFullList(800, 120), discount: n03p6t06OpenAIDiscount(300),
		},
		{
			name: "openai-json-miss", endpoint: "chat.completions",
			tokensIn: 800, tokensOut: 120, cacheRead: 0, cacheCreate: 0,
			billed:   n03p6t06OpenAIBilled(800, 120, 0),
			fullList: n03p6t06OpenAIFullList(800, 120), discount: 0,
		},
		{
			name: "anthropic-sse-hit", endpoint: "messages",
			tokensIn: 650, tokensOut: 80, cacheRead: 200, cacheCreate: 50,
			billed:   n03p6t06AnthropicBilled(400, 80, 50, 200),
			fullList: n03p6t06AnthropicFullList(400, 80, 50, 200),
			discount: n03p6t06AnthropicDiscount(50, 200),
		},
		{
			name: "openai-sse-miss", endpoint: "chat.completions",
			tokensIn: 500, tokensOut: 60, cacheRead: 0, cacheCreate: 0,
			billed:   n03p6t06OpenAIBilled(500, 60, 0),
			fullList: n03p6t06OpenAIFullList(500, 60), discount: 0,
		},
	}

	// Requests run strictly sequentially so captured events map 1:1.
	recs := []*httptest.ResponseRecorder{
		postMessages(t, gwAnthro, n03p6t06AnthropicHintBody),
		postMessages(t, gwAnthro, n03p6t06AnthropicHintBody),
		n03p6t06PostChat(t, gwChat, n03p6t06OpenAIHintBody),
		n03p6t06PostChat(t, gwChat, n03p6t06OpenAIHintBody),
		postMessages(t, gwAnthro, n03p6t06AnthropicStreamPlainBody),
		n03p6t06PostChat(t, gwChat, n03p6t06OpenAIStreamPlainBody),
	}
	for i, rec := range recs {
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", wants[i].name, rec.Body.String())
	}

	events := cap.all()
	completed := make([]*eventpub.Event, 0, len(events))
	for _, ev := range events {
		if ev.EventType == "request.completed" {
			completed = append(completed, ev)
		}
	}
	require.Len(t, completed, len(wants), "each request must produce exactly one completed event")

	var (
		sumBilled, sumFull, sumDiscount float64
		sumRead, sumCreate              int64
	)
	for i, w := range wants {
		ev := completed[i]
		assert.Equal(t, w.endpoint, ev.Endpoint, "%s: endpoint", w.name)

		// The displayed outcome agrees with the provider-reported usage:
		// hit iff the provider reported cached reads.
		header := recs[i].Header().Get(PromptCacheHeader)
		trailer := recs[i].Header().Get(promptCacheTrailerKey)
		outcome := header
		if outcome == "" {
			outcome = trailer
		}
		wantOutcome := "miss"
		if w.cacheRead > 0 {
			wantOutcome = "hit"
		}
		assert.Equal(t, wantOutcome, outcome,
			"%s: displayed outcome must be derived from the provider-reported usage only", w.name)

		// The event carries exactly the provider-reported numbers.
		assert.Equal(t, w.tokensIn, ev.TokensIn, "%s: tokens_in", w.name)
		assert.Equal(t, w.tokensOut, ev.TokensOut, "%s: tokens_out", w.name)
		assert.Equal(t, w.cacheRead, ev.CacheReadTokens, "%s: cache_read", w.name)
		assert.Equal(t, w.cacheCreate, ev.CacheCreationTokens, "%s: cache_creation", w.name)
		assert.Equal(t, "provider", ev.UsageSource, "%s: usage_source", w.name)

		n03p6t06AssertBilled(t, w.name, ev, w.billed, w.fullList, w.discount)

		sumBilled += w.billed
		sumFull += w.fullList
		sumDiscount += w.discount
		sumRead += w.cacheRead
		sumCreate += w.cacheCreate
	}

	// Aggregate reconciliation: the totals a console would show are the Σ of
	// the per-request provider-usage figures — never more, never less.
	// (µ$: billed 6742.5+6000+2825+3200+2647.5+1850 = 23265; full-list
	// 8250+6000+3200+3200+3150+1850 = 25650; savings 2385.)
	assert.InDelta(t, sumDiscount, sumFull-sumBilled, 1e-12,
		"aggregate savings must reconcile to Σ(provider-reported cached tokens × rate deltas)")
	assert.Equal(t, int64(1100), sumRead, "aggregate cache reads = Σ provider-reported reads")
	assert.Equal(t, int64(200), sumCreate, "aggregate cache creations = Σ provider-reported creations")
	assert.InDelta(t, 0.023265, sumBilled, 1e-12,
		"aggregate billed spend pinned against the hand-computed ledger total")
	assert.InDelta(t, 0.02565, sumFull, 1e-12,
		"aggregate no-cache counterfactual pinned against the hand-computed total")
}
