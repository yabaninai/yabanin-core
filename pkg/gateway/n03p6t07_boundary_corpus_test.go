package cli

// N03-P06-T07 — regression corpus, boundary values ("provider prompt cache
// and usage: regressions at the boundaries"). T06 pinned the happy paths
// end-to-end (both contracts, hits and misses, JSON and SSE); this corpus
// pins the EDGES of the same guarantees:
//
//   Aspect A — savings/billing follow real usage at the boundaries:
//     fully-cached prompt, write-premium-only traffic (honest negative
//     savings), malformed cached>prompt, hostile negative/overflow token
//     fields, zero-usage blocks, and partial usage billed on a broken SSE
//     stream.
//   Aspect B — provider contract differences at the boundaries: the legacy
//     DeepSeek prompt_cache_hit_tokens fallback billing at the wire level
//     (and no double-count when both fields are present), and unpriced
//     models where a real provider hit must stay honest without a fake
//     discount number.
//   Aspect C — unsupported-hint negative boundaries: hinted SSE traffic to
//     a non-caching provider, client hints dropped by translation while the
//     provider's own implicit cache still hits, and malformed hint shapes
//     crossing the native passthrough without breaking the request.
//
// One documented DEFECT is pinned here as prior behavior (negative
// provider-reported token fields bill negatively / inflate the bill —
// "D1"); the fix locus is pkg/provider (parsers + ComputeCost per-class
// clamp), which is outside this card's write scope (see
// artifacts/internal-delivery-program/N03-P06/T07-record-20261026.md §defect and the
// handoff). The pins exist so the defect cannot change silently and so the
// owner's fix flips these tests deliberately.

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/provider"
)

// --- aspect A: savings/billing boundaries ------------------------------------

// TestN03P6T07_FullyCached_BillsExactlyAndShows: 100% of the prompt served
// from cache (cached_tokens == prompt_tokens) — the non-cache input term is
// zero by honest arithmetic (not clamped), the bill is output + reads only,
// and the header reports the hit.
func TestN03P6T07_FullyCached_BillsExactlyAndShows(t *testing.T) {
	const body = `{"model":"gpt-4o","messages":[{"role":"user","content":"fully cached"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
			`"prompt_tokens_details":{"cached_tokens":800}}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06ChatGateway(t, up.URL)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

	ev := cap.last(t)
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(800), ev.CacheReadTokens)
	assert.Equal(t, int64(0), ev.CacheCreationTokens)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, "priced", ev.CostStatus)

	billed := n03p6t06OpenAIBilled(800, 10, 800) // (0*2.5 + 10*10 + 800*1.25)/1e6 = 0.0011
	full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
	disc := n03p6t06OpenAIDiscount(800)          // 800*(2.5-1.25)/1e6 = 0.001
	n03p6t06AssertBilled(t, "fully-cached", ev, billed, full, disc)
}

// TestN03P6T07_CreationOnly_WritePremiumBillsHonestly: anthropic
// write-only traffic (creations, zero reads). The write premium (1.25×
// input) must land in the bill — billed EXCEEDS the full-list counterfactual,
// i.e. the honest savings are NEGATIVE — and the header must promise no
// read discount ("miss"), because nothing was read.
func TestN03P6T07_CreationOnly_WritePremiumBillsHonestly(t *testing.T) {
	const body = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
		`"messages":[{"role":"user","content":"write premium"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
			`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":1000,"output_tokens":50,"cache_creation_input_tokens":2000}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06AnthropicGateway(t, up.URL)
	cap := captureAll(t)

	rec := postMessages(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
		"creation-only traffic reads nothing — no read discount may be promised")

	ev := cap.last(t)
	assert.Equal(t, int64(3000), ev.TokensIn) // 1000 + 0 read + 2000 create
	assert.Equal(t, int64(0), ev.CacheReadTokens)
	assert.Equal(t, int64(2000), ev.CacheCreationTokens)
	assert.Equal(t, "provider", ev.UsageSource)

	billed := n03p6t06AnthropicBilled(1000, 50, 2000, 0) // 0.01125
	full := n03p6t06AnthropicFullList(1000, 50, 2000, 0) // 0.00975
	disc := n03p6t06AnthropicDiscount(2000, 0)           // -0.0015 — honest NEGATIVE savings
	assert.Negative(t, disc, "the anthropic write premium must make the boundary savings negative")
	n03p6t06AssertBilled(t, "creation-only", ev, billed, full, disc)
	assert.Greater(t, ev.EstimatedCostUSD, full,
		"the bill must honestly include the write premium (exceed the no-cache counterfactual)")
	// Prior behavior: the native /v1/messages finisher publishes no
	// counterfactual baseline (0) — only the chat finishers populate it
	// (observation recorded in T07 record; the honest-negative relationship
	// lives in the cost + cache-token columns this test pins).
	assert.InDelta(t, 0.0, ev.CounterfactualCostUSD, 1e-15)
}

// TestN03P6T07_MalformedCachedOverPrompt_ClampNeverNegativeBill: a
// misreporting provider claims MORE cached tokens than the prompt itself.
// ComputeCost clamps the non-cache input term to zero (documented defensive
// behavior) — the bill must never go negative, and the malformed read count
// is mirrored verbatim onto the event (cache_read_tokens > tokens_in) so
// analytics can see the anomaly.
func TestN03P6T07_MalformedCachedOverPrompt_ClampNeverNegativeBill(t *testing.T) {
	const body = `{"model":"gpt-4o","messages":[{"role":"user","content":"malformed"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
			`"prompt_tokens_details":{"cached_tokens":1000}}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06ChatGateway(t, up.URL)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

	ev := cap.last(t)
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(1000), ev.CacheReadTokens,
		"the malformed read count must be mirrored verbatim (read > prompt visible to analytics)")

	// Clamped bill: the gateway's ComputeCost floors the input term at 0,
	// so billed = out*10 + 1000*1.25 = 0.00135 — never negative. (The raw
	// unclamped formula would bill 0.00085; the pin distinguishes the two.)
	wantBilled := (10*10.0 + 1000*1.25) / 1e6
	assert.InDelta(t, wantBilled, ev.EstimatedCostUSD, 1e-15)
	assert.InDelta(t, 0.00085, n03p6t06OpenAIBilled(800, 10, 1000), 1e-15,
		"sanity: the raw T06 helper formula is unclamped — the pin distinguishes")
	assert.Positive(t, ev.EstimatedCostUSD, "clamped malformed usage must never produce a negative bill")
	// Chat JSON finisher, non-tier traffic: the counterfactual baseline
	// equals the actual bill (savings never leak into the column).
	assert.InDelta(t, wantBilled, ev.CounterfactualCostUSD, 1e-15)
}

// TestN03P6T07_NegativeProviderFields_DefectPin_D1 — DOCUMENTED DEFECT
// (prior behavior, NOT fixed in this card): hostile/buggy upstreams
// reporting NEGATIVE cache fields are parsed and billed verbatim:
//   - anthropic: negative cache_creation_input_tokens → NEGATIVE billed cost
//     (a paying-negative bill that flows to the event, the request_logs row,
//     and a negative session-spend credit);
//   - openai: negative cached_tokens (prompt_tokens_details path, ungated)
//     INFLATES the non-cache input term → billed EXCEEDS the honest full
//     list (overcharge), while the legacy prompt_cache_hit_tokens field is
//     >0-gated and safe.
//
// Fix locus: pkg/provider parsers + a per-class floor in ComputeCost —
// outside N03-P06-T07's write scope. Handoff: T07 record §defect. These
// pins freeze today's exact numbers so the owner's fix flips them
// deliberately.
func TestN03P6T07_NegativeProviderFields_DefectPin_D1(t *testing.T) {
	t.Run("anthropic-negative-creation-bills-negative", func(t *testing.T) {
		const body = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
			`"messages":[{"role":"user","content":"hostile"}]}`
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",` +
				`"model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],` +
				`"stop_reason":"end_turn","usage":{"input_tokens":1000,"output_tokens":50,` +
				`"cache_creation_input_tokens":-5000}}`))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06AnthropicGateway(t, up.URL)
		cap := captureAll(t)

		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
			"no read reported → no discount promised even on hostile usage")

		ev := cap.last(t)
		assert.Equal(t, int64(-5000), ev.CacheCreationTokens, "DEFECT: negative creation mirrored verbatim")
		wantBilled := n03p6t06AnthropicBilled(1000, 50, -5000, 0) // (3000+750-18750)/1e6 = -0.015
		assert.InDelta(t, wantBilled, ev.EstimatedCostUSD, 1e-15,
			"DEFECT D1: the negative creation term bills NEGATIVE cost end-to-end")
		assert.Negative(t, ev.EstimatedCostUSD,
			"DEFECT D1 pin: prior behavior produces a negative bill; fix in pkg/provider flips this")
	})

	t.Run("openai-negative-cached-overcharges", func(t *testing.T) {
		const body = `{"model":"gpt-4o","messages":[{"role":"user","content":"hostile"}]}`
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
				`"prompt_tokens_details":{"cached_tokens":-300}}}`))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, body)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		assert.Equal(t, int64(-300), ev.CacheReadTokens, "DEFECT: negative cached_tokens mirrored verbatim")
		// nonCache = 800-(-300) = 1100 (the negative read INFLATES the input
		// term): billed = (1100*2.5 + 100 - 375)/1e6 = 0.002475 > honest full
		// list 0.0021 — a silent overcharge.
		wantBilled := n03p6t06OpenAIBilled(800, 10, -300)
		full := n03p6t06OpenAIFullList(800, 10)
		assert.InDelta(t, wantBilled, ev.EstimatedCostUSD, 1e-15,
			"DEFECT D1: the negative read inflates the bill above the honest full list")
		assert.Greater(t, ev.EstimatedCostUSD, full,
			"DEFECT D1 pin: prior behavior overcharges vs full list; fix in pkg/provider flips this")
	})
}

// TestN03P6T07_OverflowBoundary_NeverNegativeBill: a hostile provider
// reports cache_read_input_tokens = math.MaxInt64. The canonical prompt
// count wraps (int64 overflow in the parser) but the cost arithmetic
// double-wraps back — the input term recovers the true value and the bill
// stays POSITIVE (absurdly large, but never a credit). The wrapped token
// count itself is mirrored verbatim (D1-adjacent, same fix locus).
func TestN03P6T07_OverflowBoundary_NeverNegativeBill(t *testing.T) {
	const body = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
		`"messages":[{"role":"user","content":"overflow"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",` +
			`"model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],` +
			`"stop_reason":"end_turn","usage":{"input_tokens":1000,"output_tokens":50,` +
			`"cache_read_input_tokens":9223372036854775807}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06AnthropicGateway(t, up.URL)
	cap := captureAll(t)

	rec := postMessages(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"a positive (overflowing) read count still reports the provider hit honestly")

	ev := cap.last(t)
	maxTok := int64(math.MaxInt64)
	wrappedPrompt := maxTok + 1000 // runtime int64 wrap: 1000 + MaxInt64
	assert.Equal(t, wrappedPrompt, ev.TokensIn,
		"DEFECT-adjacent pin: the canonical prompt count wraps verbatim (parser int64 add)")
	assert.Equal(t, maxTok, ev.CacheReadTokens)

	// Mirror ComputeCost's exact term order: the non-cache input term
	// double-wraps back to the true 1000, so the bill is positive.
	want := 3.0/1e6*1000 + 15.0/1e6*50 + 3.75/1e6*0 + 0.3/1e6*float64(maxTok)
	assert.InDelta(t, want, ev.EstimatedCostUSD, 1e-15)
	assert.Positive(t, ev.EstimatedCostUSD,
		"the overflow boundary must never produce a negative bill (harm direction is overcharge only)")
}

// TestN03P6T07_ZeroUsageBlock_ProviderMissZeroBill: a present-but-empty
// usage block is still PROVIDER-reported usage (source stays provider, not
// none) — the header honestly reports "miss" (no read), the bill is a real
// zero, and the cost classification stays priced.
func TestN03P6T07_ZeroUsageBlock_ProviderMissZeroBill(t *testing.T) {
	const body = `{"model":"gpt-4o","messages":[{"role":"user","content":"empty usage"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06ChatGateway(t, up.URL)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
		"provider usage with zero reads reports the miss; it is never dropped to a fabricated absent-header")

	ev := cap.last(t)
	assert.Equal(t, "provider", ev.UsageSource,
		"a present usage block is provider-reported even when all counts are zero")
	assert.Equal(t, "priced", ev.CostStatus)
	assert.Equal(t, int64(0), ev.TokensIn)
	assert.InDelta(t, 0.0, ev.EstimatedCostUSD, 1e-15)
}

// TestN03P6T07_SSEDrainFailure_PartialUsageBillsExactly: the usage chunk
// arrives, then the upstream stream truncates (no [DONE]). The partial
// provider usage is the real upstream usage (G3 parity: the prefix was
// consumed) — it bills exactly, the failure event carries the provider
// source and cost classification, and the trailer reports the hit the
// client can still read.
func TestN03P6T07_SSEDrainFailure_PartialUsageBillsExactly(t *testing.T) {
	up := breakServer(t, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"+
		"data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":800,\"completion_tokens\":10,"+
		"\"total_tokens\":810,\"prompt_tokens_details\":{\"cached_tokens\":600}}}\n\n")
	t.Cleanup(up.Close)

	gw := n03p6t06ChatGateway(t, up.URL)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"truncated"}]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey),
		"the drain-failure branch must still report the partial provider outcome")

	ev := cap.last(t)
	assert.Equal(t, "request.failed", ev.EventType)
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(10), ev.TokensOut)
	assert.Equal(t, int64(600), ev.CacheReadTokens)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, "priced", ev.CostStatus)

	billed := n03p6t06OpenAIBilled(800, 10, 600) // (500+100+750)/1e6 = 0.00135
	full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
	disc := n03p6t06OpenAIDiscount(600)          // 0.00075
	n03p6t06AssertBilled(t, "sse-drain-failure", ev, billed, full, disc)
}

// --- aspect B: provider contract differences ---------------------------------

// TestN03P6T07_LegacyDeepSeekCacheFields_WireBilling: the DeepSeek legacy
// prompt_cache_hit_tokens field bills at the wire level even when the
// modern details object is absent (fallback), and when BOTH fields are
// present the details object wins with no double-count. T04 pinned the
// parser; this pins the billing+header consequences.
func TestN03P6T07_LegacyDeepSeekCacheFields_WireBilling(t *testing.T) {
	t.Run("legacy-only-fallback-bills", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
				`"prompt_cache_hit_tokens":400}}`))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"legacy"}]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		assert.Equal(t, int64(400), ev.CacheReadTokens)
		billed := n03p6t06OpenAIBilled(800, 10, 400) // 0.0016
		full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
		disc := n03p6t06OpenAIDiscount(400)          // 0.0005
		n03p6t06AssertBilled(t, "legacy-only", ev, billed, full, disc)
	})

	t.Run("both-present-details-wins-no-double-count", func(t *testing.T) {
		// legacy=500 would double-count to read=1100 → (clamped) 0.001475;
		// honest details-only billing is 0.00135. The pin distinguishes.
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
				`"prompt_cache_hit_tokens":500,` +
				`"prompt_tokens_details":{"cached_tokens":600}}}`))
		}))
		t.Cleanup(up.Close)

		gw := n03p6t06ChatGateway(t, up.URL)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"both"}]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		ev := cap.last(t)
		assert.Equal(t, int64(600), ev.CacheReadTokens, "details object wins; legacy field never adds on")
		billed := n03p6t06OpenAIBilled(800, 10, 600) // 0.00135
		full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
		disc := n03p6t06OpenAIDiscount(600)          // 0.00075
		n03p6t06AssertBilled(t, "both-present", ev, billed, full, disc)
		// Sanity: a double-count (read=1100, clamped) would bill 0.001475 —
		// the pin distinguishes it from the honest 0.00135.
		doubleBill := provider.ComputeCost(provider.Usage{
			PromptTokens: 800, CompletionTokens: 10, CacheReadTokens: 1100,
			Source: provider.UsageSourceProvider,
		}, "openai", "gpt-4o").EstimatedCostUSD
		assert.InDelta(t, 0.001475, doubleBill, 1e-15,
			"sanity: the double-count bill differs from the pinned honest bill")
	})
}

// TestN03P6T07_UnpricedModel_RealHit_NoFabricatedDiscount: a real provider
// hit on a model absent from the price table — the outcome stays honest
// ("hit"), but no discount NUMBER is fabricated: the bill is a true zero
// and the cost classification is unknown_price, not priced.
func TestN03P6T07_UnpricedModel_RealHit_NoFabricatedDiscount(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"unpriced-probe-model",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
			`"prompt_tokens_details":{"cached_tokens":300}}}`))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.res = stubModelResolver{
		"unpriced-probe-model": {ModelName: "unpriced-probe-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, `{"model":"unpriced-probe-model","messages":[{"role":"user","content":"unpriced"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"the provider-reported hit is reported regardless of pricing knowledge")

	ev := cap.last(t)
	// CacheHitType is the RESPONSE-cache hit field — empty for
	// upstream-served traffic; the prompt-cache outcome rode the header.
	assert.Empty(t, ev.CacheHitType)
	assert.Equal(t, "unknown_price", ev.CostStatus)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.InDelta(t, 0.0, ev.EstimatedCostUSD, 1e-15,
		"unknown price → true zero bill; no discount number may be fabricated")
	assert.Equal(t, int64(300), ev.CacheReadTokens, "the real usage still lands verbatim for analytics")
}

// --- aspect C: unsupported-hint negative boundaries --------------------------

// TestN03P6T07_HintedSSE_NonCachingProvider_NoBreakNoDiscount: a hinted
// streaming request to a non-caching provider (same-contract openai). The
// marker crosses verbatim (the client's own bytes — identity translation),
// the request does not break, the miss is reported, and the bill is full
// list — no discount is promised or granted.
func TestN03P6T07_HintedSSE_NonCachingProvider_NoBreakNoDiscount(t *testing.T) {
	const hintedBody = `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"hinted stream","cache_control":{"type":"ephemeral"}}]}]}`
	up := newN03P6T06Upstream(
		"data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
			"data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":800,\"completion_tokens\":10," +
			"\"total_tokens\":810}}\n\n" +
			"data: [DONE]\n\n",
	)
	srv := httptest.NewServer(up.handler(t))
	t.Cleanup(srv.Close)

	gw := n03p6t06ChatGateway(t, srv.URL)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, hintedBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(promptCacheTrailerKey),
		"non-caching provider + hint → honest miss on the streaming surface")

	ev := cap.last(t)
	// CacheHitType is the RESPONSE-cache hit field — empty for
	// upstream-served traffic; the prompt-cache outcome rides the trailer.
	assert.Empty(t, ev.CacheHitType)
	assert.Equal(t, int64(0), ev.CacheReadTokens)

	billed := n03p6t06OpenAIBilled(800, 10, 0) // full list 0.0021
	full := n03p6t06OpenAIFullList(800, 10)
	disc := n03p6t06OpenAIDiscount(0) // 0
	n03p6t06AssertBilled(t, "hinted-sse-miss", ev, billed, full, disc)

	assert.Contains(t, up.sentBody(), "cache_control",
		"same-contract client markers cross verbatim (identity translation — prior behavior)")
}

// TestN03P6T07_TranslationDropsClientHint_ProviderImplicitHit: a client
// hint on /v1/messages routed to an openai backend — the translation
// rebuild drops the marker (openai-shaped upstreams never carry it), the
// request does not break, and when the provider's OWN implicit cache hits
// the honest hit + discount appear anyway (savings follow provider usage,
// not the hint).
func TestN03P6T07_TranslationDropsClientHint_ProviderImplicitHit(t *testing.T) {
	const hintedAnthropicBody = `{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"translated hint","cache_control":{"type":"ephemeral"}}]}]}`
	up := newN03P6T06Upstream(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":800,"completion_tokens":10,"total_tokens":810,` +
		`"prompt_tokens_details":{"cached_tokens":600}}}`)
	srv := httptest.NewServer(up.handler(t))
	t.Cleanup(srv.Close)

	n03p6t06ResetDefaultPricer(t)
	gw := responsesTestGateway(t, srv.URL)
	gw.res = stubModelResolver{
		"gpt-4o": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := postMessages(t, gw, hintedAnthropicBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"the provider's implicit hit is reported even though the hint never crossed")

	ev := cap.last(t)
	// CacheHitType is the RESPONSE-cache hit field — empty for
	// upstream-served traffic; the prompt-cache outcome rode the header
	// pinned above.
	assert.Empty(t, ev.CacheHitType)
	assert.Equal(t, "messages", ev.Endpoint)
	assert.Equal(t, int64(600), ev.CacheReadTokens)
	billed := n03p6t06OpenAIBilled(800, 10, 600) // 0.00135
	full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
	disc := n03p6t06OpenAIDiscount(600)          // 0.00075
	n03p6t06AssertBilled(t, "translated-implicit-hit", ev, billed, full, disc)

	assert.NotContains(t, up.sentBody(), "cache_control",
		"the translated upstream body must never carry the client's anthropic marker (R103 contract)")
	assert.Contains(t, up.sentBody(), "translated hint", "the content itself must survive translation")
}

// TestN03P6T07_MalformedHintShapes_NativePassthrough_NoBreak: malformed
// cache_control shapes (number / string instead of object) on the native
// anthropic path. The native surface passes the client's body through
// verbatim (model override only) — the gateway neither validates nor
// mutates hints there, so the request must not break and billing follows
// whatever the provider reports.
func TestN03P6T07_MalformedHintShapes_NativePassthrough_NoBreak(t *testing.T) {
	const malformedBody = `{"model":"claude-sonnet-4-5","max_tokens":64,` +
		`"system":[{"type":"text","text":"sys","cache_control":"ephemeral"}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"malformed hint","cache_control":42}]}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n03p6t06AnthropicHitJSON))
	}))
	t.Cleanup(up.Close)

	gw := n03p6t06AnthropicGateway(t, up.URL)
	cap := captureAll(t)

	rec := postMessages(t, gw, malformedBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String(),
		"malformed hint shapes must not break the native passthrough")
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

	ev := cap.last(t)
	assert.Equal(t, int64(600), ev.CacheReadTokens,
		"billing follows the provider-reported usage regardless of hint shape")
	billed := n03p6t06AnthropicBilled(1000, 200, 150, 600)
	full := n03p6t06AnthropicFullList(1000, 200, 150, 600)
	disc := n03p6t06AnthropicDiscount(150, 600)
	n03p6t06AssertBilled(t, "malformed-hint-native", ev, billed, full, disc)
}

// --- helpers ------------------------------------------------------------------

// sentBody returns the last raw upstream request body the scripted upstream
// received (empty when no call happened).
func (u *n03p6t06Upstream) sentBody() string {
	s, _ := u.sent.Load().(string)
	return s
}
