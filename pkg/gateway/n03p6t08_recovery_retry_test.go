package cli

// N03-P06-T08 — interruptions / retry / resume recovery corpus for the
// provider prompt-cache & usage packet (entry path pkg/gateway). T06 pinned
// single-call billing; T07 pinned contract-boundary billing; this file pins
// what happens when a request does NOT reach the provider cleanly exactly
// once:
//
//   - JSON retry (executeChatJSON): a retryable upstream failure (503, no
//     usage) is retried against the same model; ONLY the winning attempt's
//     usage reaches the event and the bill — retried-away response bodies are
//     never parsed, never summed (both the OpenAI read discount and the
//     Anthropic write premium bill exactly once). RetryCount/AttemptCount
//     carry the attempt accounting.
//   - Ambiguous outcome (200 committed upstream, body lost mid-read): the
//     gateway refuses BOTH to auto-retry and to bill — the caller gets
//     502 upstream_outcome_unknown, no analytics event exists, and the
//     upstream saw exactly one call. (An ambiguous attempt may have consumed
//     provider cache-writes; billing it blind on a guess is exactly-once by
//     refusal.)
//   - SSE retry at the connection phase (serveStream): a 503 before any SSE
//     byte is retried transparently; the usage chunk of the winning
//     connection bills once.
//   - Drain interruption + explicit client resume: the broken stream's
//     partial provider usage bills on its own request.failed event (no loss);
//     the resumed request bills only its own usage under its own
//     X-Request-ID identity (no duplication, no token summation across
//     requests).
//   - Fallback chain: the winning hop's provider contract and price table
//     govern the bill — the failed primary contributes zero usage; the
//     chain transition is fallback accounting (AttemptCount counts hops),
//     not an intra-model retry (RetryCount).
//   - Exhausted retries: exactly one request.failed event, usage_source
//     "none", a true zero bill — no usage is invented for attempts that
//     never produced a body.
//
// Billing oracles are the T06 hand formulas (rates from pkg/pricing
// bundled.json); every cost pin is exact at 1e-15. The D1 negative-fields
// defect pin (T07) is deliberately NOT touched — every scenario here uses
// non-negative provider fields.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- scripted upstream --------------------------------------------------------

// n03p6t08Step is one scripted upstream response. Two broken-write modes:
//
//   - truncate declares Content-Length = len(body) but writes only the first
//     half: the gateway's read side gets an unexpected EOF mid-body on a
//     response whose status line already said 200 — the ambiguous-outcome
//     shape (the request executed upstream; the gateway cannot know whether
//     the provider committed usage).
//   - underwrite writes the FULL body but declares Content-Length
//     len(body)+16384: the gateway reads everything it needs (including the
//     trailing usage chunk), then hits EOF waiting for the missing tail —
//     the drain-interruption shape (a complete-looking outcome lost at the
//     framing layer). This mirrors T07's breakServer contract exactly.
type n03p6t08Step struct {
	status      int
	body        string
	contentType string
	truncate    bool
	underwrite  bool
}

type n03p6t08Scripted struct {
	steps []n03p6t08Step
	calls atomic.Int32
}

func (s *n03p6t08Scripted) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		i := int(s.calls.Add(1)) - 1
		if i >= len(s.steps) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		st := s.steps[i]
		if st.status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(st.status)
			_, _ = io.WriteString(w, st.body)
			return
		}
		ct := st.contentType
		if ct == "" {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		if st.truncate {
			w.Header().Set("Content-Length", strconv.Itoa(len(st.body)))
			_, _ = io.WriteString(w, st.body[:len(st.body)/2])
			return
		}
		if st.underwrite {
			w.Header().Set("Content-Length", strconv.Itoa(len(st.body)+16384))
			_, _ = io.WriteString(w, st.body)
			return
		}
		_, _ = io.WriteString(w, st.body)
	}
}

// n03p6t08RetryGateway is the T06 chat harness with a fast multi-attempt
// retry policy (1–2ms backoff instead of the production 50ms+ — the corpus
// must not sleep) and, optionally, a real fallback executor over the stub
// resolver (production wiring: the executor resolves failover_models via
// gw.res).
func n03p6t08RetryGateway(t *testing.T, upstreamURL string, maxAttempts int) *gateway {
	t.Helper()
	gw := n03p6t06ChatGateway(t, upstreamURL)
	gw.retryPolicy = retry.Policy{
		MaxAttempts:  maxAttempts,
		BaseDelay:    time.Millisecond,
		MaxDelay:     2 * time.Millisecond,
		JitterFactor: 0,
		RetryOn:      retry.DefaultClassifier,
	}
	return gw
}

// n03p6t08PostChatID posts through the full route stack with the requestid
// middleware mounted (production mounts it upstream of the gateway), so the
// client-supplied X-Request-ID becomes the request identity that the
// analytics events carry.
func n03p6t08PostChatID(t *testing.T, gw *gateway, body, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestid.RequestIDHeader, requestID)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Use(requestid.Inject)
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// n03p6t08SSEUsageChunk is the OpenAI-style stream usage block (T07 shape).
func n03p6t08SSEUsageChunk(prompt, completion, cached int) string {
	return "data: {\"id\":\"u\",\"choices\":[],\"usage\":{\"prompt_tokens\":" + strconv.Itoa(prompt) +
		",\"completion_tokens\":" + strconv.Itoa(completion) + ",\"total_tokens\":" + strconv.Itoa(prompt+completion) +
		",\"prompt_tokens_details\":{\"cached_tokens\":" + strconv.Itoa(cached) + "}}}\n\n"
}

// --- clause 1: JSON retry bills only the winning attempt -----------------------

// TestN03P6T08_JSONRetry_WinningAttemptUsageBillsExactlyOnce: a 503 (the
// contract-accurate retryable failure — no usage block) is retried against
// the same model; the winning attempt's usage — and only it — reaches the
// single completed event and the exact bill.
func TestN03P6T08_JSONRetry_WinningAttemptUsageBillsExactlyOnce(t *testing.T) {
	t.Run("openai-read-discount-once", func(t *testing.T) {
		scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
			{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
			{status: http.StatusOK, body: n03p6t06OpenAIHitJSON},
		}}
		up := httptest.NewServer(scripted.handler())
		t.Cleanup(up.Close)

		gw := n03p6t08RetryGateway(t, up.URL, 3)
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, int32(2), scripted.calls.Load(), "exactly one retry: 2 upstream calls total")

		events := cap.all()
		require.Len(t, events, 1, "retried-away attempts publish no events; one completed event total")
		ev := events[0]
		require.Equal(t, "request.completed", ev.EventType)
		assert.Equal(t, int64(800), ev.TokensIn, "usage comes from the WINNING attempt's body only")
		assert.Equal(t, int64(120), ev.TokensOut)
		assert.Equal(t, int64(300), ev.CacheReadTokens)
		assert.Equal(t, "provider", ev.UsageSource)
		assert.Equal(t, 1, ev.RetryCount, "one intra-model retry")
		assert.Equal(t, 1, ev.AttemptCount, "single-model chain: one hop")
		// The JSON path reports the cache outcome as a plain header (only the
		// stream path uses the trailer prefix — see prompt_cache.go).
		assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader))

		billed := n03p6t06OpenAIBilled(800, 120, 300) // 0.002825
		full := n03p6t06OpenAIFullList(800, 120)      // 0.0032
		disc := n03p6t06OpenAIDiscount(300)           // 0.000375
		n03p6t06AssertBilled(t, "retry-openai", ev, billed, full, disc)
		// Sanity: a doubled read premium (both attempts' bodies summed) would
		// bill 0.002825×2 − the retry is provably distinct from a double bill.
		double := provider.ComputeCost(provider.Usage{
			PromptTokens: 1600, CompletionTokens: 240, CacheReadTokens: 600,
			Source: provider.UsageSourceProvider,
		}, "openai", "gpt-4o").EstimatedCostUSD
		assert.InDelta(t, 0.00565, double, 1e-15, "sanity: the summed-usage bill differs from the pinned winner-only bill")
	})

	t.Run("anthropic-write-premium-once-through-chat-translation", func(t *testing.T) {
		// The premium rides the CHAT pipeline here (T06 pinned the native
		// /v1/messages path): the anthropic adapter translates the chat
		// request, the upstream answers anthropic-native, ParseUsage reads
		// the translated shape — the write premium must survive the
		// round-trip AND the retry, billed exactly once.
		scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
			{status: http.StatusServiceUnavailable, body: `{"type":"error","error":{"type":"overloaded_error"}}`},
			{status: http.StatusOK, body: n03p6t06AnthropicHitJSON},
		}}
		up := httptest.NewServer(scripted.handler())
		t.Cleanup(up.Close)

		gw := n03p6t08RetryGateway(t, up.URL, 3)
		gw.res = stubModelResolver{
			"claude-sonnet-4-5": {
				ModelName:      "claude-sonnet-4-5",
				Provider:       "anthropic",
				UpstreamURL:    up.URL,
				UpstreamAPIKey: "upstream-key",
				Enabled:        true,
			},
		}
		cap := captureAll(t)

		rec := n03p6t06PostChat(t, gw, n03p6t08ChatBody("claude-sonnet-4-5"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, int32(2), scripted.calls.Load())

		events := cap.all()
		require.Len(t, events, 1)
		ev := events[0]
		require.Equal(t, "request.completed", ev.EventType)
		assert.Equal(t, "claude-sonnet-4-5", ev.ModelUsed)
		// Canonical inclusive anthropic usage: prompt = input + read + creation.
		assert.Equal(t, int64(1750), ev.TokensIn)
		assert.Equal(t, int64(200), ev.TokensOut)
		assert.Equal(t, int64(600), ev.CacheReadTokens)
		assert.Equal(t, int64(150), ev.CacheCreationTokens, "the write premium survives translation + retry")
		assert.Equal(t, "provider", ev.UsageSource)
		assert.Equal(t, 1, ev.RetryCount)

		billed := n03p6t06AnthropicBilled(1000, 200, 150, 600) // 0.0067425
		full := n03p6t06AnthropicFullList(1000, 200, 150, 600) // 0.00825
		disc := n03p6t06AnthropicDiscount(150, 600)            // 0.0015075 (write premium shows NEGATIVE contribution)
		n03p6t06AssertBilled(t, "retry-anthropic", ev, billed, full, disc)
		// Sanity: billing BOTH attempts' usage (the retry summed with the
		// winner) would bill 0.013485 — double the canonical usage, with the
		// creation premium twice (300×3.75 instead of 150×3.75). The
		// retried-away 503 attempt provably contributed nothing.
		doublePremium := provider.ComputeCost(provider.Usage{
			PromptTokens: 3500, CompletionTokens: 400,
			CacheReadTokens: 1200, CacheCreationTokens: 300,
			Source: provider.UsageSourceProvider,
		}, "anthropic", "claude-sonnet-4-5").EstimatedCostUSD
		assert.InDelta(t, 0.013485, doublePremium, 1e-15,
			"sanity: the summed-usage bill differs from the pinned winner-only bill")
	})
}

// n03p6t08ChatBody is the plain chat body for an arbitrary resolved model
// name (chat pipeline → provider translation).
func n03p6t08ChatBody(model string) string {
	return `{"model":"` + model + `","messages":[{"role":"user","content":"summarize"}]}`
}

// --- clause 2: ambiguous outcome — never retried, never billed ------------------

// TestN03P6T08_UnknownOutcome_NeverRetriedNeverBilled: the upstream committed
// a 200 but the body is lost mid-read. The outcome is ambiguous (the provider
// may already have written cache entries / counted usage): the gateway
// refuses to auto-retry (a blind second call could double-spend) and refuses
// to bill a guessed usage — the caller gets 502 upstream_outcome_unknown, no
// analytics event exists, and the upstream saw exactly one call.
func TestN03P6T08_UnknownOutcome_NeverRetriedNeverBilled(t *testing.T) {
	scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusOK, body: n03p6t06OpenAIHitJSON, truncate: true},
		// Any further step would prove a forbidden retry.
		{status: http.StatusOK, body: n03p6t06OpenAIHitJSON},
	}}
	up := httptest.NewServer(scripted.handler())
	t.Cleanup(up.Close)

	gw := n03p6t08RetryGateway(t, up.URL, 3)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "upstream outcome unknown; request was not retried")
	assert.Equal(t, int32(1), scripted.calls.Load(),
		"an ambiguous outcome must never be auto-retried, even with retry budget left")

	require.Empty(t, cap.all(),
		"no analytics event and no bill may exist for an attempt whose outcome the gateway cannot vouch for")
}

// --- clause 3: SSE connection-phase retry --------------------------------------

// TestN03P6T08_StreamRetry_ConnectionPhase_BillsWinningUsageOnce: a 503
// before any SSE byte is a proven not-executed outcome — serveStream retries
// the connection transparently; the winning connection's usage chunk bills
// exactly once and the client sees one clean stream.
func TestN03P6T08_StreamRetry_ConnectionPhase_BillsWinningUsageOnce(t *testing.T) {
	win := "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" +
		n03p6t08SSEUsageChunk(800, 10, 300) +
		"data: [DONE]\n\n"
	scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
		{status: http.StatusOK, body: win, contentType: "text/event-stream"},
	}}
	up := httptest.NewServer(scripted.handler())
	t.Cleanup(up.Close)

	gw := n03p6t08RetryGateway(t, up.URL, 3)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIStreamPlainBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "data: [DONE]", "the client sees one clean, complete stream")
	assert.Equal(t, int32(2), scripted.calls.Load())
	assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey))

	events := cap.all()
	require.Len(t, events, 1, "the retried-away connection publishes no event")
	ev := events[0]
	require.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(10), ev.TokensOut)
	assert.Equal(t, int64(300), ev.CacheReadTokens)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, 1, ev.RetryCount)

	billed := n03p6t06OpenAIBilled(800, 10, 300) // 0.001725
	full := n03p6t06OpenAIFullList(800, 10)      // 0.0021
	disc := n03p6t06OpenAIDiscount(300)          // 0.000375
	n03p6t06AssertBilled(t, "stream-retry", ev, billed, full, disc)
}

// --- clause 4: drain interruption + explicit resume -----------------------------

// TestN03P6T08_DrainInterruption_PartialBillThenResume_NoLossNoDuplication:
// the stream breaks after the provider's usage chunk was relayed — the
// consumed prefix bills on its own request.failed event (partial usage is
// real provider spend: no loss). The client resumes with a NEW request: it
// gets its own request id, its own event, and bills ONLY its own usage (no
// duplication of the interrupted attempt's bill, no token summation across
// requests). Σ(bills) = interrupted + resumed, exact.
func TestN03P6T08_DrainInterruption_PartialBillThenResume_NoLossNoDuplication(t *testing.T) {
	broken := "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n" +
		n03p6t08SSEUsageChunk(800, 10, 600)
	resumed := "data: {\"id\":\"3\",\"choices\":[{\"delta\":{\"content\":\"full\"}}]}\n\n" +
		n03p6t08SSEUsageChunk(800, 10, 300) +
		"data: [DONE]\n\n"
	scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusOK, body: broken, contentType: "text/event-stream", underwrite: true},
		{status: http.StatusOK, body: resumed, contentType: "text/event-stream"},
	}}
	up := httptest.NewServer(scripted.handler())
	t.Cleanup(up.Close)

	gw := n03p6t08RetryGateway(t, up.URL, 1)
	cap := captureAll(t)

	// Call 1: the interruption. After the 200/SSE commit there is no
	// transparent retry (a mid-stream break is not a proven not-executed
	// outcome) — the drain-failure branch settles honestly.
	rec1 := n03p6t08PostChatID(t, gw, n03p6t06OpenAIStreamPlainBody, "req-n03p6t08-drain-1")
	require.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "hit", rec1.Header().Get(promptCacheTrailerKey),
		"the partial provider outcome stays visible to the client")

	// Call 2: the explicit client resume (same conversation, new request
	// identity — the client's X-Request-ID is the correlation key).
	rec2 := n03p6t08PostChatID(t, gw, n03p6t06OpenAIStreamPlainBody, "req-n03p6t08-drain-2")
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())

	events := cap.all()
	require.Len(t, events, 2, "exactly one event per request: failed (interrupted) + completed (resumed)")
	failed, completed := events[0], events[1]
	require.Equal(t, "request.failed", failed.EventType)
	require.Equal(t, "request.completed", completed.EventType)
	assert.Equal(t, "req-n03p6t08-drain-1", failed.RequestID,
		"the interrupted request's partial bill carries ITS identity")
	assert.Equal(t, "req-n03p6t08-drain-2", completed.RequestID,
		"the resumed request settles under its own identity")
	assert.NotEqual(t, failed.RequestID, completed.RequestID,
		"the resume is a distinct request with its own identity")

	// No loss: the interrupted request's partial provider usage bills.
	assert.Equal(t, int64(800), failed.TokensIn)
	assert.Equal(t, int64(10), failed.TokensOut)
	assert.Equal(t, int64(600), failed.CacheReadTokens)
	assert.Equal(t, "provider", failed.UsageSource)
	interruptedBill := n03p6t06OpenAIBilled(800, 10, 600) // 0.00135
	assert.InDelta(t, interruptedBill, failed.EstimatedCostUSD, 1e-15,
		"the interrupted prefix's real provider spend must not be lost")

	// No duplication: the resumed request bills only its own usage.
	assert.Equal(t, int64(800), completed.TokensIn,
		"no token summation across the interrupted and resumed requests")
	assert.Equal(t, int64(300), completed.CacheReadTokens)
	resumedBill := n03p6t06OpenAIBilled(800, 10, 300) // 0.001725
	assert.InDelta(t, resumedBill, completed.EstimatedCostUSD, 1e-15,
		"the resumed bill must contain ONLY the resumed request's usage")

	// Σ across the interruption + resume, exact: nothing lost, nothing doubled.
	assert.InDelta(t, interruptedBill+resumedBill,
		failed.EstimatedCostUSD+completed.EstimatedCostUSD, 1e-15)
}

// --- clause 5: fallback chain — the winning hop governs -------------------------

// TestN03P6T08_FallbackChain_WinningHopGovernsCacheBilling: the primary hop
// fails retryably (503, no usage) and the fallback chain (production wiring:
// router.NewFallbackExecutor resolving failover_models via gw.res) advances
// to gpt-4o-mini, whose cached read discount bills under the MINI price
// table. The failed primary contributes zero usage and publishes no event;
// the chain transition is fallback accounting (AttemptCount=2 hops), not an
// intra-model retry (RetryCount=0).
func TestN03P6T08_FallbackChain_WinningHopGovernsCacheBilling(t *testing.T) {
	primary := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
	}}
	primaryUp := httptest.NewServer(primary.handler())
	t.Cleanup(primaryUp.Close)

	fallback := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusOK, body: `{"id":"cmpl-2","object":"chat.completion","model":"gpt-4o-mini",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":200,"completion_tokens":10,"total_tokens":210,` +
			`"prompt_tokens_details":{"cached_tokens":200}}}`},
	}}
	fallbackUp := httptest.NewServer(fallback.handler())
	t.Cleanup(fallbackUp.Close)

	gw := n03p6t08RetryGateway(t, primaryUp.URL, 1)
	gw.res = stubModelResolver{
		"smart-router": {
			ModelName: "smart-router", Provider: "openai", UpstreamURL: primaryUp.URL, Enabled: true,
			FailoverModels: []string{"gpt-4o-mini"},
		},
		"gpt-4o-mini": {
			ModelName: "gpt-4o-mini", Provider: "openai", UpstreamURL: fallbackUp.URL, Enabled: true,
		},
	}
	// Production wiring shape: the executor resolves failover_models via gw.res.
	gw.fallback = router.NewFallbackExecutor(gw.res, 3, nil)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, `{"model":"smart-router","messages":[{"role":"user","content":"summarize"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int32(1), primary.calls.Load())
	assert.Equal(t, int32(1), fallback.calls.Load())

	events := cap.all()
	require.Len(t, events, 1, "the failed primary hop publishes no event")
	ev := events[0]
	require.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, "gpt-4o-mini", ev.ModelUsed, "the WINNING hop's model, not the requested one")
	assert.Equal(t, int64(200), ev.TokensIn)
	assert.Equal(t, int64(10), ev.TokensOut)
	assert.Equal(t, int64(200), ev.CacheReadTokens, "the winning hop's cache state")
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, 2, ev.AttemptCount, "the chain transition counts as the second hop")
	assert.Equal(t, 0, ev.RetryCount, "a fallback transition is NOT an intra-model retry")

	// gpt-4o-mini rates (0.15/0.6 in/out, read 0.075 — pkg/pricing): the
	// winning hop's table, not the primary's. The whole prompt was cached, so
	// billed = 0×0.15 + 10×0.6 + 200×0.075 = 0.000021.
	billed := (0*0.15 + 10*0.6 + 200*0.075) / 1e6 // 0.000021
	full := (200*0.15 + 10*0.6) / 1e6             // 0.000036
	disc := 200 * (0.15 - 0.075) / 1e6            // 0.000015
	n03p6t06AssertBilled(t, "fallback-mini", ev, billed, full, disc)
	// Sanity: pricing the same usage under the PRIMARY's table would bill
	// 0.00035 (all-noncached input 0×2.5 + 10×10 out + 200×1.25 read) — the
	// pin proves the winning hop's contract governed.
	primaryMisprice := provider.ComputeCost(provider.Usage{
		PromptTokens: 200, CompletionTokens: 10, CacheReadTokens: 200,
		Source: provider.UsageSourceProvider,
	}, "openai", "gpt-4o").EstimatedCostUSD
	assert.InDelta(t, 0.00035, primaryMisprice, 1e-15,
		"sanity: the primary-provider mispricing differs from the pinned winner-priced bill")
}

// --- clause 6: retries exhausted — one failed event, zero invented usage -------

// TestN03P6T08_RetriesExhausted_OneFailedEvent_NoUsageInvented: every attempt
// fails retryably with no usage block; exactly ONE request.failed event is
// published with usage_source "none" and a true zero bill, the attempt
// accounting is visible (RetryCount=2, AttemptCount=1), and the client gets
// the mapped 502 envelope.
func TestN03P6T08_RetriesExhausted_OneFailedEvent_NoUsageInvented(t *testing.T) {
	scripted := &n03p6t08Scripted{steps: []n03p6t08Step{
		{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
		{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
		{status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`},
	}}
	up := httptest.NewServer(scripted.handler())
	t.Cleanup(up.Close)

	gw := n03p6t08RetryGateway(t, up.URL, 3)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw, n03p6t06OpenAIPlainBody)
	require.Equal(t, http.StatusBadGateway, rec.Code,
		"upstream 503 maps to the client 502 envelope (MapUpstreamStatus)")
	assert.Equal(t, int32(3), scripted.calls.Load(), "the retry budget is spent before giving up")

	events := cap.all()
	require.Len(t, events, 1, "exactly one failed event for the whole exhausted sequence")
	ev := events[0]
	require.Equal(t, "request.failed", ev.EventType)
	assert.Equal(t, int64(503), ev.StatusCode, "the upstream status stays visible on the event")
	assert.Equal(t, "none", ev.UsageSource)
	assert.Equal(t, "no_usage", ev.CostStatus)
	assert.Equal(t, int64(0), ev.TokensIn)
	assert.Equal(t, int64(0), ev.TokensOut)
	assert.Equal(t, 2, ev.RetryCount)
	assert.Equal(t, 1, ev.AttemptCount)
	assert.InDelta(t, 0.0, ev.EstimatedCostUSD, 1e-15,
		"attempts that never produced a body must never invent usage or a bill")
}

// --- guard: the corpus must not silently drift into the D1 defect ---------------

// n03p6t08AssertUsageNonNegative parses the JSON payload (a full completion
// body or one SSE data frame), finds every "usage" object and asserts each
// numeric leaf is >= 0 — the T07 D1 defect pin (negative provider cache
// fields billed verbatim) is owned by the W-PROV lease and must never leak
// into this recovery corpus.
func n03p6t08AssertUsageNonNegative(t *testing.T, label, payload string) {
	t.Helper()
	var doc map[string]any
	// TrimPrefix is a no-op for the plain-JSON fixtures (no SSE frame prefix).
	raw := strings.TrimPrefix(payload, "data: ")
	require.NoError(t, json.Unmarshal([]byte(raw), &doc), "%s: fixture must be valid JSON", label)
	usage, ok := doc["usage"].(map[string]any)
	require.True(t, ok, "%s: fixture must carry a usage object", label)
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch tv := v.(type) {
		case map[string]any:
			for k, nv := range tv {
				walk(path+"."+k, nv)
			}
		case float64:
			assert.GreaterOrEqual(t, tv, 0.0, "%s: usage field %s must be non-negative (D1 stays with W-PROV)", label, path)
		}
	}
	walk("usage", usage)
}

// TestN03P6T08_CorpusIsolation_NoNegativeFields: documents that every
// recovery scenario above deliberately uses non-negative provider usage
// fields so the D1 defect pin (negative provider cache fields billed
// verbatim, owned by the W-PROV pkg/provider lease) stays byte-stable across
// this delivery. If a future editor introduces a negative-field fixture
// here, the card's D1 non-fix contract is violated — move it to W-PROV.
func TestN03P6T08_CorpusIsolation_NoNegativeFields(t *testing.T) {
	n03p6t08AssertUsageNonNegative(t, "openai-hit-json", n03p6t06OpenAIHitJSON)
	n03p6t08AssertUsageNonNegative(t, "anthropic-hit-json", n03p6t06AnthropicHitJSON)
	for _, chunk := range []string{
		n03p6t08SSEUsageChunk(800, 10, 300),
		n03p6t08SSEUsageChunk(800, 10, 600),
	} {
		n03p6t08AssertUsageNonNegative(t, "sse-usage-chunk", chunk)
	}
}
