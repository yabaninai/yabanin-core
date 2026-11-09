package cli

// N03-P06-T09 — independent review of the N03-P06 packet (T05–T08 pins and
// evidence) plus the fix the review surfaced. Card contract: "actionable
// findings исправляются до принятия".
//
// D-T09-1 (new defect found by this review, FIXED in this delivery): the two
// CHAT policy-denial finishers billed the cache-discounted spend but DROPPED
// the cache token columns from the analytics event:
//
//   - pkg/gateway/chat.go finishPolicyDeniedJSON: EstimatedCostUSD comes from
//     ComputeCost(usage, …) with CacheReadTokens billed at the cached rate,
//     yet CacheReadTokens/CacheCreationTokens were not copied into the
//     eventBase (contrast the completed path in finalizeChatJSON).
//   - pkg/gateway/stream.go finishStreamPolicyDenied: ext := ComputeCost(usage,
//     …) billed at the cached rate, cache columns omitted likewise (contrast
//     finishDrainFailure and finishSuccess).
//
//   That violated the packet's own invariant documented at
// pkg/gateway/completions_endpoint.go:295–299 (N03-P06-T05): a discounted
// EstimatedCostUSD with zero CacheReadTokens makes the analytics ledger
// irreproducible from its own fields — the cost cannot be recomputed from the
// event's token columns, and Σ(cache_read_tokens) undercounts. The
// completions/native-messages/native-responses denial paths share the ONE
// builder with the columns; only the chat JSON and chat stream denials
// diverged. Both finishers now copy usage.CacheReadTokens/CacheCreationTokens
// into the event; the tests below pin the corrected contract — the bill AND
// its explaining columns ride every policy_denied event.
//
// Claim verification: the T07 record (§2, волна-24 errata п.6) quotes the
// OpenAI overflow magnitude ≈1.15e13 USD. The anthropic twin is pinned in
// TestN03P6T07_OverflowBoundary_NeverNegativeBill; the OpenAI figure had no
// pin — TestN03P6T09_OpenAIOverflowClaim_Pinned closes that gap at the
// ComputeCost contract level (non-cache input clamps to 0, cached tokens bill
// at 1.25 $/1M gpt-4o, result positive and finite, no negative bill).

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// n03p6t09OpenAIDenyJSON is a contract-accurate OpenAI-style completion whose
// usage reports a provider cache hit AND whose content trips a post-upstream
// deny detector: the tokens were consumed (billed) before the verdict.
const n03p6t09OpenAIDenyJSON = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"here is the leaked-ssn"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":800,"completion_tokens":120,"total_tokens":920,` +
	`"prompt_tokens_details":{"cached_tokens":300}}}`

// n03p6t09PostDenyYAML is denyWordYAML aimed at the post_upstream hook.
func n03p6t09PostDenyYAML(name, word string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - post_upstream\nsteps:\n  - id: word\n    detector: builtin/contains\n    params:\n      words: [\"" + word + "\"]\n      action: deny\n"
}

// n03p6t09Pricer prices the stream pin's resolved model (m1) at gpt-4o rates
// so the denial bill is the exact cache-discounted hand formula. The stream
// harness resolves "m1" (streamPolicyPostAsync overwrites gw.res), which the
// bundled static table does not price — without this pin the finisher quotes
// $0/unknown_price and the pin would test nothing about the discount.
type n03p6t09Pricer struct{}

func (n03p6t09Pricer) Lookup(p, model string) (pricing.Price, bool) {
	if p == "openai" && model == "m1" {
		return pricing.Price{InputPerM: 2.5, OutputPerM: 10.0, CacheWritePerM: 3.125, CacheReadPerM: 1.25}, true
	}
	return pricing.Price{}, false
}

// n03p6t09PinM1Pricer installs the m1 pricer as the process default for the
// test's lifetime (ComputeCost reads the global default pricer).
func n03p6t09PinM1Pricer(t *testing.T) {
	t.Helper()
	pricing.SetDefaultPricer(n03p6t09Pricer{})
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })
}

// n03p6t09PostChat mounts the production chat handler WITHOUT the inference
// middleware chain. The auth middleware deletes any client-supplied X-Org-Id
// (auth.go:57, anti-spoofing — only a DB-backed resolver re-sets it), which
// would empty policyPostUpstream's org channel and silently skip the pin's
// deny policy. Mounting gw.chatCompletions the same way routes() does, minus
// the middleware, restores the header contract the finishers consume.
func n03p6t09PostChat(t *testing.T, gw *gateway, body, orgID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", orgID)
	// chatCompletions installs a reservation gate in production; without one
	// the finisher's termination class never lands on the event
	// (reservationGateFrom(ctx) → attach). Mirror streamPolicyPostAsync: an
	// off-mode escrow keeps the wallet out of the test.
	ctx := withReservationGate(req.Context(), &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		rsv: &budget.Reservation{OrgID: testOrg, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: testOrg, Bound: 1_000_000},
		}},
	})
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Post("/v1/chat/completions", gw.chatCompletions)
	r.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

// n03p6t09FailedEvent returns the single request.failed event captured for
// the request (bounded wait — the stream denial publishes asynchronously).
func n03p6t09FailedEvent(t *testing.T, all func() []*eventpub.Event) *eventpub.Event {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, ev := range all() {
			if ev.EventType == "request.failed" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "no request.failed event captured")
	for _, ev := range all() {
		if ev.EventType == "request.failed" {
			return ev
		}
	}
	t.Fatal("unreachable")
	return nil
}

// TestN03P6T09_PolicyDeniedJSON_EventCarriesDiscountingCacheColumns pins the
// D-T09-1 fix on the JSON chat path: the denial event carries the
// cache-discounted bill TOGETHER with the cache columns that explain it.
func TestN03P6T09_PolicyDeniedJSON_EventCarriesDiscountingCacheColumns(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n03p6t09OpenAIDenyJSON))
	}))
	t.Cleanup(up.Close)

	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "n03p6t09-json-deny", OrgID: testOrg, Name: "n03p6t09-json-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: n03p6t09PostDenyYAML("n03p6t09-json-deny", "leaked-ssn")},
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.policyRuntime = rt
	cap := captureAll(t)

	rec := n03p6t09PostChat(t, gw, n03p6t06OpenAIPlainBody, testOrg)

	// The client gets the denial envelope, not the upstream body.
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "content_policy_violation")
	assert.NotContains(t, rec.Body.String(), "leaked-ssn",
		"denied content must not reach the client")

	// The upstream call happened — the provider-reported spend is real.
	ev := n03p6t09FailedEvent(t, cap.all)
	assert.Equal(t, int64(400), ev.StatusCode)
	assert.Equal(t, "policy_denied", ev.Termination)

	// The usage-bearing part of the contract is CORRECT: the provider usage
	// is on the event and the bill is the cache-discounted hand formula —
	// proof the denial billed exactly the spend that left the org.
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(120), ev.TokensOut)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, "priced", ev.CostStatus)
	assert.InDelta(t, n03p6t06OpenAIBilled(800, 120, 300), ev.EstimatedCostUSD, 1e-15,
		"the denial bill must be the cache-discounted provider-usage quote (0.002825, not the 0.0032 full list)")

	// D-T09-1 (FIXED here): the cache columns that discount the bill above
	// ride the event — full-list − billed = 300×1.25$/1M of savings are
	// explained by CacheReadTokens=300, the row is reproducible from its own
	// fields (the invariant completions_endpoint.go:295–299 pins), and the
	// OpenAI contract invents no creation tokens.
	assert.Equal(t, int64(300), ev.CacheReadTokens,
		"the denial event must carry the provider-reported cache reads the bill discounted")
	assert.Equal(t, int64(0), ev.CacheCreationTokens,
		"no cache-creation tokens may be invented on the OpenAI contract")
	assert.Less(t, ev.EstimatedCostUSD, n03p6t06OpenAIFullList(800, 120),
		"the denied spend shows the real cache discount, not the full-list bill")
}

// TestN03P6T09_PolicyDeniedStream_EventCarriesDiscountingCacheColumns pins
// the D-T09-1 fix on the stream path: the usage-only chunk arrives BEFORE the
// denied content frame, so the prefix abort bills parsed provider usage (with
// a cache hit) and the event carries the explaining cache columns.
func TestN03P6T09_PolicyDeniedStream_EventCarriesDiscountingCacheColumns(t *testing.T) {
	const trigger = "stream-secret"
	frames := []string{
		// Usage first: the openai handler parses it into the drain's usage
		// holder even though the prefix gate holds the frame from the client.
		`{"id":"1","choices":[],"usage":{"prompt_tokens":800,"completion_tokens":120,"total_tokens":920,"prompt_tokens_details":{"cached_tokens":300}}}`,
		streamChunkFrame("1", "here is the "+trigger+" the policy must abort"),
		`data: [DONE]`, // never reached — the abort cancels the upstream
	}
	up := newStreamPolicyUpstream(t, 0, frames...)

	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "n03p6t09-stream-deny", OrgID: testOrg, Name: "n03p6t09-stream-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: streamDenyPrefixYAML(trigger)},
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)

	n03p6t06ResetDefaultPricer(t)
	n03p6t09PinM1Pricer(t)
	// streamPolicyPostAsync installs its own stub resolver for "m1" (the
	// harness's resolved model, priced by n03p6t09PinM1Pricer) pointing the
	// upstream at gw.cfg.Provider — streamTestGateway already set that to the
	// test upstream.
	gw := streamTestGateway(up.srv.URL)
	gw.policyRuntime = rt
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai"})
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"probe"}]}`)

	// In-band AbortFrame termination; the denied content stays off the wire.
	assert.Contains(t, rec.body(), "blocked by organization policy", rec.body())
	assert.NotContains(t, rec.body(), trigger)

	ev := n03p6t09FailedEvent(t, events)
	assert.Equal(t, int64(200), ev.StatusCode, "the stream denial is in-band (stream was live)")
	assert.Equal(t, "policy_denied", ev.Termination)

	// Usage parsed from the pre-abort usage chunk bills cache-discounted.
	assert.Equal(t, int64(800), ev.TokensIn)
	assert.Equal(t, int64(120), ev.TokensOut)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, "priced", ev.CostStatus)
	assert.InDelta(t, n03p6t06OpenAIBilled(800, 120, 300), ev.EstimatedCostUSD, 1e-15,
		"the stream denial bill must be the cache-discounted provider-usage quote")

	// D-T09-1 (FIXED here), stream twin of the JSON pin: the columns that
	// discount the bill ride the in-band denial event too.
	assert.Equal(t, int64(300), ev.CacheReadTokens,
		"the stream denial event must carry the provider-reported cache reads the bill discounted")
	assert.Equal(t, int64(0), ev.CacheCreationTokens,
		"no cache-creation tokens may be invented on the OpenAI contract")
	assert.Less(t, ev.EstimatedCostUSD, n03p6t06OpenAIFullList(800, 120),
		"the denied spend shows the real cache discount, not the full-list bill")
}

// TestN03P6T09_OpenAIOverflowClaim_Pinned verifies the T07-record overflow
// claim for the OpenAI contract (≈1.15e13 USD): MaxInt64 cached tokens clamp
// the non-cache input to zero and bill 1.25 $/1M × MaxInt64 — a positive,
// finite quote with no negative branch taken. The anthropic twin (≈2.77e12,
// pinned in TestN03P6T07_OverflowBoundary_NeverNegativeBill) bills the cache
// READ rate 0.3 $/1M; the OpenAI figure uses gpt-4o's 1.25 $/1M.
func TestN03P6T09_OpenAIOverflowClaim_Pinned(t *testing.T) {
	u := provider.Usage{
		PromptTokens:    math.MaxInt64,
		CacheReadTokens: math.MaxInt64,
		Source:          provider.UsageSourceProvider,
	}
	ext := provider.ComputeCost(u, "openai", "gpt-4o")

	require.True(t, ext.PriceKnown, "gpt-4o must be priced by the bundled static table")
	want := 1.25 / 1e6 * float64(math.MaxInt64) // (800−300-style non-cache term clamped to 0)
	assert.InDelta(t, want, ext.EstimatedCostUSD, want*1e-12,
		"the overflow quote must be exactly the cached-rate term — the clamped input term contributes nothing")
	assert.Greater(t, ext.EstimatedCostUSD, 1e13,
		"claim magnitude: the OpenAI overflow quote exceeds 1e13 USD")
	assert.Less(t, ext.EstimatedCostUSD, 1.2e13,
		"claim magnitude ≈1.15e13 USD (T07 record §2 / волна-24 errata п.6)")
}
