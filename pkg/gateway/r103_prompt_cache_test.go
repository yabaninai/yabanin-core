package cli

// wire-boundary regressions for the ratified MINIMAL prompt-cache
// scope (2026-10-16): opt-in hint injection through the real policy pipeline
// (builtin/compress), x-yabanin-prompt-cache transparency from provider
// usage, billing of provider-reported cache tokens, and the pinned ordering
// — the policy mutation lands on cc.body BEFORE the reservation plan, the
// cache lookup/write and the upstream forward all consume it.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// r103Upstream is a dual-shape synthetic provider: /v1/messages answers the
// Anthropic Messages shape, /v1/chat/completions the OpenAI shape, both with
// configurable cache-usage reporting. Every received body is recorded.
type r103Upstream struct {
	srv       *httptest.Server
	cacheRead bool

	mu     sync.Mutex
	bodies map[string][]byte
}

func newR103Upstream(t *testing.T, cacheRead bool) *r103Upstream {
	t.Helper()
	u := &r103Upstream{cacheRead: cacheRead, bodies: map[string][]byte{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies[r.URL.Path] = raw
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/messages":
			usage := `"usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":2}`
			if u.cacheRead {
				usage = `"usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":2,"cache_read_input_tokens":4}`
			}
			_, _ = w.Write([]byte(`{"id":"msg_r103","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` + usage + `}`))
		default:
			usage := `"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}`
			if u.cacheRead {
				usage = `"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":4}}`
			}
			_, _ = w.Write([]byte(`{"id":"cmpl_r103","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` + usage + `}`))
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *r103Upstream) bodyFor(path string) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bodies[path]
}

// r103Cache is a responseCache double that always misses but records every
// lookup and write prompt, so tests can pin WHICH body the cache identity
// was computed over.
type r103Cache struct {
	mu      sync.Mutex
	lookups [][]byte
	writes  [][]byte
}

func (c *r103Cache) LookupWithResult(_ context.Context, _ cache.RouteIdentity, promptJSON []byte) (*cache.CacheHit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups = append(c.lookups, append([]byte(nil), promptJSON...))
	return nil, nil //nolint:nilnil // documented miss contract, mirrors CacheService.LookupWithResult
}

func (c *r103Cache) Write(_ context.Context, _ cache.RouteIdentity, promptJSON, _ json.RawMessage, _, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), promptJSON...))
	return nil
}

func (c *r103Cache) recorded() (lookups, writes [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.lookups...), append([][]byte(nil), c.writes...)
}

// r103CompressYAML is the minimal enforce pre_upstream policy carrying the
// builtin/compress mutator (D1: enablement is a policy step — nothing is
// hinted unless an org attaches this policy).
func r103CompressYAML(name, paramsYAML string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: hint\n    mutator: builtin/compress\n" + paramsYAML
}

// r103ChatGateway wires the full chat entry over a DB-backed resolver with
// one anthropic and one openai model, a policy runtime and the recording
// cache.
func r103ChatGateway(t *testing.T, u *r103Upstream, store *fakePolicyStore) (*gateway, *r103Cache) {
	t.Helper()
	db := &rt06ModelDB{rows: map[string][]any{
		"r103-claude": rt06RegistryRow("r103-claude", "anthropic", "EU", u.srv.URL),
		"r103-gpt":    rt06RegistryRow("r103-gpt", "openai", "EU", u.srv.URL),
	}}
	res := resolver.NewResolver(db, "r103-default", time.Minute, slog.New(slog.DiscardHandler))
	gw := streamTestGateway(u.srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	gw.res = res
	gw.fallback = router.NewFallbackExecutor(res, 3, slog.New(slog.DiscardHandler))
	gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	rec := &r103Cache{}
	gw.cache = rec
	return gw, rec
}

func r103AddCompressPolicy(store *fakePolicyStore, paramsYAML string) {
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "r103-hint", OrgID: testOrg, Name: "r103-hint", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r103CompressYAML("r103-hint", paramsYAML)}, []adminstore.PolicyAttachment{chatAttachment(10)})
}

func r103ChatPost(t *testing.T, gw *gateway, model string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"` + model + `","messages":[{"role":"system","content":"You are careful."},{"role":"user","content":"r103 question"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", testOrg)
	r.Header.Set("X-Session-Id", "sess-r103")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// Main scenario at the wire boundary: the opt-in policy step injects the
// native cache_control hint, the mutation reaches the upstream (through the
// OpenAI→Anthropic translate), the cache identity AND the async cache write
// are computed over the MUTATED body (ordering pin: policyPreChat runs before
// serveChatCache), the transparency header reports the provider outcome, the
// provider-reported cache tokens flow into the accounting event (D4/D5), and
// the decision record carries the mandatory hint finding.
func TestR103_CacheHint_Enabled_MutationBeforeCacheAndUpstream(t *testing.T) {
	u := newR103Upstream(t, true)
	store := newFakePolicyStore()
	r103AddCompressPolicy(store, "")
	gw, recCache := r103ChatGateway(t, u, store)
	events := captureEvents(t)

	recorder := r103ChatPost(t, gw, "r103-claude")

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, "hit", recorder.Header().Get(PromptCacheHeader), "provider reported cache_read_input_tokens")

	up := string(u.bodyFor("/v1/messages"))
	require.Contains(t, up, "cache_control", "the hint must reach the anthropic upstream:\n%s", up)
	require.Contains(t, up, "r103 question", "the user text must survive verbatim:\n%s", up)
	require.Contains(t, up, `"ephemeral"`)
	assert.NotContains(t, `"role":"system"`, up, "system stays a top-level anthropic field after translate")

	lookups, writes := recCache.recorded()
	require.Len(t, lookups, 1, "one cache lookup")
	require.Len(t, writes, 1, "one cache write")
	assert.Contains(t, string(lookups[0]), "cache_control",
		"the cache identity must be computed over the POST-policy body (mutation before the cache lookup)")
	assert.Contains(t, string(writes[0]), "cache_control",
		"the cache write must store under the mutated body's identity")

	var completed *struct {
		CacheReadTokens     int64
		CacheCreationTokens int64
		TokensIn            int64
	}
	for _, ev := range events() {
		if ev.EventType != "request.completed" {
			continue
		}
		if completed != nil {
			t.Fatal("more than one completed event")
		}
		completed = &struct {
			CacheReadTokens     int64
			CacheCreationTokens int64
			TokensIn            int64
		}{ev.CacheReadTokens, ev.CacheCreationTokens, ev.TokensIn}
	}
	require.NotNil(t, completed, "the served request must publish its analytics event")
	assert.Equal(t, int64(4), completed.CacheReadTokens, "D5: cache_read_input_tokens must reach the accounting event")
	assert.Equal(t, int64(2), completed.CacheCreationTokens, "D5: cache_creation_input_tokens must reach the accounting event")
	assert.Equal(t, int64(16), completed.TokensIn, "canonical prompt tokens include cache reads and writes")

	// The policy decision record surfaces the applied hint (OP-9).
	foundHint := false
	for _, ev := range events() {
		if ev.EventType != "request.completed" {
			continue
		}
		for _, d := range parseDecisions(t, ev.Policy) {
			for _, f := range d.Findings {
				if strings.Contains(f.Category, "prompt_cache") {
					foundHint = true
				}
			}
		}
	}
	assert.True(t, foundHint, "the decision record must carry the prompt_cache_hint finding")
}

// Off by default and disable-restores-original: without the policy step the
// body crosses to the upstream without any cache_control marker and the
// header reports the provider outcome of the UNhinted request.
func TestR103_CacheHint_Disabled_BodyUntouched(t *testing.T) {
	u := newR103Upstream(t, false)
	gw, _ := r103ChatGateway(t, u, newFakePolicyStore())

	recorder := r103ChatPost(t, gw, "r103-claude")

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, "miss", recorder.Header().Get(PromptCacheHeader))
	up := string(u.bodyFor("/v1/messages"))
	assert.NotContains(t, up, "cache_control", "no policy step — no marker may appear:\n%s", up)
	assert.Contains(t, up, "r103 question", "the body still crosses (translated) with content intact")
}

// D2 provider gate at the wire boundary: the same org policy leaves an
// openai-routed model untouched (implicit caching — nothing to inject).
func TestR103_CacheHint_ProviderGateOpenAIUntouched(t *testing.T) {
	u := newR103Upstream(t, true)
	store := newFakePolicyStore()
	r103AddCompressPolicy(store, "")
	gw, _ := r103ChatGateway(t, u, store)

	recorder := r103ChatPost(t, gw, "r103-gpt")

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	up := string(u.bodyFor("/v1/chat/completions"))
	assert.NotContains(t, up, "cache_control", "openai-routed requests must never carry anthropic markers:\n%s", up)
	assert.Equal(t, "hit", recorder.Header().Get(PromptCacheHeader),
		"the header still reports the provider's own implicit caching outcome")
}

// The native /v1/messages surface (the one place the system target is
// representable): the injected system blocks cross to the upstream verbatim
// with the marker, proving the step's system promotion end-to-end.
func TestR103_CacheHint_NativeMessagesSystemMarked(t *testing.T) {
	u := newR103Upstream(t, false)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "r103-hint", OrgID: testOrg, Name: "r103-hint", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r103CompressYAML("r103-hint", "")}, []adminstore.PolicyAttachment{r017MessagesAttachment(10)})
	gw := nativeMessagesGateway(t, u.srv.URL)
	gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw.log = slog.New(slog.DiscardHandler)

	body := `{"model":"claude-3-5-sonnet","max_tokens":64,"system":"You are careful.","messages":[{"role":"user","content":"r103 native"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	r.Header.Set("X-Org-Id", testOrg)
	rec := httptest.NewRecorder()
	gw.messages(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	up := string(u.bodyFor("/v1/messages"))
	require.Contains(t, up, `"system":[{"cache_control":{"type":"ephemeral"}`, "the system hint must cross natively:\n%s", up)
	require.Contains(t, up, "You are careful.", "the system text must survive verbatim:\n%s", up)
	assert.Contains(t, up, "r103 native")
}

// Ordering pin for the reservation stage: chatCompletions adopts the
// policyPreUpstream body (chat.go:116) and passes that same cc.body into
// reservationRequest (chat.go:131) BEFORE the cache lookup — so the §5.1
// pre-check must estimate the POST-policy (hint-marked) request, not the raw
// client body. The composition is pinned at the exact producer/consumer
// boundary: the byte profile reservationInputProfile computes over the
// mutated body equals the actual mutated request bytes (estimate = actual
// request; the markers carry no base64 payload, so no span is stripped).
func TestR103_MutatedBodyReachesReservationInput(t *testing.T) {
	store := newFakePolicyStore()
	r103AddCompressPolicy(store, "")
	gw := testHookGateway(newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce))

	const body = `{"model":"m","messages":[{"role":"user","content":"price me"}]}`
	w, r := policyRequest(body)
	mutated, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "anthropic", []byte(body))
	require.True(t, ok, "enforce policy with a flag mutator must proceed")
	require.Empty(t, w.Body.String(), "a passing flag mutator answers nothing terminally")
	require.Contains(t, string(mutated), "cache_control", "the hint must be in the adopted body")

	inBytes, images := reservationInputProfile(mutated)
	require.Zero(t, images)
	assert.Equal(t, int64(len(mutated)), inBytes,
		"the reservation estimate must equal the actual (hinted) request bytes")
	assert.NotEqual(t, int64(len(body)), inBytes,
		"the hint markers must move the estimate off the raw client body")
}

// D4 mapping unit contract: hit/miss derive exclusively from the
// provider-reported usage; no provider usage — no header (never fabricated).
func TestR103_PromptCacheOutcome_Mapping(t *testing.T) {
	cases := []struct {
		name string
		u    provider.Usage
		want string
	}{
		{"cache read", provider.Usage{Source: provider.UsageSourceProvider, CacheReadTokens: 1}, "hit"},
		{"no cache read", provider.Usage{Source: provider.UsageSourceProvider}, "miss"},
		{"no usage", provider.Usage{Source: provider.UsageSourceNone}, ""},
	}
	for _, tc := range cases {
		if got := promptCacheOutcome(tc.u); got != tc.want {
			t.Errorf("%s: promptCacheOutcome = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// params is rejected at load (invalid_config) and the enforce runtime answers
// 503 policy_configuration_unavailable — the request never reaches the
// upstream, the cache identity is never computed, and no partially-hinted
// body can exist. Rollback for an operator = detach/disable the policy.
func TestR103_CacheHint_BadStepParams_FailClosedWire(t *testing.T) {
	u := newR103Upstream(t, true)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "r103-bad", OrgID: testOrg, Name: "r103-bad", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r103CompressYAML("r103-bad", "    params:\n      targets:\n        - middle\n")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw, recCache := r103ChatGateway(t, u, store)

	recorder := r103ChatPost(t, gw, "r103-claude")

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code, recorder.Body.String())
	assert.Contains(t, recorder.Body.String(), "policy_configuration_unavailable",
		"the bounded invalid-config code, not a store-outage code")
	assert.Nil(t, u.bodyFor("/v1/messages"), "no upstream call may happen on a failed policy load")
	lookups, _ := recCache.recorded()
	assert.Empty(t, lookups, "no cache identity may be computed")
}

// steps (the stacking an org can build by composing packs) forwards a body
// with exactly ONE marker for the last turn — the second step is a no-op and
// emits no second finding, so Anthropic's four-block cap is never at risk
// from re-runs inside one gateway pass.
func TestR103_CacheHint_StackedStepsSingleMarkerWire(t *testing.T) {
	u := newR103Upstream(t, true)
	store := newFakePolicyStore()
	stacked := "apiVersion: ypp/v1\nkind: Policy\nname: r103-stacked\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n" +
		"  - id: hint1\n    mutator: builtin/compress\n" +
		"  - id: hint2\n    mutator: builtin/compress\n    params:\n      ttl: 1h\n"
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "r103-stacked", OrgID: testOrg, Name: "r103-stacked", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: stacked}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw, _ := r103ChatGateway(t, u, store)
	events := captureEvents(t)

	recorder := r103ChatPost(t, gw, "r103-claude")

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	up := string(u.bodyFor("/v1/messages"))
	require.Contains(t, up, "cache_control", "the first step's hint must reach the upstream:\n%s", up)
	assert.Equal(t, 1, strings.Count(up, `"cache_control"`),
		"stacked steps must leave exactly one marker:\n%s", up)
	assert.NotContains(t, up, `"ttl"`, "the second step must not re-mark with its own ttl:\n%s", up)
	assert.Equal(t, "hit", recorder.Header().Get(PromptCacheHeader))

	hintFindings := 0
	for _, ev := range events() {
		if ev.EventType != "request.completed" {
			continue
		}
		for _, d := range parseDecisions(t, ev.Policy) {
			for _, f := range d.Findings {
				if strings.Contains(f.Category, "prompt_cache") {
					hintFindings++
				}
			}
		}
	}
	assert.Equal(t, 1, hintFindings, "only the applying step reports its hint")
}

// --- N03-P06-T05: savings surfaces and the translation-route hint gate -------

// TestR103_Metrics_CacheReadCounterFollowsProviderUsageOnly pins the metrics
// surface of the savings promise: the gw_upstream_tokens_total{direction=
// "cache_read"} counter moves only when the provider.Usage it is handed
// carries a positive CacheReadTokens — an estimated or absent usage (the
// shapes every estimated-consumption constructor produces, cache fields zero
// by construction) can never move it.
func TestR103_Metrics_CacheReadCounterFollowsProviderUsageOnly(t *testing.T) {
	labels := metrics.UpstreamTokensTotal.WithLabelValues("openai", "t05-metrics-model", "cache_read")
	before := testutil.ToFloat64(labels)

	gw := &gateway{}
	gw.emitUpstreamMetrics("openai", "t05-metrics-model", http.StatusOK, time.Millisecond,
		provider.Usage{PromptTokens: 100, Source: provider.UsageSourceEstimated}, 0)
	assert.InDelta(t, before, testutil.ToFloat64(labels), 1e-9,
		"estimated usage must never move the cache_read counter")

	gw.emitUpstreamMetrics("openai", "t05-metrics-model", http.StatusOK, time.Millisecond,
		provider.Usage{PromptTokens: 100, Source: provider.UsageSourceNone}, 0)
	assert.InDelta(t, before, testutil.ToFloat64(labels), 1e-9,
		"absent usage must never move the cache_read counter")

	gw.emitUpstreamMetrics("openai", "t05-metrics-model", http.StatusOK, time.Millisecond,
		provider.Usage{PromptTokens: 100, CacheReadTokens: 30, Source: provider.UsageSourceProvider}, 0)
	assert.InDelta(t, before+30, testutil.ToFloat64(labels), 1e-9,
		"only provider-reported cache reads may move the cache_read counter")
}

// TestR103_CacheHint_MessagesTranslationToOpenAI_NoMarkerNoPromise pins the
// D2 provider gate on the /v1/messages translation route: the org-wide
// builtin/compress policy is attached, but the serving provider is
// openai-compat, so no cache_control marker may reach the upstream body —
// and the response still reports the honest outcome from that provider's own
// usage (here an implicit-cache "hit" from its reported cached_tokens).
func TestR103_CacheHint_MessagesTranslationToOpenAI_NoMarkerNoPromise(t *testing.T) {
	u := newR103Upstream(t, true)
	store := newFakePolicyStore()
	r103AddCompressPolicy(store, "")
	gw, _ := r103ChatGateway(t, u, store)

	rec := postMessagesForOrg(t, gw, `{"model":"r103-gpt","max_tokens":16,"messages":[{"role":"user","content":"r103 via translation"}]}`, testOrg)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"type":"message"`,
		"the translation path must answer with the anthropic envelope")

	up := string(u.bodyFor("/v1/chat/completions"))
	require.NotEmpty(t, up, "the request must reach the openai upstream")
	assert.NotContains(t, up, "cache_control",
		"builtin/compress is provider-gated: no marker may be injected on an openai-compat serving provider:\n%s", up)
	assert.Contains(t, up, "r103 via translation", "the user text must survive verbatim:\n%s", up)

	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"the outcome follows the serving provider's own reported usage (cached_tokens=4), not the un-injected hint")
}
