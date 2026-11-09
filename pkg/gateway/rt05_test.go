package cli

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// RT-05 regressions: a warm cache entry is only served for the CURRENT route
// after the same policy checks an upstream call passes, and only when the
// entry's provenance (org, route model, namespace version, generation
// parameters) matches the lookup identity. A fallback response is stored
// under the model that actually generated it, never under the primary.
//
// Every test drives the real production handler (chatCompletions /
// serveStream) against httptest upstreams with an in-memory keyed cache
// double that reproduces the production contract (seal on write, open+verify
// on lookup) — the rt01/rt02/rt03 pattern; there is no miniredis in the repo.

// rt05Cache is an in-memory responseCache double keyed by the full route
// identity + prompt hash, storing sealed envelopes exactly like the
// production CacheService stores Redis values. Lookups verify the stored
// provenance against the lookup identity — a mismatch is a miss.
type rt05Cache struct {
	mu      sync.Mutex
	entries map[string][]byte
	lookups int
	writes  int
	lastRI  cache.RouteIdentity
}

func newRT05Cache() *rt05Cache {
	return &rt05Cache{entries: make(map[string][]byte)}
}

func rt05Key(ri cache.RouteIdentity, prompt []byte) string {
	k := ri.Resolved()
	return k.OrgID + "\x1f" + k.Version + "\x1f" + k.Model + "\x1f" + k.GenParams + "\x1f" + cache.ComputePromptHash(prompt)
}

func (c *rt05Cache) LookupWithResult(_ context.Context, ri cache.RouteIdentity, prompt []byte) (*cache.CacheHit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups++
	raw, ok := c.entries[rt05Key(ri, prompt)]
	if !ok {
		return nil, nil //nolint:nilnil // documented miss contract (mirrors CacheService.LookupWithResult)
	}
	prov, data, sealed := cache.OpenEntry(raw)
	if !sealed || !prov.Matches(ri) {
		return nil, nil //nolint:nilnil // documented miss contract (mirrors CacheService.LookupWithResult)
	}
	return &cache.CacheHit{Data: data, SourceType: "exact", Similarity: 1.0, ModelUsed: prov.ModelUsed}, nil
}

func (c *rt05Cache) Write(_ context.Context, ri cache.RouteIdentity, prompt, response json.RawMessage, _, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.lastRI = ri
	sealed, err := cache.SealEntry(response, ri)
	if err != nil {
		return err
	}
	c.entries[rt05Key(ri, prompt)] = sealed
	return nil
}

// seedRaw stores bytes verbatim, bypassing the seal — a pre-RT-05 legacy
// entry (no provenance) at the current key layout.
func (c *rt05Cache) seedRaw(ri cache.RouteIdentity, prompt []byte, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[rt05Key(ri, prompt)] = raw
}

func (c *rt05Cache) lastWrite() cache.RouteIdentity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRI
}

func (c *rt05Cache) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

const rt05CachedDoc = `{"id":"rt05-cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// rt05Gateway returns the standard chat test gateway with the rt05 double.
func rt05Gateway(t *testing.T, u *rt02Upstream) (*gateway, *rt05Cache) {
	t.Helper()
	gw := rt02ChatGateway(t, u, nil)
	c := newRT05Cache()
	gw.cache = c
	return gw, c
}

// rt05PostAs posts a chat completion as the given org (rt02Post is pinned to
// org-a).
func rt05PostAs(t *testing.T, gw *gateway, orgID, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", orgID)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// rt05WarmRI returns the route identity a production lookup derives for the
// given model on this gateway (audit H1): the resolved model info drives the
// same endpoint-revision fingerprint the request path stamps. Test doubles
// warm entries through this so pinned lookups stay hittable; a mismatched or
// omitted component degrades the entry to a miss, exactly like production.
func rt05WarmRI(gw *gateway, orgID, model string) cache.RouteIdentity {
	ri := cache.RouteIdentity{OrgID: orgID, Model: model}
	info, err := gw.resolveModelInfo(context.Background(), model)
	if err != nil {
		return ri
	}
	ri.Upstream = gw.cacheUpstreamFP(info)
	return ri
}

// rt05Warm stores a warm entry for (org-a, model) keyed by the given request
// body. H1: the entry carries the endpoint fingerprint the gateway derives
// for the model, so production lookups still hit it.
func rt05Warm(t *testing.T, gw *gateway, c *rt05Cache, model, body string) {
	t.Helper()
	require.NoError(t, c.Write(context.Background(), rt05WarmRI(gw, "org-a", model),
		[]byte(body), json.RawMessage(rt05CachedDoc), 1, 1))
}

// --- Allowed hit: served without a provider call, honest model used -----------

func TestRT05_Chat_WarmHit_Allowed_JSON_NoProviderCall_ModelUsedCorrect(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	rt05Warm(t, gw, c, "m", `{"model":"m","messages":[{"role":"user","content":"rt05-json"}]}`)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt05-json"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	assert.Contains(t, rec.Body.String(), "from-cache")
	assert.Equal(t, 0, u.totalCalls(), "an allowed cache hit must not touch the provider")

	require.NotNil(t, ev, "cache hit must publish an analytics event")
	assert.Equal(t, "m", ev.ModelUsed, "event model used must match the entry provenance")
	assert.Equal(t, "exact", ev.CacheHitType)
}

func TestRT05_Chat_WarmHit_Allowed_SSEReplay_NoProviderCall(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	// Stream lookups are gated by the W-STCACHE kill-switch; this test
	// exercises the cached-stream replay path, so enable it explicitly.
	gw.cfg.CacheStreamEnabled = true
	rt05Warm(t, gw, c, "m", `{"model":"m","stream":true,"messages":[{"role":"user","content":"rt05-sse"}]}`)

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"rt05-sse"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "from-cache", "SSE replay must carry the cached completion")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	assert.Equal(t, 0, u.totalCalls())
}

// --- Warm cache → deny / policy outage: terminal, never a refetch -------------

func TestRT05_Chat_WarmHit_DeniedRoutedTarget_Terminal403(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02RuleOverrideGateway(t, u, &rt02Access{deny: map[string]bool{"target-a": true}})
	c := newRT05Cache()
	gw.cache = c
	rt05Warm(t, gw, c, "shared-model", `{"model":"shared-model","messages":[{"role":"user","content":"rt05-deny"}]}`)

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt05-deny"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"nothing forbidden may be served from a warm cache")
	assert.Equal(t, 0, u.totalCalls(),
		"a denied warm-cache request must stay terminal — no silent refetch around the policy")
}

func TestRT05_Chat_WarmHit_PolicyStoreError_Terminal503(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02RuleOverrideGateway(t, u, &rt02Access{errFor: map[string]error{"target-a": assert.AnError}})
	c := newRT05Cache()
	gw.cache = c
	rt05Warm(t, gw, c, "shared-model", `{"model":"shared-model","messages":[{"role":"user","content":"rt05-503"}]}`)

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt05-503"}]}`, nil)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "whitelist_check_unavailable", errorType(t, rec))
	assert.NotContains(t, rec.Body.String(), "from-cache")
	assert.Equal(t, 0, u.totalCalls(),
		"a policy error on hit must be the 503 contract, not a quiet miss that refetches")
}

// --- Changed route / residency / alias: the old entry is a miss ---------------

func TestRT05_Chat_ChangedRuleRoute_OldEntryIsMiss(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	rt05Warm(t, gw, c, "shared-model", `{"model":"shared-model","messages":[{"role":"user","content":"rt05-reroute"}]}`)

	// The policy changed: the same request now routes shared-model → target-a.
	gw.res = stubModelResolver{
		"shared-model": {ModelName: "shared-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"target-a":     {ModelName: "target-a", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "target-a")},
	}}
	gw.ruleStore = rulestore.New(db, nil, 0, nil, slog.New(slog.DiscardHandler))

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt05-reroute"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "target-a", u.modelFor("/v1/chat/completions"),
		"the request must follow the CURRENT route to the provider")
	assert.Contains(t, rec.Body.String(), `"content":"ok"`, "the current route's fresh response is served")
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"an entry generated by the old route must not be served under the new one")
}

func TestRT05_Chat_ResidencyRemap_WarmEntryOfOldRoute_IsMiss(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	rt05Warm(t, gw, c, "m", `{"model":"m","messages":[{"role":"user","content":"rt05-residency"}]}`)

	// Residency now remaps m → in-region: the m-keyed entry must not serve.
	gw.res = stubModelResolver{
		"m":         {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"in-region": {ModelName: "in-region", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "in-region"}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt05-residency"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "in-region", u.modelFor("/v1/chat/completions"))
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"a residency remap to another model must miss the old route's entry")
}

func TestRT05_Chat_AliasRetarget_OldEntryNotServedUnderNewTarget(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	// Warm under the CURRENT alias target.
	gw.res = stubModelResolver{
		"alias-x": {ModelName: "target-a", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Alias: "alias-x"},
	}
	rt05Warm(t, gw, c, "target-a", `{"model":"alias-x","messages":[{"role":"user","content":"rt05-alias"}]}`)

	// The alias retargets: alias-x now resolves to target-b.
	gw.res = stubModelResolver{
		"alias-x":  {ModelName: "target-b", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Alias: "alias-x"},
		"target-b": {ModelName: "target-b", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}

	rec := rt02Post(t, gw,
		`{"model":"alias-x","messages":[{"role":"user","content":"rt05-alias"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "target-b", u.modelFor("/v1/chat/completions"),
		"the retargeted alias must resolve to its NEW target at the provider")
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"the old target's entry must not be served under the new alias target")
}

// --- Foreign org / legacy provenance → miss -----------------------------------

func TestRT05_Chat_ForeignOrgEntry_IsMiss(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	rt05Warm(t, gw, c, "m", `{"model":"m","messages":[{"role":"user","content":"rt05-org"}]}`)

	rec := rt05PostAs(t, gw, "org-b",
		`{"model":"m","messages":[{"role":"user","content":"rt05-org"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"org B must never be served org A's entry")
	assert.Equal(t, 1, u.totalCalls(), "a foreign-org entry must miss to the provider")
	assert.Empty(t, rec.Header().Get("X-Cache"), "an upstream-served response carries no cache header")
}

func TestRT05_Chat_LegacyEntryWithoutProvenance_MissAndSafeRefill(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	ri := rt05WarmRI(gw, "org-a", "m")
	body := `{"model":"m","messages":[{"role":"user","content":"rt05-legacy"}]}`

	// A pre-RT-05 entry: raw completion bytes at the current key, no provenance.
	c.seedRaw(ri, []byte(body), []byte(rt05CachedDoc))

	rec := rt02Post(t, gw, body, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, u.totalCalls(), "a legacy entry must miss to the provider (safe refill)")
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.NotContains(t, rec.Body.String(), "from-cache")

	// The refill stored a sealed entry, which the next request serves.
	hit, err := c.LookupWithResult(context.Background(), ri, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, hit, "the refill must store a provenance-carrying entry")
	assert.Equal(t, "m", hit.ModelUsed)

	rec2 := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, "EXACT", rec2.Header().Get("X-Cache"), "the refilled entry is served")
	assert.Equal(t, 1, u.totalCalls(), "the refilled hit must not call the provider again")
}

// --- Fallback attribution: stored and served under the ACTUAL model -----------

func TestRT05_Chat_FallbackResponse_StoredAndServedUnderActualModel(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true, UpstreamAPIKey: "f1-key"},
	}, nil)
	c := newRT05Cache()
	gw.cache = c

	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-f1")
	require.Equal(t, 1, c.writeCount(), "the winning response must be written to the cache")

	// RT-05 core assertion: written under f1 — the model that ACTUALLY
	// responded — never under the primary m1.
	wri := c.lastWrite()
	assert.Equal(t, "f1", wri.Model, "a fallback response must be stored under the actual model")
	assert.Equal(t, "org-a", wri.OrgID)

	body := []byte(rt03ChatBody)
	underFallback, err := c.LookupWithResult(context.Background(),
		rt05WarmRI(gw, "org-a", "f1"), body)
	require.NoError(t, err)
	require.NotNil(t, underFallback, "the entry must be retrievable under the fallback identity")
	assert.Contains(t, string(underFallback.Data), "ok-from-f1")

	underPrimary, err := c.LookupWithResult(context.Background(),
		rt05WarmRI(gw, "org-a", "m1"), body)
	require.NoError(t, err)
	assert.Nil(t, underPrimary, "the fallback response must NOT be retrievable under the primary identity")

	// A second identical request re-routes to m1 (503 again) → f1: the route
	// identity for THIS request is m1, so the f1 entry must not serve before
	// the fresh upstream attempt.
	primaryCalls := primary.totalCalls()
	rec2 := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, primaryCalls+1, primary.totalCalls(),
		"the second request must not be served from the fallback-model entry under the primary route")
}

func TestRT05_Stream_FallbackResponse_StoredUnderActualModel(t *testing.T) {
	// stream.go wrote the captured SSE response under the PRIMARY model —
	// the exact attribution defect this card closes. The write must carry
	// the winning hop's identity.
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	healthy := newRT03Upstream(t, func(rt03Call) rt03Response {
		return rt03Response{ContentType: "text/event-stream", Body: "data: {\"id\":\"fb\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok-from-f1\"}}]}\n\ndata: [DONE]\n\n"}
	})

	gw := streamTestGateway(primary.srv.URL)
	gw.cfg.CacheStreamEnabled = true // the stream write path is kill-switched off by default
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	c := newRT05Cache()
	gw.cache = c

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"rt05-sse-fb"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	gw.serveStream(rec, r.Context(), rt06TestResolve(gw, "m1"), []byte(body), false,
		"sess", "org-a", "", "task", "req", testLogger(), routingDecision{From: "m1"}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-f1")

	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the streamed response must be written to the cache")
	wri := c.lastWrite()
	assert.Equal(t, "f1", wri.Model,
		"the stream cache write must carry the model that ACTUALLY streamed, not the primary")
	assert.Equal(t, "org-a", wri.OrgID)
}

// --- no-store and generation parameters ---------------------------------------

func TestRT05_Chat_NoStore_NeverServedFromCache(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	rt05Warm(t, gw, c, "m", `{"model":"m","messages":[{"role":"user","content":"rt05-nostore"}]}`)

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt05-nostore"}]}`,
		map[string]string{"Cache-Control": "no-store"})

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, u.totalCalls(), "no-store must go upstream")
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.NotContains(t, rec.Body.String(), "from-cache")
}

// --- deny-policy tool_calls must not land in the cache ------------------------

// rt05ToolCallsDoc is an upstream completion declaring two tool calls: shell
// (denied by the org policy in the test below) and calculator (allowed).
const rt05ToolCallsDoc = `{"id":"tc1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"shell","arguments":"{}"}},{"id":"c2","type":"function","function":{"name":"calculator","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

func TestRT05_Chat_DeniedToolCalls_NeverWrittenToCache(t *testing.T) {
	// RT-05 review finding: the cache write ran BEFORE the tool-calls policy
	// gate, so a response whose tool_calls the org policy denies was cached
	// raw — and the warm-hit path (serveChatCache) writes hit.Data to the
	// client verbatim, without re-gating.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rt05ToolCallsDoc))
	}))
	t.Cleanup(srv.Close)

	gw := streamTestGateway(srv.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)
	c := newRT05Cache()
	gw.cache = c

	body := `{"model":"m","messages":[{"role":"user","content":"rt05-toolgat"}]}`

	rec := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), `"shell"`,
		"the client-facing gate must strip the denied call (TOOL-02 premise)")
	assert.Contains(t, rec.Body.String(), "calculator", "the allowed call survives the gate")

	// The stored entry must be the post-gate response: no denied call.
	ri := rt05WarmRI(gw, "org-a", "m")
	hit, err := c.LookupWithResult(context.Background(), ri, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, hit, "the gated response must be cached (allowed tool_calls included)")
	assert.NotContains(t, string(hit.Data), `"shell"`,
		"deny-policy tool_calls must never be written to the cache")
	assert.Contains(t, string(hit.Data), "calculator")

	// Behavioral proof: the warm hit serves the cached entry verbatim, so the
	// cached body itself must already be clean.
	rec2 := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, "EXACT", rec2.Header().Get("X-Cache"), "the gated response must be served from the cache")
	assert.NotContains(t, rec2.Body.String(), `"shell"`,
		"a deny-policy tool_call must not reach the client from a warm hit")
	assert.Contains(t, rec2.Body.String(), "calculator")
}

// rt05WireTierRouting wires the rule-tier classifier + tier router so the
// "Tell me about AI" prompt (medium@0.6) tier-routes m → routed-model.
func rt05WireTierRouting(t *testing.T, gw *gateway, u *rt02Upstream) {
	t.Helper()
	gw.res = stubModelResolver{
		"m":            {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"routed-model": {ModelName: "routed-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, slog.Default())
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "routed-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
	}, nil)
}

func TestRT05_Chat_GenParamsMismatch_OldEntryIsMiss(t *testing.T) {
	// Tier routing picks routed-model for the medium-class prompt; effort
	// routing gives that candidate reasoning_effort=medium on the write side.
	// A reader without effort routing computes different generation
	// parameters → the entry must miss to the provider.
	body := `{"model":"m","messages":[{"role":"user","content":"Tell me about AI"}]}`

	u := newRT02Upstream(t)
	gwWrite, c := rt05Gateway(t, u)
	rt05WireTierRouting(t, gwWrite, u)
	gwWrite.cfg.EffortRoutingEnabled = true
	gwWrite.effortModels = []string{"routed-model"}

	rec := rt02Post(t, gwWrite, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, c.writeCount())
	wri := c.lastWrite()
	assert.Equal(t, "routed-model", wri.Model)
	assert.Equal(t, "medium", wri.GenParams,
		"the write identity must carry the generation parameters actually injected")

	// Same route, but effort routing off → other generation parameters → miss.
	gwRead := rt02ChatGateway(t, u, nil)
	gwRead.cache = c
	rt05WireTierRouting(t, gwRead, u)
	gwRead.cfg.EffortRoutingEnabled = false

	rec2 := rt02Post(t, gwRead, body, nil)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, 2, u.totalCalls(),
		"an entry generated under other reasoning effort must miss to the provider")
	assert.Equal(t, "routed-model", u.modelFor("/v1/chat/completions"))
	require.Eventually(t, func() bool { return c.writeCount() == 2 }, 2*time.Second, 10*time.Millisecond)
	assert.Empty(t, c.lastWrite().GenParams, "the refill carries this route's generation parameters")
}
