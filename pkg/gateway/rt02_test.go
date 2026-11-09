package cli

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

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/evalgate"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// RT-02 regressions: the final canonical candidate — after classifier/tier
// routing, org rule overrides, time-window downgrade, unknown-model fallback
// and residency remap — must pass the shared policy gate BEFORE any upstream
// call, on chat JSON/SSE and on every non-chat endpoint. A denied candidate is
// a terminal 403, an access-check store failure a terminal 503; neither is
// retried, routed around, or answered from a warm cache entry.
//
// Every test drives the real production path (chatCompletions / gw.routes
// handlers) with a mock DB rule store, fake whitelist, stub cache and an
// httptest upstream — the rt01/rt00 pattern, no local lambdas.

// rt02Upstream is a multi-path mock provider: it counts every request and
// records the routed model per path, and answers each endpoint shape.
type rt02Upstream struct {
	mu     sync.Mutex
	calls  int
	models map[string]string // path -> last model
	srv    *httptest.Server
}

func newRT02Upstream(t *testing.T) *rt02Upstream {
	t.Helper()
	u := &rt02Upstream{models: make(map[string]string)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var probe struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(raw, &probe)
		u.mu.Lock()
		u.calls++
		u.models[r.URL.Path] = probe.Model
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/chat/completions" && probe.Stream:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n")
			// H3: a real terminal carries the finish chunk before [DONE] (the
			// canonical fixture shape in chat_opencode_real/evalgate/shadow
			// tests); a fixture without one encodes the truncated-stream shape
			// and can no longer produce a replayable cache entry.
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
		case r.URL.Path == "/v1/chat/completions":
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"` + probe.Model + `","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		case r.URL.Path == "/v1/completions":
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"text_completion","choices":[{"index":0,"text":"ok","finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		case r.URL.Path == "/v1/embeddings":
			_, _ = w.Write([]byte(`{"object":"list","data":[],"model":"` + probe.Model + `","usage":{"prompt_tokens":2,"total_tokens":2}}`))
		case r.URL.Path == "/v1/messages":
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"` + probe.Model + `","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":1}}`))
		case r.URL.Path == "/v1/responses":
			_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","model":"` + probe.Model + `","output":[],"usage":{"input_tokens":2,"output_tokens":1}}`))
		case r.URL.Path == "/v1/messages/count_tokens":
			_, _ = w.Write([]byte(`{"input_tokens":5}`))
		default:
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *rt02Upstream) totalCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func (u *rt02Upstream) modelFor(path string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.models[path]
}

// rt02Access is a selective whitelist double. Unlisted models are allowed
// (the loader's default-allow); deny/err are keyed by the checked model name.
// Every Check call is recorded so tests can assert the trusted identity.
// notify, when set, receives every checked model name (non-blocking), so
// tests can synchronize on the gate evaluation inside detached goroutines.
type rt02Access struct {
	mu     sync.Mutex
	deny   map[string]bool
	errFor map[string]error
	keys   []string
	teams  []string
	models []string
	notify chan string
}

func (a *rt02Access) Check(_ context.Context, apiKeyID, teamID, model string) (bool, error) {
	a.mu.Lock()
	a.keys = append(a.keys, apiKeyID)
	a.teams = append(a.teams, teamID)
	a.models = append(a.models, model)
	deny := a.deny[model]
	err := a.errFor[model]
	a.mu.Unlock()
	if a.notify != nil {
		select {
		case a.notify <- model:
		default:
		}
	}
	if err != nil {
		return false, err
	}
	return !deny, nil
}

func (a *rt02Access) seen() (keys, teams, models []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.keys...), append([]string(nil), a.teams...), append([]string(nil), a.models...)
}

func (a *rt02Access) sawIdentity(forbiddenKey, forbiddenTeam string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.keys {
		if k == forbiddenKey {
			return false
		}
	}
	for _, tm := range a.teams {
		if tm == forbiddenTeam {
			return false
		}
	}
	return true
}

// rt02Cache is a responseCache double with an optional warm entry.
type rt02Cache struct {
	mu      sync.Mutex
	hit     *cache.CacheHit
	lookups int
	writes  int
}

func (c *rt02Cache) LookupWithResult(context.Context, cache.RouteIdentity, []byte) (*cache.CacheHit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups++
	return c.hit, nil
}

func (c *rt02Cache) Write(context.Context, cache.RouteIdentity, json.RawMessage, json.RawMessage, int, int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return nil
}

// rt02TierLoader feeds the tier router a fixed model pool.
type rt02TierLoader []fallbackrouter.ModelInfo

func (l rt02TierLoader) ListModels(context.Context) ([]fallbackrouter.ModelInfo, error) {
	return l, nil
}

func rt02ChatGateway(t *testing.T, u *rt02Upstream, access *rt02Access) *gateway {
	t.Helper()
	gw := streamTestGateway(u.srv.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	if access != nil {
		gw.wl = access
	}
	return gw
}

func rt02Post(t *testing.T, gw *gateway, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-a")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

const rt02CachedDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// --- Allowed → allowed preserves the response (JSON and SSE) -----------------

func TestRT02_Chat_AllowedCandidate_JSON_ResponsePreserved(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt02-json"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.Equal(t, 1, u.totalCalls())
	assert.Equal(t, "m", u.modelFor("/v1/chat/completions"))
}

func TestRT02_Chat_AllowedCandidate_SSE_ResponsePreserved(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"rt02-sse"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"delta"`)
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	assert.Equal(t, 1, u.totalCalls())
}

// --- Routing transformations that produce a denied candidate -----------------

func rt02RuleOverrideGateway(t *testing.T, u *rt02Upstream, access *rt02Access) *gateway {
	t.Helper()
	gw := rt02ChatGateway(t, u, access)
	gw.res = stubModelResolver{
		"shared-model": {ModelName: "shared-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"target-a":     {ModelName: "target-a", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "target-a")},
	}}
	gw.ruleStore = rulestore.New(db, nil, 0, nil, slog.New(slog.DiscardHandler))
	return gw
}

func TestRT02_Chat_RuleOverrideToDeniedTarget_403BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{"target-a": true}}
	gw := rt02RuleOverrideGateway(t, u, access)

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt02-rule-deny"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "permission_denied_error", errorType(t, rec))
	assert.Equal(t, 0, u.totalCalls(), "denied final candidate must never reach upstream")
}

func TestRT02_Chat_RuleOverrideToAllowedTarget_ResponsePreserved(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02RuleOverrideGateway(t, u, &rt02Access{})

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt02-rule-allow"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "target-a", u.modelFor("/v1/chat/completions"),
		"allowed override must keep the existing routing behavior")
}

func TestRT02_Chat_UnknownModelFallbackToDeniedTarget_403BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	// The requested ghost name is whitelisted; the fallback target is NOT.
	// Pre-routing admission checks "ghost" and passes — the gate must stop
	// the request because "fb-model" is what would actually be called.
	access := &rt02Access{deny: map[string]bool{"fb-model": true}}
	gw := rt02ChatGateway(t, u, access)
	gw.res = stubModelResolver{
		"ghost": {ModelName: "fb-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Fallback: true},
	}

	rec := rt02Post(t, gw,
		`{"model":"ghost","messages":[{"role":"user","content":"rt02-fallback-deny"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "permission_denied_error", errorType(t, rec))
	assert.Equal(t, 0, u.totalCalls())
	_, _, models := access.seen()
	assert.Contains(t, models, "ghost", "pre-routing admission still checks the requested name")
	assert.Contains(t, models, "fb-model", "the final gate must re-check the fallback target")
}

func TestRT02_Chat_ResidencyRemapToDeniedTarget_403BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{"in-region": true}}
	gw := rt02ChatGateway(t, u, access)
	gw.res = stubModelResolver{
		"m":         {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"in-region": {ModelName: "in-region", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "in-region"}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt02-remap-deny"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "permission_denied_error", errorType(t, rec))
	assert.Equal(t, 0, u.totalCalls(), "remapped candidate must be gated before upstream")
}

func TestRT02_Chat_ResidencyRemapToAllowedTarget_ResponsePreserved(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.res = stubModelResolver{
		"m":         {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"in-region": {ModelName: "in-region", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "in-region"}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt02-remap-allow"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "in-region", u.modelFor("/v1/chat/completions"))
	assert.Equal(t, "SG", rec.Header().Get("X-Residency-Region"), "residency contract headers preserved")
}

func TestRT02_Chat_FinalCandidateAccessError_503BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	// The requested model checks fine; the store fails exactly on the routed
	// target, so pre-routing admission passes and the FINAL gate hits the
	// outage. Fail-closed: 503, never a forward.
	access := &rt02Access{errFor: map[string]error{"target-a": assert.AnError}}
	gw := rt02RuleOverrideGateway(t, u, access)

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt02-access-err"}]}`, nil)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "whitelist_check_unavailable", errorType(t, rec))
	assert.Equal(t, 0, u.totalCalls(), "a degraded policy store must not be routed around")
}

func TestRT02_Chat_ClassifierRoutedDeniedModel_403AndEvalgateSkipped(t *testing.T) {
	var judgeHits int
	var judgeMu sync.Mutex
	judgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		judgeMu.Lock()
		judgeHits++
		judgeMu.Unlock()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"cheap_quality\":0.4,\"premium_quality\":0.9}"}}]}`))
	}))
	t.Cleanup(judgeSrv.Close)
	store := &fakeVerdictStore{}

	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{"premium-target": true}}
	gw := rt02ChatGateway(t, u, access)
	gw.res = stubModelResolver{
		"m":              {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"premium-target": {ModelName: "premium-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, slog.Default())
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "premium-target", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
	}, nil)
	gw.judge = evalgate.NewJudge(judgeSrv.URL, nil)
	gw.evalStore = store
	gw.cfg.EvalgateSampleRate = 1.0

	// "Tell me about AI" classifies medium@0.60 (>= default threshold 0.6), so
	// tier routing replaces the model; on success the same shape would also be
	// evalgate-sampled (medium + conf < 0.7 + rate 1.0).
	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"Tell me about AI"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, 0, u.totalCalls(), "denied tier-routed candidate must not be called (primary or evalgate premium)")
	judgeMu.Lock()
	defer judgeMu.Unlock()
	assert.Equal(t, 0, judgeHits)
	assert.Equal(t, 0, store.count(), "a denied candidate must never produce an evalgate verdict")
}

func TestRT02_Chat_TimeDowngradeToDeniedTarget_403BeforeUpstream(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{"cheap-target": true}}
	gw := rt02ChatGateway(t, u, access)
	gw.res = stubModelResolver{
		"m":            {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"cheap-target": {ModelName: "cheap-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.timeRoutingEnabled = true
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "cheap-target", Tier: "easy", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}, nil)

	// X-Yabanin-Batch forces the downgrade path regardless of the window.
	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt02-downgrade-deny"}]}`,
		map[string]string{"X-Yabanin-Batch": "true"})

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, 0, u.totalCalls(), "downgraded candidate must be gated before upstream")
}

// --- Warm cache: no response without the executed gate -----------------------

func TestRT02_Chat_WarmCacheHit_Allowed_ServedAfterGate(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(rt02CachedDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"rt02-cache-allow"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	assert.Contains(t, rec.Body.String(), "from-cache")
	assert.Equal(t, 0, u.totalCalls(), "an allowed cache hit must not touch upstream")
}

func TestRT02_Chat_WarmCacheHit_DeniedCandidate_NeverServed(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	// ZAI Coding disabled: the old order ran the ZAI check only AFTER the
	// cache branch, so a warm entry leaked a response with no gate at all.
	// The cache branch now runs the same final gate — 403, no bytes served.
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(rt02CachedDoc), SourceType: "exact", Similarity: 1.0}}
	gw.res = stubModelResolver{
		"glm-x": {ModelName: "glm-x", Provider: "zai-coding", Enabled: true},
	}

	rec := rt02Post(t, gw,
		`{"model":"glm-x","messages":[{"role":"user","content":"rt02-cache-deny"}]}`, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "provider_not_authorized")
	assert.NotContains(t, rec.Body.String(), "from-cache", "a denied candidate must never be served from cache")
	assert.Equal(t, 0, u.totalCalls())
}

func TestRT02_Chat_WarmCacheHit_SSEReplay_AfterGate(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	// Stream lookups are gated by the W-STCACHE kill-switch; this test
	// exercises the cached-stream replay path, so enable it explicitly.
	gw.cfg.CacheStreamEnabled = true
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(rt02CachedDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"rt02-cache-sse"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "from-cache")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	assert.Equal(t, 0, u.totalCalls())
}

// --- Alias behaves identically across chat and every non-chat endpoint ------

type rt02EndpointCase struct {
	name string
	path string
	body string
	// upstreamPath is the mock path a successful call lands on;
	// count_tokens is asserted separately (estimated path never forwards).
	upstreamPath string
}

func rt02RouteGateway(t *testing.T, u *rt02Upstream, access *rt02Access, target resolver.ModelInfo, nativeResponses bool) *gateway {
	t.Helper()
	cfg := config.Gateway{
		AuthMode:      "strict",
		APIKey:        "test-key",
		Provider:      u.srv.URL,
		FallbackModel: "smart",
	}
	if nativeResponses {
		cfg.ResponsesNativeProviders = []string{"openai"}
	}
	gw := &gateway{
		cfg:         cfg,
		log:         slog.New(slog.DiscardHandler),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-a", nil)),
		res:         stubModelResolver{"alias-x": target},
		pool:        upstream.NewPool(upstream.Options{BaseURL: u.srv.URL}),
		fallback:    fallbackrouter.NewFallbackExecutor(stubModelResolver{"alias-x": target}, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1},
	}
	if access != nil {
		gw.wl = access
	}
	return gw
}

func rt02Serve(t *testing.T, gw *gateway, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-key")
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux := chi.NewRouter()
	gw.routes(mux)
	mux.ServeHTTP(rec, r)
	return rec
}

func TestRT02_Alias_UniformBehavior_AllEndpoints(t *testing.T) {
	forwardingCases := []rt02EndpointCase{
		{"chat json", "/v1/chat/completions", `{"model":"alias-x","messages":[{"role":"user","content":"a1"}]}`, "/v1/chat/completions"},
		{"chat sse", "/v1/chat/completions", `{"model":"alias-x","stream":true,"messages":[{"role":"user","content":"a2"}]}`, "/v1/chat/completions"},
		{"completions", "/v1/completions", `{"model":"alias-x","prompt":"hi"}`, "/v1/completions"},
		{"embeddings", "/v1/embeddings", `{"model":"alias-x","input":"hi"}`, "/v1/embeddings"},
		{"responses native", "/v1/responses", `{"model":"alias-x","input":"hi"}`, "/v1/responses"},
		{"messages adapted", "/v1/messages", `{"model":"alias-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "/v1/chat/completions"},
	}
	countBody := `{"model":"alias-x","messages":[{"role":"user","content":"hi"}]}`

	t.Run("openai target", func(t *testing.T) {
		u := newRT02Upstream(t)
		target := resolver.ModelInfo{ModelName: "alias-target", Provider: "openai", UpstreamURL: u.srv.URL, Alias: "alias-x", Enabled: true}

		allowed := rt02RouteGateway(t, u, nil, target, true)
		for _, tc := range forwardingCases {
			rec := rt02Serve(t, allowed, tc.path, tc.body)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", tc.name, rec.Body.String())
			assert.Equal(t, "alias-target", u.modelFor(tc.upstreamPath),
				"%s: upstream must see the canonical alias target", tc.name)
		}
		rec := rt02Serve(t, allowed, "/v1/messages/count_tokens", countBody)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "true", rec.Header().Get("X-Yabanin-Estimated"),
			"count_tokens for a non-anthropic provider stays estimated (no upstream call)")

		denied := rt02RouteGateway(t, u, &rt02Access{deny: map[string]bool{"alias-target": true}}, target, true)
		before := u.totalCalls()
		for _, tc := range forwardingCases {
			rec := rt02Serve(t, denied, tc.path, tc.body)
			require.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", tc.name, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "not allowed", "%s: deny reason preserved", tc.name)
		}
		recCount := rt02Serve(t, denied, "/v1/messages/count_tokens", countBody)
		require.Equal(t, http.StatusForbidden, recCount.Code, recCount.Body.String())
		assert.Equal(t, before, u.totalCalls(), "denied alias must make zero upstream calls across all endpoints")
	})

	t.Run("anthropic target native messages and adapted responses", func(t *testing.T) {
		u := newRT02Upstream(t)
		target := resolver.ModelInfo{ModelName: "alias-native", Provider: "anthropic", UpstreamURL: u.srv.URL, Alias: "alias-x", Enabled: true}
		anthroCases := []rt02EndpointCase{
			// Both flows forward through the anthropic adapter (/v1/messages):
			// native messages directly, adapted responses via the chat path.
			{"messages native", "/v1/messages", `{"model":"alias-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "/v1/messages"},
			{"responses adapted", "/v1/responses", `{"model":"alias-x","input":"hi"}`, "/v1/messages"},
		}

		allowed := rt02RouteGateway(t, u, nil, target, false)
		for _, tc := range anthroCases {
			rec := rt02Serve(t, allowed, tc.path, tc.body)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", tc.name, rec.Body.String())
			assert.Equal(t, "alias-native", u.modelFor(tc.upstreamPath),
				"%s: upstream must see the canonical alias target", tc.name)
		}

		denied := rt02RouteGateway(t, u, &rt02Access{deny: map[string]bool{"alias-native": true}}, target, false)
		before := u.totalCalls()
		for _, tc := range anthroCases {
			rec := rt02Serve(t, denied, tc.path, tc.body)
			require.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", tc.name, rec.Body.String())
		}
		assert.Equal(t, before, u.totalCalls(), "denied alias must make zero upstream calls")
	})
}

// --- Non-chat: unknown-model fallback and access-store outage ----------------

func TestRT02_Completions_UnknownModelFallbackToDeniedTarget_403(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{"fb-model": true}}
	gw := rt02RouteGateway(t, u, access, resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}, false)
	gw.res = stubModelResolver{
		"alias-x": {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"ghost":   {ModelName: "fb-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Fallback: true},
	}

	rec := rt02Serve(t, gw, "/v1/completions", `{"model":"ghost","prompt":"hi"}`)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, 0, u.totalCalls(), "the fallback target must be gated before upstream")
}

func TestRT02_Completions_AccessStoreError_503(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{errFor: map[string]error{"m": assert.AnError}}
	gw := rt02RouteGateway(t, u, access, resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}, false)
	gw.res = stubModelResolver{"alias-x": {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}}

	rec := rt02Serve(t, gw, "/v1/completions", `{"model":"alias-x","prompt":"hi"}`)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, 0, u.totalCalls())
}

// --- Embeddings keep NoRemap --------------------------------------------------

func TestRT02_Embeddings_RemapForbidden_EvenWhenAllowed(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02RouteGateway(t, u, nil, resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}, false)
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "other"}}

	rec := rt02Serve(t, gw, "/v1/embeddings", `{"model":"alias-x","input":"hi"}`)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "residency_policy_violation", errorType(t, rec))
	assert.Equal(t, 0, u.totalCalls(), "embeddings must never be remapped to another model")
}

// --- Spoofed identity headers cannot change the trusted identity -------------

func TestRT02_SpoofedIdentityHeaders_TrustedIdentityWins(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{}
	gw := rt02RouteGateway(t, u, access, resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}, false)
	// The resolved org (org-real) routes to an allowed target; the spoofed
	// org (org-evil) would route to a denied one. The auth middleware strips
	// the client copies before resolving the key.
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-real": {rt02OrgRule("org-real", "real-target")},
		"org-evil": {rt02OrgRule("org-evil", "evil-target")},
	}}
	gw.ruleStore = rulestore.New(db, nil, 0, nil, slog.New(slog.DiscardHandler))
	gw.res = stubModelResolver{
		"alias-x":     {ModelName: "m", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"real-target": {ModelName: "real-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"evil-target": {ModelName: "evil-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-real", nil))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"alias-x","messages":[{"role":"user","content":"rt02-spoof"}]}`))
	r.Header.Set("Authorization", "Bearer test-key")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-evil")
	r.Header.Set("X-Team-Id", "team-evil")
	r.Header.Set("X-API-Key-Id", "key-evil")
	rec := httptest.NewRecorder()
	mux := chi.NewRouter()
	gw.routes(mux)
	mux.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "real-target", u.modelFor("/v1/chat/completions"),
		"routing must use the org resolved by the auth middleware, not the spoofed header")
	u.mu.Lock()
	_, evilCalled := u.models["evil-target"]
	u.mu.Unlock()
	assert.False(t, evilCalled, "the spoofed org's denied target must never be called")
	assert.True(t, access.sawIdentity("key-evil", "team-evil"),
		"whitelist must only ever see the auth middleware's resolved identity")
}

// rt02OrgRule builds an evaluator rule matching the resolved request model.
// The client asks for "alias-x", which resolves to the canonical "m" — the
// evaluator sees the canonical requested model.
func rt02OrgRule(org, target string) evaluator.Rule {
	return evaluator.Rule{
		ID:          "r-" + org,
		OrgID:       org,
		MatchExpr:   `model_requested == "m"`,
		TargetModel: target,
		Priority:    10,
		Enabled:     true,
	}
}
