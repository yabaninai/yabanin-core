package cli

// RT-07 end-to-end routing matrix. The per-card fixes (RT-01..RT-06) each have
// focused regressions; this file combines their dimensions into single flows
// through the REAL production handlers (chatCompletions / serveStream /
// gw.routes), a mock provider, a mock DB rule store and an in-memory cache
// double that reproduces the production seal/open contract — no local lambdas.
//
// Matrix coverage per test:
//
//	Identity      1  (org A/B interleave + same session ID + key/team + cache/affinity isolation)
//	Selection     2,3 (rule → time downgrade → residency remap; unknown-model policy)
//	Policy        4  (allowed → denied → lookup error, policy change after warm cache)
//	Execution     7  (permitted fallback, denied fallback SSE, cancel between hops)
//	Payload/cache 5,6 (guard + vertical + unknown fields, guarded cache input, exact/semantic, no-store)
//	Attribution   2,3,6,7 (requested/selected/used distinct and consistent end to end)
//	Endpoints     8  (allowed happy path for every endpoint, native and adapted)

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
)

// rt07Upstream is a mock provider recording the routed model per request
// marker (first message content). Its usage carries enough cached tokens for
// the success path to record session affinity (≥ minTokens).
type rt07Upstream struct {
	mu     sync.Mutex
	models map[string]string
	calls  int
	srv    *httptest.Server
}

func newRT07Upstream(t *testing.T) *rt07Upstream {
	t.Helper()
	u := &rt07Upstream{models: make(map[string]string)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Content interface{} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		marker := "unknown"
		if len(body.Messages) > 0 {
			if s, ok := body.Messages[0].Content.(string); ok {
				marker = s
			}
		}
		u.mu.Lock()
		u.models[marker] = body.Model
		u.calls++
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"` + body.Model +
			`","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":600,"completion_tokens":1,"total_tokens":601,"prompt_tokens_details":{"cached_tokens":600}}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *rt07Upstream) modelFor(marker string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.models[marker]
}

func (u *rt07Upstream) totalCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// rt07IdentityGateway wires the full chat pipeline for the identity matrix:
// real rule store over the mock DB, per-request snapshot evaluation, org+team
// scoped session affinity and the sealed in-memory cache double.
func rt07IdentityGateway(t *testing.T, u *rt07Upstream, access *rt02Access, rules map[string][]evaluator.Rule) (*gateway, *rt05Cache) {
	t.Helper()
	gw := streamTestGateway(u.srv.URL)
	gw.retryPolicy.MaxAttempts = 1
	gw.res = stubModelResolver{
		"shared-model": {ModelName: "shared-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"target-a":     {ModelName: "target-a", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"target-b":     {ModelName: "target-b", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.wl = access
	gw.ruleStore = rulestore.New(&rt01RuleDB{rules: rules}, nil, 0, nil, slog.New(slog.DiscardHandler))
	gw.sessionAffinity = fallbackrouter.NewSessionAffinity(0, 0, 0)
	c := newRT05Cache()
	gw.cache = c
	return gw, c
}

// TestRT07_Matrix_Identity_OrgAB_SameSession_RulesCacheAffinity: one shared
// session ID, two organizations, simultaneously. Each org's rules snapshot and
// sticky affinity stay isolated (RT-01), and a warm cache entry of org A is
// never served to org B (RT-05 route identity).
func TestRT07_Matrix_Identity_OrgAB_SameSession_RulesCacheAffinity(t *testing.T) {
	const session = "sess-shared"
	rules := map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "target-a")},
		"org-b": {rt01Rule("org-b", "target-b")},
	}

	t.Run("concurrent same-session requests keep per-org rules and affinity", func(t *testing.T) {
		u := newRT07Upstream(t)
		gw, _ := rt07IdentityGateway(t, u, &rt02Access{}, rules)

		// Rebuild the rule store with a barrier so both orgs load rules
		// simultaneously (the original shared-snapshot bypass only reproduces
		// under interleave). The cache stays OFF: every iteration must walk
		// the rule pipeline to the provider.
		barrierDB := &rt01RuleDB{rules: rules}
		gw.ruleStore = rulestore.New(barrierDB, nil, 0, nil, slog.New(slog.DiscardHandler))
		gw.cache = nil

		fire := func(org, marker string) *httptest.ResponseRecorder {
			body := `{"model":"shared-model","messages":[{"role":"user","content":"` + marker + `"}]}`
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"/v1/chat/completions", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Org-Id", org)
			r.Header.Set("X-Session-Id", session)
			rec := httptest.NewRecorder()
			gw.chatCompletions(rec, r)
			return rec
		}

		for i := 0; i < 50; i++ {
			barrierDB.mu.Lock()
			barrierDB.barrier = &sync.WaitGroup{}
			barrierDB.barrier.Add(2)
			barrierDB.mu.Unlock()

			var wg sync.WaitGroup
			var recA, recB *httptest.ResponseRecorder
			wg.Add(2)
			go func() { defer wg.Done(); recA = fire("org-a", "rt07-id-rules-a") }()
			go func() { defer wg.Done(); recB = fire("org-b", "rt07-id-rules-b") }()
			wg.Wait()

			require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
			require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
			assert.Equal(t, "target-a", u.modelFor("rt07-id-rules-a"),
				"iteration %d: org A must land on its own rule target", i)
			assert.Equal(t, "target-b", u.modelFor("rt07-id-rules-b"),
				"iteration %d: org B must land on its own rule target", i)
			if t.Failed() {
				return
			}
		}

		// Same session ID recorded under BOTH orgs — the sticky entry of one
		// org must never surface for the other (production affinity store).
		ctx := context.Background()
		assert.Equal(t, "target-a", gw.sessionAffinity.Preferred(ctx, "org-a", session))
		assert.Equal(t, "target-b", gw.sessionAffinity.Preferred(ctx, "org-b", session))
		assert.Equal(t, 100, u.totalCalls(), "every interleave iteration sends both orgs to the provider")
	})

	t.Run("warm entry of org A is never served to org B", func(t *testing.T) {
		u := newRT07Upstream(t)
		gw, c := rt07IdentityGateway(t, u, &rt02Access{}, map[string][]evaluator.Rule{
			"org-a": {},
			"org-b": {},
		})
		body := `{"model":"shared-model","messages":[{"role":"user","content":"rt07-id-cache"}]}`
		require.NoError(t, c.Write(context.Background(), rt05WarmRI(gw, "org-a", "shared-model"),
			[]byte(body), json.RawMessage(`{"id":"a","object":"chat.completion","model":"shared-model","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache-a"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`), 1, 1))

		recA := rt05PostAs(t, gw, "org-a", body, map[string]string{"X-Session-Id": session})
		require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
		assert.Equal(t, "EXACT", recA.Header().Get("X-Cache"))
		assert.Contains(t, recA.Body.String(), "from-cache-a")

		// Org B, same session, byte-identical body: the entry is org-scoped.
		recB := rt05PostAs(t, gw, "org-b", body, map[string]string{"X-Session-Id": session})
		require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
		assert.NotContains(t, recB.Body.String(), "from-cache-a", "org B must never be served org A's entry")
		assert.Empty(t, recB.Header().Get("X-Cache"))
		assert.Equal(t, "shared-model", u.modelFor("rt07-id-cache"),
			"org B's identical request must reach the provider under its own identity")
	})
}

// TestRT07_Matrix_Selection_RuleThenDowngradeThenRemap_AllowedChain: one
// allowed request walks the full selection pipeline — org rule override, then
// time-window downgrade, then residency remap — and the final candidate is the
// one actually called, with requested/used attribution intact end to end.
func TestRT07_Matrix_Selection_RuleThenDowngradeThenRemap_AllowedChain(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.res = stubModelResolver{
		"shared-model": {ModelName: "shared-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"mid-model":    {ModelName: "mid-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"cheap-target": {ModelName: "cheap-target", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"in-region":    {ModelName: "in-region", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.ruleStore = rulestore.New(&rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "mid-model")},
	}}, nil, 0, nil, slog.New(slog.DiscardHandler))
	gw.timeRoutingEnabled = true
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "cheap-target", Tier: "easy", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}, nil)
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "in-region"}}

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := rt02Post(t, gw,
		`{"model":"shared-model","messages":[{"role":"user","content":"rt07-chain"}]}`,
		map[string]string{"X-Yabanin-Batch": "true"})

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "in-region", u.modelFor("/v1/chat/completions"),
		"the final remapped candidate is what reaches the provider")
	assert.Equal(t, "SG", rec.Header().Get("X-Residency-Region"))
	require.NotNil(t, ev)
	assert.Equal(t, "shared-model", ev.ModelRequested, "the event keeps the canonical requested model")
	assert.Equal(t, "in-region", ev.ModelUsed, "the event carries the candidate that actually served")
	assert.NotEqual(t, ev.ModelRequested, ev.ModelUsed, "requested and used must stay distinguishable")
}

// TestRT07_Matrix_UnknownModelPolicy_AttributedFallbackOrReject: the RM-09
// unknown-model contract end to end — the configured fallback candidate serves
// under its own name (fallback header + honest attribution), or the reject
// policy stops the request before routing.
func TestRT07_Matrix_UnknownModelPolicy_AttributedFallbackOrReject(t *testing.T) {
	t.Run("fallback policy serves and attributes the fallback candidate", func(t *testing.T) {
		u := newRT02Upstream(t)
		gw := rt02ChatGateway(t, u, &rt02Access{})
		gw.res = stubModelResolver{
			"ghost": {ModelName: "fb-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Fallback: true},
		}

		var evMu sync.Mutex
		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) {
			if e.EventType != "request.completed" {
				return
			}
			evMu.Lock()
			defer evMu.Unlock()
			ev = e
		})
		defer restore()

		rec := rt02Post(t, gw, `{"model":"ghost","messages":[{"role":"user","content":"rt07-ghost"}]}`, nil)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "ghost->fb-model", rec.Header().Get("X-Yabanin-Model-Fallback"))
		assert.Equal(t, "fb-model", u.modelFor("/v1/chat/completions"))
		evMu.Lock()
		completed := ev
		evMu.Unlock()
		require.NotNil(t, completed)
		assert.Equal(t, "fb-model", completed.ModelUsed)
		assert.Equal(t, "fb-model", completed.ModelRequested,
			"the event keeps the canonical pre-routing model; the client's ghost name stays on the fallback header")
	})

	t.Run("reject policy stops unknown models before any routing", func(t *testing.T) {
		u := newRT02Upstream(t)
		gw := rt02ChatGateway(t, u, &rt02Access{})
		gw.unknownModelPolicy = "reject"
		gw.res = stubModelResolver{
			"ghost": {ModelName: "fb-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true, Fallback: true},
		}

		var evMu sync.Mutex
		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) {
			if e.EventType != "request.invalid" {
				return
			}
			evMu.Lock()
			defer evMu.Unlock()
			ev = e
		})
		defer restore()

		rec := rt02Post(t, gw, `{"model":"ghost","messages":[{"role":"user","content":"rt07-ghost-reject"}]}`, nil)

		require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
		assert.Equal(t, "not_found_error", errorType(t, rec))
		assert.Contains(t, rec.Body.String(), "model_not_found")
		assert.Equal(t, 0, u.totalCalls())
		evMu.Lock()
		invalid := ev
		evMu.Unlock()
		require.NotNil(t, invalid)
		assert.Equal(t, "request.invalid", invalid.EventType)
		assert.Equal(t, "ghost", invalid.ModelRequested)
	})
}

// TestRT07_Matrix_PolicyChange_AfterWarmCache_AllowThenDenyThenError: the same
// warm entry is served while the policy allows it, becomes a terminal 403 the
// moment the policy denies the route, and a terminal 503 on a policy-store
// lookup error — a warm cache never outranks the current policy.
func TestRT07_Matrix_PolicyChange_AfterWarmCache_AllowThenDenyThenError(t *testing.T) {
	u := newRT02Upstream(t)
	access := &rt02Access{deny: map[string]bool{}, errFor: map[string]error{}}
	gw := rt02ChatGateway(t, u, access)
	c := newRT05Cache()
	gw.cache = c
	rt05Warm(t, gw, c, "m", `{"model":"m","messages":[{"role":"user","content":"rt07-policy"}]}`)
	body := `{"model":"m","messages":[{"role":"user","content":"rt07-policy"}]}`

	rec := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	assert.Contains(t, rec.Body.String(), "from-cache")
	require.Equal(t, 0, u.totalCalls())

	access.mu.Lock()
	access.deny["m"] = true
	access.mu.Unlock()
	rec = rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"a warm entry must not survive a policy that now denies the route")
	assert.Equal(t, 0, u.totalCalls(), "a denied warm-cache request stays terminal — no refetch")

	access.mu.Lock()
	access.deny["m"] = false
	access.errFor["m"] = assert.AnError
	access.mu.Unlock()
	rec = rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "whitelist_check_unavailable", errorType(t, rec))
	assert.NotContains(t, rec.Body.String(), "from-cache")
	assert.Equal(t, 0, u.totalCalls(), "a degraded policy store must not fall back to the cache")
}

// TestRT07_Matrix_GuardVertical_CacheInputGuarded_NoStoreNeverWritten: guard
// redaction + vertical masking + unknown fields survive to the provider, the
// cache key is the actual guarded+masked payload (RT-04), and a no-store
// request is neither served from nor written to the cache (JSON and SSE).
func TestRT07_Matrix_GuardVertical_CacheInputGuarded_NoStoreNeverWritten(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		var probe struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))
	gw.cfg.CacheStreamEnabled = true // the stream write path is kill-switched off by default
	c := newRT05Cache()
	gw.cache = c

	withSecret := func(seed byte) string {
		// Synthetic OpenAI-style key assembled at runtime: the guard detector
		// sees the full literal, while the source keeps no scanner-shaped
		// credential text. All values are fake.
		key := "sk-" + strings.Repeat(string(seed), 20)
		return `{"model":"gpt-4o-mini","messages":[{"role":"system","content":"system context ` + key + `","x_custom_msg":"msg-keep"},{"role":"user","content":"please process patient-record"}],"stream":false,"my_custom_field":"keep-me","tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]}`
	}

	// 1) Secret S1 goes upstream masked and guarded, unknown fields intact.
	rec := rt05PostAs(t, gw, "org-1", withSecret('a'), nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, cap.count())
	rt04AssertGuardedMaskedPayload(t, cap.last())
	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the guarded response must be written to the cache")

	// 2) A different secret redacts to the same guarded payload → EXACT hit:
	// the cache key is the guarded body, not the raw request bytes.
	rec = rt05PostAs(t, gw, "org-1", withSecret('z'), nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"),
		"two requests whose guarded payloads coincide must share the cache entry")
	assert.Equal(t, 1, cap.count(), "the hit must not touch the provider")

	// 3) no-store JSON: served fresh, and — the RT-07 leftover — NOT written.
	rec = rt05PostAs(t, gw, "org-1", withSecret('q'),
		map[string]string{"Cache-Control": "no-store"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get("X-Cache"))
	assert.Equal(t, 2, cap.count())
	assert.Equal(t, 1, c.writeCount(), "a no-store response must never be written to the cache")

	// 4) no-store SSE: same contract on the streaming write path.
	sseBody := strings.Replace(withSecret('w'), `"stream":false`, `"stream":true`, 1)
	rec = rt05PostAs(t, gw, "org-1", sseBody, map[string]string{"Cache-Control": "no-store"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "data: ")
	assert.Equal(t, 3, cap.count())
	assert.Equal(t, 1, c.writeCount(), "a no-store stream must never be recorded for the cache")

	// 5) A streaming request without no-store DOES record under the guarded
	// payload — proving the guard above is the no-store branch, not a broken
	// recording path.
	streamBody := strings.Replace(withSecret('b'), `"stream":false`, `"stream":true`, 1)
	rec = rt05PostAs(t, gw, "org-1", streamBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Eventually(t, func() bool { return c.writeCount() == 2 }, 2*time.Second, 10*time.Millisecond,
		"the recorded stream write proves the no-store skips are selective, not a dead path")
}

// rt07SemanticCache re-labels hits as semantic sources so the handler's
// semantic-hit surface (headers + event) is exercised end to end.
type rt07SemanticCache struct{ *rt05Cache }

func (c *rt07SemanticCache) LookupWithResult(ctx context.Context, ri cache.RouteIdentity, prompt []byte) (*cache.CacheHit, error) {
	hit, err := c.rt05Cache.LookupWithResult(ctx, ri, prompt)
	if err != nil || hit == nil {
		return hit, err
	}
	hit.SourceType = "semantic"
	hit.Similarity = 0.92
	return hit, nil
}

// TestRT07_Matrix_CacheHit_SemanticSource_HeadersAndEventConsistent: a
// semantic-provenance hit is served with the SEMANTIC header/similarity and
// the event attributes it to the model that generated the entry.
func TestRT07_Matrix_CacheHit_SemanticSource_HeadersAndEventConsistent(t *testing.T) {
	u := newRT02Upstream(t)
	gw, c := rt05Gateway(t, u)
	gw.cache = &rt07SemanticCache{rt05Cache: c}
	body := `{"model":"m","messages":[{"role":"user","content":"rt07-semantic"}]}`
	rt05Warm(t, gw, c, "m", body)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := rt02Post(t, gw, body, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "SEMANTIC", rec.Header().Get("X-Cache"))
	assert.Equal(t, "0.9200", rec.Header().Get("X-Cache-Similarity"))
	assert.Contains(t, rec.Body.String(), "from-cache")
	assert.Equal(t, 0, u.totalCalls())
	require.NotNil(t, ev)
	assert.Equal(t, "semantic", ev.CacheHitType)
	assert.Equal(t, "m", ev.ModelUsed, "the hit event must attribute the entry's provenance model")
}

// TestRT07_Matrix_Fallback_AttributionAndCacheIdentity_AndDeniedSSE:
//   - a permitted fallback is attributed to the winning candidate and stored
//     under its identity; the next request re-routes (never serves the fallback
//     entry under the primary route);
//   - a denied fallback on a streaming request is a structured SSE error before
//     the first content frame, and a warm entry of the denied target is not served;
//   - a cancel between hops stops the chain with zero further attempts.
func TestRT07_Matrix_Fallback_AttributionAndCacheIdentity_AndDeniedSSE(t *testing.T) {
	t.Run("permitted fallback: winning-candidate attribution + route identity", func(t *testing.T) {
		primary, healthy := rt03Pair(t)
		gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
			"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
			"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true, UpstreamAPIKey: "f1-key"},
		}, &rt02Access{})
		c := newRT05Cache()
		gw.cache = c

		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) { ev = e })
		defer restore()

		rec := rt02Post(t, gw, rt03ChatBody, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "ok-from-f1")
		require.NotNil(t, ev)
		assert.Equal(t, "m1", ev.ModelRequested)
		assert.Equal(t, "f1", ev.ModelUsed, "the event must carry the candidate that actually served")
		require.Equal(t, 1, c.writeCount())
		assert.Equal(t, "f1", c.lastWrite().Model, "the response must be stored under the winning model")

		// The next identical request routes as m1 again — the f1 entry must
		// not be served under the m1 route identity.
		rec = rt02Post(t, gw, rt03ChatBody, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, 2, primary.totalCalls(),
			"the fallback entry must never serve under the primary's route identity")
	})

	t.Run("denied fallback on SSE: structured error before first frame, warm entry of denied target not served", func(t *testing.T) {
		primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
		healthy := newRT03Upstream(t, func(rt03Call) rt03Response {
			return rt03Response{ContentType: "text/event-stream", Body: "data: {\"id\":\"fb\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok-from-f1\"}}]}\n\ndata: [DONE]\n\n"}
		})
		gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
			"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
			"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
		}, &rt02Access{deny: map[string]bool{"f1": true}})
		c := newRT05Cache()
		gw.cache = c
		// A warm entry for the DENIED target exists (route identity f1) — it
		// must never be served, and the fallback hop must not run.
		require.NoError(t, c.Write(context.Background(), cache.RouteIdentity{OrgID: "org-a", Model: "f1"},
			[]byte(rt03ChatBody), json.RawMessage(rt05CachedDoc), 1, 1))

		rec := rt02Post(t, gw, `{"model":"m1","stream":true,"messages":[{"role":"user","content":"rt03"}]}`, nil)

		out := rec.Body.String()
		assert.Contains(t, out, "permission_denied_error",
			"the policy denial must surface as a structured SSE error frame")
		assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"))
		assert.NotContains(t, out, "delta", "no content frames may precede or follow the denial")
		assert.NotContains(t, out, "from-cache", "the denied target's warm entry must not be served")
		assert.Equal(t, 0, healthy.totalCalls(), "a denied fallback candidate is never called")
	})

	t.Run("cancel between hops: zero further attempts", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		primary := newRT03Upstream(t, func(rt03Call) rt03Response {
			cancel()
			return rt03Down()
		})
		healthy := newRT03Upstream(t, nil)
		gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
			"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
			"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true, UpstreamAPIKey: "f1-key"},
		}, &rt02Access{})

		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(rt03ChatBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Org-Id", "org-a")
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)

		assert.NotEqual(t, http.StatusOK, rec.Code)
		assert.Equal(t, 1, primary.totalCalls())
		assert.Equal(t, 0, healthy.totalCalls(), "a canceled request makes zero further attempts")
	})
}

// TestRT07_Matrix_EndpointHappyPaths_AllEndpoints: one allowed request per
// endpoint through the real mux (auth middleware included), native and adapted,
// each reaching the provider under the canonical model. count_tokens stays
// estimated for non-anthropic providers and passes through for anthropic.
func TestRT07_Matrix_EndpointHappyPaths_AllEndpoints(t *testing.T) {
	t.Run("openai target", func(t *testing.T) {
		u := newRT02Upstream(t)
		target := resolver.ModelInfo{ModelName: "target-o", Provider: "openai", UpstreamURL: u.srv.URL, Alias: "alias-x", Enabled: true}
		gw := rt02RouteGateway(t, u, &rt02Access{}, target, true)

		cases := []rt02EndpointCase{
			{"chat json", "/v1/chat/completions", `{"model":"alias-x","messages":[{"role":"user","content":"rt07-ep-1"}]}`, "/v1/chat/completions"},
			{"chat sse", "/v1/chat/completions", `{"model":"alias-x","stream":true,"messages":[{"role":"user","content":"rt07-ep-2"}]}`, "/v1/chat/completions"},
			{"completions", "/v1/completions", `{"model":"alias-x","prompt":"hi"}`, "/v1/completions"},
			{"embeddings", "/v1/embeddings", `{"model":"alias-x","input":"hi"}`, "/v1/embeddings"},
			{"responses native", "/v1/responses", `{"model":"alias-x","input":"hi"}`, "/v1/responses"},
			{"messages adapted", "/v1/messages", `{"model":"alias-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "/v1/chat/completions"},
		}
		for _, tc := range cases {
			rec := rt02Serve(t, gw, tc.path, tc.body)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", tc.name, rec.Body.String())
			assert.Equal(t, "target-o", u.modelFor(tc.upstreamPath), "%s: canonical model upstream", tc.name)
		}
		rec := rt02Serve(t, gw, "/v1/messages/count_tokens", `{"model":"alias-x","messages":[{"role":"user","content":"hi"}]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "true", rec.Header().Get("X-Yabanin-Estimated"),
			"count_tokens for a non-anthropic provider stays estimated")
		assert.Equal(t, 6, u.totalCalls(), "estimated count_tokens must not call the provider")
	})

	t.Run("anthropic target native messages, adapted responses, count_tokens passthrough", func(t *testing.T) {
		u := newRT02Upstream(t)
		target := resolver.ModelInfo{ModelName: "target-a", Provider: "anthropic", UpstreamURL: u.srv.URL, Alias: "alias-x", Enabled: true}
		gw := rt02RouteGateway(t, u, &rt02Access{}, target, false)

		cases := []rt02EndpointCase{
			{"messages native", "/v1/messages", `{"model":"alias-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "/v1/messages"},
			{"responses adapted", "/v1/responses", `{"model":"alias-x","input":"hi"}`, "/v1/messages"},
		}
		for _, tc := range cases {
			rec := rt02Serve(t, gw, tc.path, tc.body)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", tc.name, rec.Body.String())
			assert.Equal(t, "target-a", u.modelFor(tc.upstreamPath), "%s: canonical model upstream", tc.name)
		}
		rec := rt02Serve(t, gw, "/v1/messages/count_tokens", `{"model":"alias-x","messages":[{"role":"user","content":"hi"}]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, rec.Header().Get("X-Yabanin-Estimated"),
			"anthropic count_tokens passes through to the provider")
		assert.Equal(t, "target-a", u.modelFor("/v1/messages/count_tokens"),
			"the passthrough must reach the provider under the canonical model")
	})
}
