package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
)

// RT-03 regressions: every actual provider attempt — primary, fallback hop or
// optional secondary call (shadow target, evalgate premium) — passes the
// shared policy gate under the request's trusted identity. A denied or
// unavailable outcome is terminal: the transport fallback must not route
// around it, the next hop is never started, and candidate data (URL, adapter,
// credentials, timeout) comes from the candidate's own ModelInfo, never from
// the previous hop.
//
// Every test drives the real production path (chatCompletions with real
// retry/fallback machinery) against httptest upstream fixtures — the
// rt01/rt02 pattern.

// rt03Call is one recorded upstream hit.
type rt03Call struct {
	Auth  string // Authorization header as received
	Model string // model field of the request body
	Path  string
}

// rt03Response is the canned upstream answer.
type rt03Response struct {
	Status      int
	ContentType string
	Body        string
	Sleep       time.Duration // delay before answering (timeout fixtures)
}

// rt03Upstream is a mock provider fixture recording every call. Every request
// also signals hit (non-blocking; nil until a test opts in), so tests can
// synchronize on the call instead of polling.
type rt03Upstream struct {
	mu    sync.Mutex
	calls []rt03Call
	srv   *httptest.Server
	hit   chan struct{}
}

// waitHit waits (bounded) for one upstream request to land.
func (u *rt03Upstream) waitHit(t *testing.T) {
	t.Helper()
	if u.hit == nil {
		t.Fatal("waitHit on an upstream without a hit channel")
	}
	select {
	case <-u.hit:
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream never received the expected call")
	}
}

func newRT03Upstream(t *testing.T, respond func(call rt03Call) rt03Response) *rt03Upstream {
	t.Helper()
	u := &rt03Upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var probe struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &probe)
		call := rt03Call{Auth: r.Header.Get("Authorization"), Model: probe.Model, Path: r.URL.Path}
		u.mu.Lock()
		u.calls = append(u.calls, call)
		u.mu.Unlock()
		select {
		case u.hit <- struct{}{}:
		default:
		}

		res := rt03Response{Status: http.StatusOK, ContentType: "application/json"}
		if respond != nil {
			res = respond(call)
		}
		if res.Status == 0 {
			res.Status = http.StatusOK
		}
		if res.Body == "" {
			res.Body = `{"id":"cmpl","object":"chat.completion","model":"` + probe.Model +
				`","choices":[{"index":0,"message":{"role":"assistant","content":"ok-from-` + probe.Model +
				`"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
		}
		if res.Sleep > 0 {
			time.Sleep(res.Sleep)
		}
		if res.ContentType != "" {
			w.Header().Set("Content-Type", res.ContentType)
		}
		w.WriteHeader(res.Status)
		_, _ = io.WriteString(w, res.Body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *rt03Upstream) totalCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *rt03Upstream) callAt(i int) rt03Call {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls[i]
}

// rt03Gateway builds the real chat path over two upstream fixtures:
// baseURL is the primary's URL (cfg.Provider), resolvers maps model names to
// per-candidate ModelInfo (own URL/key/timeout each), access is the whitelist.
func rt03Gateway(t *testing.T, baseURL string, resolvers stubModelResolver, access *rt02Access) *gateway {
	t.Helper()
	gw := streamTestGateway(baseURL)
	gw.res = resolvers
	gw.fallback = fallbackrouter.NewFallbackExecutor(resolvers, 3, nil)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	if access != nil {
		gw.wl = access
	}
	return gw
}

func rt03Down() rt03Response {
	return rt03Response{Status: 503, Body: "upstream error 503: overloaded"}
}

// rt03Pair returns a 503 primary fixture and a healthy candidate fixture.
func rt03Pair(t *testing.T) (*rt03Upstream, *rt03Upstream) {
	t.Helper()
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	healthy := newRT03Upstream(t, nil)
	return primary, healthy
}

const rt03ChatBody = `{"model":"m1","messages":[{"role":"user","content":"rt03"}]}`

// --- 503 primary → allowed fallback succeeds ---------------------------------

func TestRT03_Chat_Primary503_AllowedFallbackSucceeds(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true, UpstreamAPIKey: "f1-key"},
	}, &rt02Access{})

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-f1", "the winning candidate's response is served")
	assert.Equal(t, 1, primary.totalCalls())
	assert.Equal(t, 1, healthy.totalCalls())
	assert.Equal(t, "f1", healthy.callAt(0).Model)
	assert.Equal(t, "Bearer f1-key", healthy.callAt(0).Auth,
		"the fallback hop must authenticate with its own candidate key")
	assert.Equal(t, "Bearer test-key", primary.callAt(0).Auth,
		"the primary uses the documented global default when it has no per-model key")
}

// --- Candidate data comes from mi, not from the previous hop ------------------

func TestRT03_Chat_PrimaryKeyNeverReachesSecondUpstream(t *testing.T) {
	// Two different provider/URL fixtures: the primary carries a per-model
	// key, the fallback candidate carries none. The candidate must get the
	// documented GLOBAL default key only — never the primary's credential.
	primary, healthy := rt03Pair(t)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, UpstreamAPIKey: "primary-secret", Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, &rt02Access{})

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "Bearer primary-secret", primary.callAt(0).Auth)
	require.Equal(t, 1, healthy.totalCalls())
	assert.NotEqual(t, "Bearer primary-secret", healthy.callAt(0).Auth,
		"the primary's key must never leak to the other provider/URL fixture")
	assert.Equal(t, "Bearer test-key", healthy.callAt(0).Auth,
		"an empty candidate key falls back to the global default only")
}

func TestRT03_Chat_TimeoutComesFromCandidateNotPrimary(t *testing.T) {
	t.Run("short candidate timeout fails the hop", func(t *testing.T) {
		primary, _ := rt03Pair(t)
		// Healthy fixture, but slower than the candidate's own timeout.
		healthy := newRT03Upstream(t, func(rt03Call) rt03Response {
			return rt03Response{Sleep: 800 * time.Millisecond}
		})
		gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
			// Primary timeout is huge: if the code inherited it, the hop
			// would succeed despite the candidate's own short timeout.
			"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, UpstreamTimeout: 30 * time.Second, Enabled: true, FailoverModels: []string{"f1"}},
			"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, UpstreamTimeout: 60 * time.Millisecond, Enabled: true},
		}, &rt02Access{})

		rec := rt02Post(t, gw, rt03ChatBody, nil)

		assert.NotEqual(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, 1, healthy.totalCalls(), "the candidate was attempted exactly once")
	})

	t.Run("candidate timeout accommodates a legitimate slow upstream", func(t *testing.T) {
		primary, _ := rt03Pair(t)
		healthy := newRT03Upstream(t, func(rt03Call) rt03Response {
			return rt03Response{Sleep: 200 * time.Millisecond}
		})
		gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
			"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
			"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, UpstreamTimeout: 10 * time.Second, Enabled: true},
		}, &rt02Access{})

		rec := rt02Post(t, gw, rt03ChatBody, nil)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "ok-from-f1")
	})
}

// --- Denied / unavailable fallback is terminal --------------------------------

func TestRT03_Chat_DeniedFallback_Terminal403_JSON(t *testing.T) {
	primary, healthy := rt03Pair(t)
	access := &rt02Access{deny: map[string]bool{"f1": true}}
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, access)

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "permission_denied_error", errorType(t, rec))
	assert.Equal(t, 1, primary.totalCalls(), "the allowed primary was attempted")
	assert.Equal(t, 0, healthy.totalCalls(), "a denied fallback candidate is never called")
	_, _, models := access.seen()
	assert.Contains(t, models, "f1", "the fallback hop entered the gate before any transport call")
}

func TestRT03_Chat_DeniedFallback_StructuredSSEErrorBeforeFirstFrame(t *testing.T) {
	primary, healthy := rt03Pair(t)
	access := &rt02Access{deny: map[string]bool{"f1": true}}
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, access)

	rec := rt02Post(t, gw, `{"model":"m1","stream":true,"messages":[{"role":"user","content":"rt03-sse"}]}`, nil)

	body := rec.Body.String()
	assert.Contains(t, body, "permission_denied_error", "structured policy error before the first frame")
	assert.NotContains(t, body, `"delta"`, "no stream content may be produced by a denied candidate")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"), body)
	assert.Equal(t, 0, healthy.totalCalls(), "the forbidden next stream call is never started")
	assert.Equal(t, 1, primary.totalCalls())
}

func TestRT03_Chat_PolicyStoreOutage_FallbackNotPermitted_Terminal503(t *testing.T) {
	primary, healthy := rt03Pair(t)
	access := &rt02Access{errFor: map[string]error{"f1": assert.AnError}}
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, access)

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "whitelist_check_unavailable", errorType(t, rec))
	assert.Equal(t, 0, healthy.totalCalls(), "a degraded policy store must not permit the fallback")
}

func TestRT03_Chat_ForeignRegionFallback_Terminal403(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Region: "US", Enabled: true},
	}, &rt02Access{})
	gw.residencyEnforcer = rt03Residency{denyModel: "f1"}

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "residency_policy_violation", errorType(t, rec))
	assert.Equal(t, 1, primary.totalCalls())
	assert.Equal(t, 0, healthy.totalCalls(), "a foreign-region fallback candidate is never called")
}

// rt03Residency denies one model by name (the fallback hop), allows the rest.
type rt03Residency struct{ denyModel string }

func (f rt03Residency) Enforce(_ context.Context, _, model string, region policy.Region, _ string) policy.Decision {
	if model == f.denyModel {
		return policy.Decision{Allowed: false, Region: region, Reason: "model not available in the pinned region"}
	}
	return policy.Decision{Allowed: true, Region: "SG"}
}

// --- Unknown failover entry: gated, not transport-retried ----------------------

func TestRT03_Chat_UnknownFailoverEntry_NotExecutedWithoutGate(t *testing.T) {
	primary, healthy := rt03Pair(t)
	// ghost-x is unknown; the resolver maps it to the registry fallback
	// model, which the key is NOT allowed to call. The outcome must be the
	// policy denial — never a transport attempt against the unknown target.
	access := &rt02Access{deny: map[string]bool{"fb-model": true}}
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1":      {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"ghost-x"}},
		"ghost-x": {ModelName: "fb-model", Fallback: true, Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, access)

	rec := rt02Post(t, gw, rt03ChatBody, nil)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "permission_denied_error", errorType(t, rec))
	assert.Equal(t, 0, healthy.totalCalls(), "the unknown entry resolved to a denied candidate — no transport call")
	_, _, models := access.seen()
	assert.Contains(t, models, "fb-model", "the unknown entry was evaluated by the gate, not skipped silently")
}

// --- Cancellation between hops ------------------------------------------------

func TestRT03_Chat_CancelBetweenHops_ZeroNextAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	primary := newRT03Upstream(t, func(rt03Call) rt03Response {
		cancel() // client disconnects while the primary hop is failing
		return rt03Down()
	})
	healthy := newRT03Upstream(t, nil)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, &rt02Access{})

	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(rt03ChatBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-a")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, primary.totalCalls())
	assert.Equal(t, 0, healthy.totalCalls(), "a canceled request makes zero further attempts")
}

// --- Spend admission is not repeated per hop -----------------------------------

type rt03BudgetCounter struct {
	mu     sync.Mutex
	checks int
}

func (b *rt03BudgetCounter) CheckBudget(context.Context, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checks++
	return nil
}

func (b *rt03BudgetCounter) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checks
}

func TestRT03_Chat_BudgetCheckedOncePerRequest_AcrossHops(t *testing.T) {
	primary, healthy := rt03Pair(t)
	budget := &rt03BudgetCounter{}
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, &rt02Access{})
	gw.budgetEnforcer = budget

	rec := rt02Post(t, gw, rt03ChatBody, map[string]string{"X-Team-Id": "team-1"})

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 2, primary.totalCalls()+healthy.totalCalls(), "two hops were taken")
	assert.Equal(t, 1, budget.count(), "spend admission runs once per request, not per hop")
}

// --- Evalgate premium comparison is gated --------------------------------------

func TestRT03_Evalgate_PremiumDenied_NoCallNoVerdict(t *testing.T) {
	var judgeHits int32
	judgeSrv, judgeHit, _ := judgeHitServer(t, &judgeHits)
	store := newFakeVerdictStore()

	primaryOK := newRT03Upstream(t, nil) // primary answers 200 with a comparable text answer
	premium := newRT03Upstream(t, nil)
	premium.hit = make(chan struct{}, 4)
	gw := evalgateTestGateway(t, primaryOK.srv.URL, judgeSrv.URL, store)
	gw.res = stubModelResolver{
		"gpt-4o-mini":    {ModelName: "gpt-4o-mini", Provider: "openai", UpstreamURL: primaryOK.srv.URL, Enabled: true},
		"premium-target": {ModelName: "premium-target", Provider: "openai", UpstreamURL: premium.srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)
	// The medium pool holds the primary model itself (tier routing keeps it),
	// the hard pool holds the premium target so the sampling pair is
	// cheap(gpt-4o-mini) vs premium(premium-target).
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "gpt-4o-mini", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "premium-target", Tier: "hard", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}, nil)
	access := &rt02Access{
		deny:   map[string]bool{"premium-target": true},
		notify: make(chan string, 4),
	}
	gw.wl = access

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// The premium gate runs inside the detached judge goroutine: wait until
	// the gate has evaluated the premium candidate — the goroutine's last
	// checkpoint before it must bail. This keeps the test non-vacuous (the
	// sampling path really ran) without sleeping on hope.
	for settled := false; !settled; {
		select {
		case m := <-access.notify:
			settled = m == "premium-target"
		case <-time.After(2 * time.Second):
			t.Fatal("the detached judge goroutine never reached the premium gate")
		}
	}
	// Post-gate actions are immediate, so a gate bypass would call the
	// premium upstream (and then the judge, then the store) right away; the
	// bounded negative window fails fast on such a regression.
	select {
	case <-premium.hit:
		t.Fatal("a denied premium target makes no provider call")
	case <-judgeHit:
		t.Fatal("a denied premium target makes no judge call")
	case <-store.calls:
		t.Fatal("a denied premium target produces no verdict")
	case <-time.After(250 * time.Millisecond):
	}
	assert.Equal(t, int32(0), judgeHits, "a denied premium target makes no judge call")
	assert.Equal(t, 0, store.count(), "a denied premium target produces no verdict")
	assert.Equal(t, 0, premium.totalCalls(), "the premium upstream is never called")
}

func TestRT03_Evalgate_PremiumAllowed_VerdictStillProduced(t *testing.T) {
	var judgeHits int32
	judgeSrv, _, _ := judgeHitServer(t, &judgeHits)
	store := newFakeVerdictStore()

	primaryOK := newRT03Upstream(t, nil)
	premium := newRT03Upstream(t, nil)
	gw := evalgateTestGateway(t, primaryOK.srv.URL, judgeSrv.URL, store)
	gw.res = stubModelResolver{
		"gpt-4o-mini":    {ModelName: "gpt-4o-mini", Provider: "openai", UpstreamURL: primaryOK.srv.URL, Enabled: true},
		"premium-target": {ModelName: "premium-target", Provider: "openai", UpstreamURL: premium.srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "gpt-4o-mini", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "premium-target", Tier: "hard", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}, nil)
	gw.wl = &rt02Access{} // premium target allowed

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	store.waitForVerdicts(t, 1)
	assert.Equal(t, int32(1), judgeHits)
	assert.Equal(t, 1, store.count(), "the allowed premium comparison keeps producing verdicts")
	assert.Equal(t, 1, premium.totalCalls(), "the premium upstream is called once")
	assert.Equal(t, "premium-target", premium.callAt(0).Model)
}

// --- Shadow target is gated -----------------------------------------------------

func rt03ShadowGateway(t *testing.T, primaryURL, shadowURL string) *gateway {
	t.Helper()
	gw := shadowTestGateway(t, primaryURL, shadowURL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	return gw
}

func TestRT03_Shadow_DeniedCandidate_NoShadowCall(t *testing.T) {
	primary := newRT03Upstream(t, nil)  // primary answers 200
	shadowed := newRT03Upstream(t, nil) // shadow target
	gw := rt03ShadowGateway(t, primary.srv.URL, shadowed.srv.URL)
	gw.wl = &rt02Access{deny: map[string]bool{"gpt-4o": true}} // shadow candidate denied

	body := nonStreamBody("gpt-4o-mini", "rt03-shadow-deny")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// The shadow gate (fireShadow) runs synchronously in the request path and
	// returns before any goroutine is spawned when the candidate is denied —
	// once chatCompletions has returned, no shadow call can ever be made.
	assert.Equal(t, 0, shadowed.totalCalls(), "a denied shadow candidate makes no call")
}

func TestRT03_Shadow_AllowedCandidate_StillMirrored(t *testing.T) {
	primary := newRT03Upstream(t, nil)
	shadowed := newRT03Upstream(t, nil)
	shadowed.hit = make(chan struct{}, 1)
	gw := rt03ShadowGateway(t, primary.srv.URL, shadowed.srv.URL)
	gw.wl = &rt02Access{}
	completed := make(chan struct{}, 1)
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.shadow_completed" && e.OrgID == "rt03-shadow-allow-org" {
			select {
			case completed <- struct{}{}:
			default:
			}
		}
	})
	defer restore()

	body := nonStreamBody("gpt-4o-mini", "rt03-shadow-allow")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "rt03-shadow-allow-org")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// The detached shadow goroutine signals through the shadow target's hit
	// channel — no polling.
	shadowed.waitHit(t)
	// An upstream hit precedes response parsing and event publication. Wait for
	// completion so this detached job cannot call the next test's observer.
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("shadow completion event was not published")
	}
	assert.Equal(t, 1, shadowed.totalCalls(), "an allowed shadow candidate keeps mirroring")
	assert.Equal(t, "gpt-4o", shadowed.callAt(0).Model)
	assert.Equal(t, "Bearer shadow-key", shadowed.callAt(0).Auth,
		"the shadow call keeps its own documented credential contract")
}
