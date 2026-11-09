package cli

// W-CAPS acceptance coverage for the org-caps enforcement layer: RPM/TPM
// over-limit answers 429 with Retry-After, the hard monthly budget answers
// 402 budget_exceeded, a Redis outage in enforce mode fails CLOSED (503)
// while shadow mode passes, key-level windows bind before org-level, and the
// enforced caps are the requesting org's own (never another org's overrides).
// The Redis window semantics live in ratelimit_int_test.go on a real Redis.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
)

// stubCapsSource maps org → caps/spend/webhook, simulating the store's
// per-org scoping: an org only ever resolves its own row.
type stubCapsSource struct {
	caps   map[string]*adminstore.EffectiveOrgCaps
	spend  map[string]int64
	target map[string]adminstore.OrgAlertTarget
	err    error
}

func (s *stubCapsSource) EffectiveOrgCaps(_ context.Context, orgID string) (*adminstore.EffectiveOrgCaps, error) {
	if s.err != nil {
		return nil, s.err
	}
	if c, ok := s.caps[orgID]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
}

func (s *stubCapsSource) OrgMonthSpendCents(context.Context, string) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.spend[""], nil
}

func (s *stubCapsSource) OrgAlertTarget(_ context.Context, orgID string) (adminstore.OrgAlertTarget, error) {
	if t, ok := s.target[orgID]; ok {
		return t, nil
	}
	return adminstore.OrgAlertTarget{}, nil
}

func betaCaps(orgID string) *adminstore.EffectiveOrgCaps {
	return &adminstore.EffectiveOrgCaps{
		OrgID: orgID, RPM: 60, TPM: 200_000, MonthlyBudgetCents: 5_000_000,
	}
}

// capsTestLimiter builds a keyRateLimiter with the caps layer enforcing (or
// shadow) over the given fake Redis and stub source. Key-level limits are
// empty — the caps layer must work standalone.
func capsTestLimiter(script rateLimitScripter, src *stubCapsSource, mode string) *keyRateLimiter {
	rl := newKeyRateLimiter(script, &stubRateSource{}, rateLimitTestLogger(&strings.Builder{}))
	rl.caps = newOrgCapsEnforcer(script, src, mode, rateLimitTestLogger(&strings.Builder{}))
	return rl
}

// capsRequest runs one request through the middleware with the org identity
// header and returns the recorder.
func capsRequest(t *testing.T, rl *keyRateLimiter, orgID string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Org-Id", orgID)
	req.Header.Set("X-API-Key-Id", "key-1")
	rec := httptest.NewRecorder()
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	return rec
}

func metricValue(t *testing.T, counter *prometheus.CounterVec, kind string) float64 {
	t.Helper()
	return testutil.ToFloat64(counter.WithLabelValues(kind))
}

func TestOrgCapsModeEnv(t *testing.T) {
	t.Setenv("YABANIN_ORG_CAPS", "")
	assert.Equal(t, config.OrgCapsOff, config.OrgCapsMode())
	t.Setenv("YABANIN_ORG_CAPS", "nonsense")
	assert.Equal(t, config.OrgCapsOff, config.OrgCapsMode(), "unknown values degrade to off")
	t.Setenv("YABANIN_ORG_CAPS", "shadow")
	assert.Equal(t, config.OrgCapsShadow, config.OrgCapsMode())
	t.Setenv("YABANIN_ORG_CAPS", " ENFORCE ")
	assert.Equal(t, config.OrgCapsEnforce, config.OrgCapsMode())
}

func TestOrgCapsRPMExceededAnswers429WithRetryAfter(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 1, 60, 0, -1, 200000, 0, 0, ""),              // request 1 admitted
		admitResult(false, -1, 60, 30000, -1, 200000, 0, 30000, "rpm"), // request 2: rpm exhausted
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())
	retryAfter, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Equal(t, 30, retryAfter)
	assert.Equal(t, "60", rec.Header().Get("x-ratelimit-limit-requests"))
	assert.Contains(t, rec.Body.String(), "rate_limit_exceeded")
	assert.Contains(t, rec.Body.String(), "requests per minute (RPM)")
}

func TestOrgCapsTPMExceededAnswers429TPMDimension(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(false, -1, 60, 0, -1, 200000, 5000, 5000, "tpm"), // tpm exhausted
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	// A ~40KB body estimates ~10k tokens against the 200k TPM window.
	rec := capsRequest(t, rl, "org-1", strings.Repeat("x", 40_000))
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "200000", rec.Header().Get("x-ratelimit-limit-tokens"))
	assert.Contains(t, rec.Body.String(), "tokens per minute (TPM)")
}

func TestOrgCapsBudgetExceededAnswers402(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"), // $50 budget
	}, spend: map[string]int64{"": 5_100_000}} // $51k cents spent
	script := &fakeRateScript{}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusPaymentRequired, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "budget_exceeded")
	assert.Equal(t, 0, script.evalCount(),
		"the budget denial must short-circuit before any Redis window work")
}

func TestOrgCapsBudgetWebhookFiresToOwnerTarget(t *testing.T) {
	src := &stubCapsSource{
		caps:  map[string]*adminstore.EffectiveOrgCaps{"org-1": betaCaps("org-1")},
		spend: map[string]int64{"": 5_000_000},
		target: map[string]adminstore.OrgAlertTarget{
			// The spend-alert webhook the org already configured is REUSED
			// (empty here = nothing configured = honest no-op). Loopback
			// delivery targets are blocked by the SSRF dialer by design, so
			// the delivery contract itself is pinned by the adminstore unit
			// tests; this test pins that the async notify never blocks or
			// fails the 402 denial path.
			"org-1": {Name: "Org One", WebhookURL: ""},
		},
	}
	rl := capsTestLimiter(&fakeRateScript{}, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusPaymentRequired, rec.Code)
	rec = capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusPaymentRequired, rec.Code)
}

func TestOrgCapsRedisDownEnforceFailsClosed(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{errs: []error{errors.New("redis down")}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	before := metricValue(t, orgCapsDeniedTotal, orgCapsKindDependency)
	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "body: %s", rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Greater(t, metricValue(t, orgCapsDeniedTotal, orgCapsKindDependency), before,
		"enforce mode must count the fail-closed denial")
}

func TestOrgCapsSourceDownEnforceFailsClosed(t *testing.T) {
	src := &stubCapsSource{err: errors.New("db down")}
	rl := capsTestLimiter(&fakeRateScript{}, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "body: %s", rec.Body.String())
}

func TestOrgCapsShadowNeverDenies(t *testing.T) {
	t.Run("redis down passes", func(t *testing.T) {
		src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
			"org-1": betaCaps("org-1"),
		}, spend: map[string]int64{"": 0}}
		script := &fakeRateScript{errs: []error{errors.New("redis down")}}
		rl := capsTestLimiter(script, src, config.OrgCapsShadow)

		before := metricValue(t, orgCapsWouldDenyTotal, orgCapsKindDependency)
		rec := capsRequest(t, rl, "org-1", `{}`)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Greater(t, metricValue(t, orgCapsWouldDenyTotal, orgCapsKindDependency), before)
	})

	t.Run("over budget passes but is counted", func(t *testing.T) {
		src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
			"org-1": betaCaps("org-1"),
		}, spend: map[string]int64{"": 6_000_000}}
		rl := capsTestLimiter(&fakeRateScript{}, src, config.OrgCapsShadow)

		before := metricValue(t, orgCapsWouldDenyTotal, orgCapsKindBudget)
		rec := capsRequest(t, rl, "org-1", `{}`)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Greater(t, metricValue(t, orgCapsWouldDenyTotal, orgCapsKindBudget), before)
	})
}

func TestOrgCapsKeyLevelBindsBeforeOrgLevel(t *testing.T) {
	// Key-level rows exist AND org caps apply: the caps scope must ride the
	// SAME atomic script AFTER the key scope (card ordering), so one denial
	// names the binding scope deterministically.
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(false, -1, 5, 0, -1, 0, 0, 1000, "rpm"), // key window exhausted
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)
	rl.source = &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(5), nil),
	}}

	rec := capsRequest(t, rl, "org-1", `{}`)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())

	require.Equal(t, 1, script.evalCount())
	call := script.calls[0]
	require.GreaterOrEqual(t, len(call.keys), 14, "key scope + caps scope windows expected (7 keys each)")
	assert.Contains(t, call.keys[0], "gwrl:rpm:key:key-1", "key-level window first")
	last := call.keys[len(call.keys)-7:]
	assert.Contains(t, last[0], "gwrl:rpm:orgcaps:org-1", "org-caps window last")
	assert.Contains(t, last[1], "gwrl:tpm:orgcaps:org-1")
	assert.Contains(t, last[2], "gwrl:tpmw:orgcaps:org-1")
	assert.Contains(t, last[3], "gwrl:itpm:orgcaps:org-1")
	assert.Contains(t, last[5], "gwrl:otpm:orgcaps:org-1")
	// Per-scope limits ride ARGV after the 4 header args (scope 1 = key:
	// args[4..7] rpm/tpm/itpm/otpm; scope 2 = caps: args[8..11]).
	assert.Equal(t, int64(5), call.args[4], "key-level rpm")
	assert.Equal(t, int64(0), call.args[5], "key-level tpm (unset)")
	assert.Equal(t, int64(0), call.args[6], "key-level itpm (admin rows never set it)")
	assert.Equal(t, int64(60), call.args[8], "org caps rpm (beta default)")
	assert.Equal(t, int64(200000), call.args[9], "org caps tpm (beta default)")
}

func TestOrgCapsAppliesRequestingOrgsOwnCaps(t *testing.T) {
	// org-1 holds a raised override; a request identifying org-2 must be
	// measured against org-2's OWN defaults — another org's caps are never
	// visible through the caps source.
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": {OrgID: "org-1", RPM: 5000, TPM: 900_000, MonthlyBudgetCents: 99_000_000},
		"org-2": betaCaps("org-2"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{admitResult(true, 59, 60, 0, -1, 200000, 0, 0, "")}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-2", `{}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, script.evalCount())
	call := script.calls[0]
	assert.Equal(t, int64(60), call.args[4], "org-2 is enforced at ITS defaults, not org-1's override")
	assert.Equal(t, int64(200000), call.args[5])
	assert.Equal(t, "60", rec.Header().Get("x-ratelimit-limit-requests"))
}

func TestOrgCapsNoIdentityPassesThrough(t *testing.T) {
	rl := capsTestLimiter(&fakeRateScript{}, &stubCapsSource{}, config.OrgCapsEnforce)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "static-key modes stay out of the caps path")
}

func TestOrgCapsReconcileCoversCapsWindow(t *testing.T) {
	// The caps scope participates in the token reconcile: the reservation
	// records it, so the post-response correction rewrites the caps windows
	// exactly like the admin-configured scopes.
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": betaCaps("org-1"),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 59, 60, 0, 199000, 200000, 0, 0, ""),
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	var ctx context.Context
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Org-Id", "org-1")
	req.Header.Set("X-API-Key-Id", "key-1")
	rec := httptest.NewRecorder()
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	tr, _ := ctx.Value(tokenReconcileCtxKey{}).(*tokenReservation)
	require.NotNil(t, tr, "a TPM-windowing request must carry the reconcile handle")
	require.Len(t, tr.scopes, 1)
	assert.Equal(t, "orgcaps", tr.scopes[0].scope)
	assert.Equal(t, "org-1", tr.scopes[0].id)

	script.results = []interface{}{int64(1)}
	reconcileRateLimitUsage(ctx, 1000, 234)
	require.Equal(t, 2, script.evalCount())
	reconcile := script.calls[1]
	assert.Contains(t, reconcile.keys[0], "gwrl:tpm:orgcaps:org-1")
}
