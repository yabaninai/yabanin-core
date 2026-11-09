package cli

// headers, 429 shaping, fail-open accounting, and the TPM reservation →
// reconcile flow. The Redis-window semantics (exactly-N, shared replicas,
// real correction) live in ratelimit_int_test.go on a real Redis.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// stubRateSource returns fixed per-scope limits.
type stubRateSource struct {
	limits []adminstore.KeyRateScopeLimits
	err    error
}

func (s *stubRateSource) EffectiveKeyRateLimits(context.Context, string, string, string) ([]adminstore.KeyRateScopeLimits, error) {
	return s.limits, s.err
}

// fakeRateScript is a scripted rateLimitScripter: each Eval pops the next
// canned result (or error) and records the call.
type fakeRateScript struct {
	mu      sync.Mutex
	results []interface{}
	errs    []error
	calls   []fakeRateEval
}

type fakeRateEval struct {
	script string
	keys   []string
	args   []interface{}
}

func (f *fakeRateScript) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeRateEval{script: script, keys: keys, args: args})
	cmd := redis.NewCmd(ctx)
	switch {
	case len(f.errs) > 0 && f.errs[0] != nil:
		err := f.errs[0]
		f.errs = f.errs[1:]
		cmd.SetErr(err)
	case len(f.results) > 0:
		res := f.results[0]
		f.results = f.results[1:]
		cmd.SetVal(res)
	default:
		cmd.SetErr(errors.New("fakeRateScript: no canned result"))
	}
	return cmd
}

func (f *fakeRateScript) evalCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// admitResult builds one admit-script-shaped canned result (dimension is the
// binding dimension on a denial: "" allowed / "rpm" / "tpm" / "itpm" / "otpm").
func admitResult(allowed bool, rpmRem, rpmLimit, rpmResetMs, tpmRem, tpmLimit, tpmResetMs, retryMs int64, dimension string) []interface{} {
	allowedV := int64(0)
	if allowed {
		allowedV = 1
	}
	return []interface{}{allowedV, rpmRem, rpmLimit, rpmResetMs, tpmRem, tpmLimit, tpmResetMs, retryMs, dimension}
}

func keyLimit(scope, id string, rpm, tpm *int64) adminstore.KeyRateScopeLimits {
	return adminstore.KeyRateScopeLimits{Scope: scope, SubjectID: id, RPM: rpm, TPM: tpm}
}

func int64ptr(v int64) *int64 { return &v }

func rateLimitTestLogger(buf *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func TestKeyRateLimitsFlagDisabledByDefault(t *testing.T) {
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "")
	assert.False(t, keyRateLimitsFlagEnabled())
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "false")
	assert.False(t, keyRateLimitsFlagEnabled())
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "1")
	assert.True(t, keyRateLimitsFlagEnabled())
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "TRUE")
	assert.True(t, keyRateLimitsFlagEnabled())
}

func TestPlanScopesOrderAndFlags(t *testing.T) {
	limits := []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeOrg, "org-1", int64ptr(100), nil),
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), int64ptr(1000)),
		keyLimit(adminstore.RateLimitScopeTeam, "", int64ptr(50), nil), // empty id never matches
		keyLimit("user", "u1", int64ptr(5), nil),                       // unknown scope ignored
	}
	scopes, rpmOn, tpmOn, itpmOn, otpmOn := planScopes(limits, "key-1", "", "org-1")
	require.Len(t, scopes, 2)
	assert.Equal(t, adminstore.RateLimitScopeKey, scopes[0].scope)
	assert.Equal(t, int64(10), scopes[0].rpm)
	assert.Equal(t, int64(1000), scopes[0].tpm)
	assert.Equal(t, adminstore.RateLimitScopeOrg, scopes[1].scope)
	assert.Equal(t, int64(100), scopes[1].rpm)
	assert.Equal(t, int64(0), scopes[1].tpm)
	assert.True(t, rpmOn)
	assert.True(t, tpmOn)
	assert.False(t, itpmOn, "admin rows never set the split dimensions — org caps only")
	assert.False(t, otpmOn)

	// RPM-only limits leave the TPM dimension off (no body buffering).
	scopes, rpmOn, tpmOn, itpmOn, otpmOn = planScopes(
		[]adminstore.KeyRateScopeLimits{keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), nil)},
		"key-1", "", "")
	require.Len(t, scopes, 1)
	assert.True(t, rpmOn)
	assert.False(t, tpmOn)
	assert.False(t, itpmOn)
	assert.False(t, otpmOn)

	// No identity → no scopes.
	scopes, rpmOn, tpmOn, itpmOn, otpmOn = planScopes(limits, "", "", "")
	assert.Empty(t, scopes)
	assert.False(t, rpmOn)
	assert.False(t, tpmOn)
	assert.False(t, itpmOn)
	assert.False(t, otpmOn)
}

// contextCapturer records what the downstream handler saw.
type contextCapturer struct {
	ctx  context.Context
	body string
}

// runRateLimitedRequest drives one request through the limiter middleware.
func runRateLimitedRequest(t *testing.T, rl *keyRateLimiter, body string, identity map[string]string) (*httptest.ResponseRecorder, *contextCapturer) {
	t.Helper()
	captured := &contextCapturer{}
	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.ctx = r.Context()
		if body != "" {
			got, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			captured.body = string(got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	for k, v := range identity {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, captured
}

func TestMiddlewareAdmitsAndSetsHeaders(t *testing.T) {
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 7, 10, 42000, 800, 1000, 30000, 0, ""),
	}}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), int64ptr(1000)),
	}}, nil)

	rec, captured := runRateLimitedRequest(t, rl, `{"model":"m"}`, map[string]string{
		"X-API-Key-Id": "key-1", "X-Team-Id": "team-1", "X-Org-Id": "org-1",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "10", rec.Header().Get("x-ratelimit-limit-requests"))
	assert.Equal(t, "7", rec.Header().Get("x-ratelimit-remaining-requests"))
	assert.Equal(t, "42s", rec.Header().Get("x-ratelimit-reset-requests"))
	assert.Equal(t, "1000", rec.Header().Get("x-ratelimit-limit-tokens"))
	assert.Equal(t, "800", rec.Header().Get("x-ratelimit-remaining-tokens"))
	assert.Equal(t, "30s", rec.Header().Get("x-ratelimit-reset-tokens"))
	assert.Empty(t, rec.Header().Get("Retry-After"))
	assert.NotNil(t, captured.ctx, "the handler must run")

	// One admit EVAL for the single scoped identity; the body was re-armed
	// and the input estimate reserved.
	require.Equal(t, 1, script.evalCount())
	assert.JSONEq(t, `{"model":"m"}`, captured.body)
	call := script.calls[0]
	require.Len(t, call.keys, 7)
	assert.Equal(t, "gwrl:rpm:key:key-1", call.keys[0])
	assert.Equal(t, "gwrl:tpm:key:key-1", call.keys[1])
	assert.Equal(t, "gwrl:tpmw:key:key-1", call.keys[2])
	assert.Equal(t, "gwrl:itpm:key:key-1", call.keys[3])
	assert.Equal(t, "gwrl:otpm:key:key-1", call.keys[5])
	require.Len(t, call.args, 8)
	assert.Equal(t, 1, call.args[0], "one planned scope")
	assert.Equal(t, rateLimitsWindow.Milliseconds(), call.args[1])
	assert.Equal(t, int64((len(`{"model":"m"}`)+3)/4), call.args[3], "token estimate")
	assert.Equal(t, int64(10), call.args[4], "scope rpm limit")
	assert.Equal(t, int64(1000), call.args[5], "scope tpm limit")
	assert.Equal(t, int64(0), call.args[6], "scope itpm limit (admin rows never set it)")
	assert.Equal(t, int64(0), call.args[7], "scope otpm limit (admin rows never set it)")
}

func TestMiddlewareDeniesWith429(t *testing.T) {
	script := &fakeRateScript{results: []interface{}{
		admitResult(false, -1, 10, 2500, 800, 1000, 30000, 2500, "rpm"),
	}}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), int64ptr(1000)),
	}}, nil)

	before := testutil.ToFloat64(keyRateLimitDeniedTotal.WithLabelValues("rpm"))
	rec, captured := runRateLimitedRequest(t, rl, "", map[string]string{"X-API-Key-Id": "key-1"})
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Empty(t, captured.ctx, "a denied request must not reach the handler")
	assert.Equal(t, "3", rec.Header().Get("Retry-After"), "ceil(2500ms)")
	assert.Equal(t, "10", rec.Header().Get("x-ratelimit-limit-requests"))
	assert.Equal(t, "0", rec.Header().Get("x-ratelimit-remaining-requests"), "clamped at zero")
	assert.InDelta(t, before+1, testutil.ToFloat64(keyRateLimitDeniedTotal.WithLabelValues("rpm")), 0.0001)
	assert.Contains(t, rec.Body.String(), "rate_limit_exceeded")
	assert.Contains(t, rec.Body.String(), "requests per minute")

	// TPM denial reports the token dimension.
	script2 := &fakeRateScript{results: []interface{}{
		admitResult(false, 7, 10, 42000, -5, 1000, 30000, 30000, "tpm"),
	}}
	rl2 := newKeyRateLimiter(script2, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), int64ptr(1000)),
	}}, nil)
	rec2, _ := runRateLimitedRequest(t, rl2, "abcd", map[string]string{"X-API-Key-Id": "key-1"})
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "tokens per minute")
}

func TestMiddlewareNoLimitsPassThrough(t *testing.T) {
	script := &fakeRateScript{}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: nil}, nil)

	rec, captured := runRateLimitedRequest(t, rl, "body", map[string]string{"X-API-Key-Id": "key-1"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, captured.ctx)
	assert.Equal(t, 0, script.evalCount(), "no limits → no Redis traffic")
	assert.Empty(t, rec.Header().Get("x-ratelimit-limit-requests"), "no limits → no headers")
}

func TestMiddlewareNoIdentityPassThrough(t *testing.T) {
	script := &fakeRateScript{}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeOrg, "org-1", int64ptr(1), nil),
	}}, nil)

	rec, captured := runRateLimitedRequest(t, rl, "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, captured.ctx)
	assert.Equal(t, 0, script.evalCount())
}

func TestMiddlewareFailOpenOnRedisError(t *testing.T) {
	script := &fakeRateScript{errs: []error{errors.New("redis down")}}
	logs := &strings.Builder{}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(1), nil),
	}}, rateLimitTestLogger(logs))
	rl.warnEvery = time.Millisecond

	before := testutil.ToFloat64(keyRateLimitFallbackTotal)
	rec, captured := runRateLimitedRequest(t, rl, "", map[string]string{"X-API-Key-Id": "key-1"})
	require.Equal(t, http.StatusOK, rec.Code, "fail-open must admit")
	assert.NotNil(t, captured.ctx)
	assert.Greater(t, testutil.ToFloat64(keyRateLimitFallbackTotal), before, "fallback must be counted")
	assert.Contains(t, logs.String(), "failing open")
	assert.Empty(t, rec.Header().Get("x-ratelimit-limit-requests"), "no fabricated headers on the fallback path")
}

// TestMiddlewareLimitsSourceErrorFailsOpen covers the limits-resolution half
// of the fail-open contract: without the configuration data the limiter
// admits and counts instead of denying.
func TestMiddlewareLimitsSourceErrorFailsOpen(t *testing.T) {
	script := &fakeRateScript{}
	rl := newKeyRateLimiter(script, &stubRateSource{err: errors.New("db down")}, nil)

	before := testutil.ToFloat64(keyRateLimitFallbackTotal)
	rec, captured := runRateLimitedRequest(t, rl, "", map[string]string{"X-API-Key-Id": "key-1"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, captured.ctx)
	assert.Greater(t, testutil.ToFloat64(keyRateLimitFallbackTotal), before)
	assert.Equal(t, 0, script.evalCount())
}

// TestReconcileCorrectsReservation verifies the estimate→fact correction: the
// finish path swaps the reserved input estimate for the actual usage on every
// scope window the request was charged against.
func TestReconcileCorrectsReservation(t *testing.T) {
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 9, 10, 0, 100, 1000, 0, 0, ""),
	}}
	rl := newKeyRateLimiter(script, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(10), int64ptr(1000)),
		keyLimit(adminstore.RateLimitScopeOrg, "org-1", int64ptr(100), int64ptr(10000)),
	}}, nil)

	rec, captured := runRateLimitedRequest(t, rl, strings.Repeat("x", 4000), map[string]string{
		"X-API-Key-Id": "key-1", "X-Org-Id": "org-1",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, script.evalCount())
	require.NotNil(t, captured.ctx)

	// The endpoint finish path corrects the reservation (estimate 1000 →
	// actual 60 = prompt 40 + completion 20).
	reconcileRateLimitUsage(captured.ctx, 40, 20)
	require.Equal(t, 2, script.evalCount())
	call := script.calls[1]
	assert.Contains(t, call.script, "ZSCORE")
	require.Len(t, call.keys, 12, "tpm/itpm/otpm zset+hash per scope")
	assert.Equal(t, "gwrl:tpm:key:key-1", call.keys[0])
	assert.Equal(t, "gwrl:tpmw:key:key-1", call.keys[1])
	assert.Equal(t, "gwrl:itpm:key:key-1", call.keys[2])
	assert.Equal(t, "gwrl:itpmw:key:key-1", call.keys[3])
	assert.Equal(t, "gwrl:otpm:key:key-1", call.keys[4])
	assert.Equal(t, "gwrl:otpmw:key:key-1", call.keys[5])
	assert.Equal(t, "gwrl:tpm:org:org-1", call.keys[6])
	assert.Equal(t, "gwrl:tpmw:org:org-1", call.keys[7])
	require.Len(t, call.args, 5)
	assert.Equal(t, int64(60), call.args[1], "total (prompt + completion)")
	assert.Equal(t, int64(40), call.args[2], "prompt → ITPM window")
	assert.Equal(t, int64(20), call.args[3], "completion → OTPM window")
	assert.Equal(t, 2, call.args[4], "scopes")

	// No reservation (feature off / RPM-only / no identity) → no-op.
	reconcileRateLimitUsage(context.Background(), 40, 20)
	assert.Equal(t, 2, script.evalCount())

	// Same values as the reservation → no-op (nothing changed).
	reconcileRateLimitUsage(captured.ctx, 1000, 0)
	assert.Equal(t, 2, script.evalCount())
}

func TestEstimateRequestTokens(t *testing.T) {
	assert.Equal(t, int64(0), estimateRequestTokens(0))
	assert.Equal(t, int64(1), estimateRequestTokens(3))
	assert.Equal(t, int64(1), estimateRequestTokens(4))
	assert.Equal(t, int64(2), estimateRequestTokens(5))
}

func TestFormatResetSeconds(t *testing.T) {
	assert.Equal(t, "0s", formatResetSeconds(0))
	assert.Equal(t, "1s", formatResetSeconds(1*time.Millisecond))
	assert.Equal(t, "1s", formatResetSeconds(999*time.Millisecond))
	assert.Equal(t, "2s", formatResetSeconds(1500*time.Millisecond))
	assert.Equal(t, "1m0s", formatResetSeconds(60*time.Second))
	assert.Equal(t, "0s", formatResetSeconds(-time.Second))
}

func TestSetRateLimitHeadersOmitAbsentDimensions(t *testing.T) {
	rec := httptest.NewRecorder()
	setRateLimitHeaders(rec, admitDecision{rpmRem: -1, rpmLimit: 0, tpmRem: 5, tpmLimit: 100})
	assert.Empty(t, rec.Header().Get("x-ratelimit-limit-requests"))
	assert.Empty(t, rec.Header().Get("x-ratelimit-remaining-requests"))
	assert.Empty(t, rec.Header().Get("x-ratelimit-reset-requests"))
	assert.Equal(t, "100", rec.Header().Get("x-ratelimit-limit-tokens"))
	assert.Equal(t, "5", rec.Header().Get("x-ratelimit-remaining-tokens"))
}

func TestMemberIsUnique(t *testing.T) {
	rl := newKeyRateLimiter(&fakeRateScript{}, &stubRateSource{}, nil)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		m := rl.member()
		require.False(t, seen[m], "members must be unique")
		seen[m] = true
	}
}

func TestAdmitParsesScriptResult(t *testing.T) {
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 3, 5, 1000, 42, 100, 2000, 0, ""),
	}}
	rl := newKeyRateLimiter(script, &stubRateSource{}, nil)
	dec := rl.admit(context.Background(), []rateLimitScopeRef{
		{scope: "key", id: "k1", rpm: 5, tpm: 100},
	}, 10)
	assert.True(t, dec.allowed)
	assert.Equal(t, int64(3), dec.rpmRem)
	assert.Equal(t, int64(5), dec.rpmLimit)
	assert.Equal(t, time.Second, dec.rpmReset)
	assert.Equal(t, int64(42), dec.tpmRem)
	assert.Equal(t, int64(100), dec.tpmLimit)
	assert.Equal(t, 2*time.Second, dec.tpmReset)
	assert.Empty(t, dec.dimension)
	require.Len(t, script.calls[0].args, 8)
	assert.Equal(t, int64(5), script.calls[0].args[4], "scope rpm limit arg")
	assert.Equal(t, int64(100), script.calls[0].args[5], "scope tpm limit arg")

	// Malformed script output fails open (admitted, no panic).
	script2 := &fakeRateScript{results: []interface{}{"not-an-array"}}
	rl2 := newKeyRateLimiter(script2, &stubRateSource{}, nil)
	before := testutil.ToFloat64(keyRateLimitFallbackTotal)
	dec = rl2.admit(context.Background(), []rateLimitScopeRef{{scope: "key", id: "k1", rpm: 5}}, 0)
	assert.True(t, dec.allowed)
	assert.Greater(t, testutil.ToFloat64(keyRateLimitFallbackTotal), before)
}

func TestRateLimitScopeKeyNamespacing(t *testing.T) {
	ref := rateLimitScopeRef{scope: "team", id: "t-1"}
	assert.Equal(t, "gwrl:rpm:team:t-1", ref.rpmZSet())
	assert.Equal(t, "gwrl:tpm:team:t-1", ref.tpmZSet())
	assert.Equal(t, "gwrl:tpmw:team:t-1", ref.tpmHash())
	assert.Equal(t, "gwrl:itpm:team:t-1", ref.itpmZSet())
	assert.Equal(t, "gwrl:itpmw:team:t-1", ref.itpmHash())
	assert.Equal(t, "gwrl:otpm:team:t-1", ref.otpmZSet())
	assert.Equal(t, "gwrl:otpmw:team:t-1", ref.otpmHash())
}
