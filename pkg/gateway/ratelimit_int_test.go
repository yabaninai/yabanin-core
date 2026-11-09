//go:build integration

package cli

// acceptance scenarios — exactly-N concurrent admissions, the limit shared
// across replicas, TPM corrected to the actual usage, fail-open with the
// fallback metric when Redis dies.

import (
	"context"
	"fmt"
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
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
)

func keyRLRedisAddr(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	ctx := context.Background()
	container, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)
	portStr := port.Port()
	if i := len(portStr) - 4; i > 0 && portStr[i:] == "/tcp" {
		portStr = portStr[:i]
	}
	return host + ":" + portStr
}

func keyRLRedisClient(t *testing.T, addr string) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		DialTimeout:  time.Second,
	})
	require.NoError(t, rdb.Ping(context.Background()).Err(), "test redis should be reachable")
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func keyRLKeyOnly(t *testing.T, rdb rateLimitScripter, keyID string, rpm, tpm int64) *keyRateLimiter {
	t.Helper()
	limits := []adminstore.KeyRateScopeLimits{
		{Scope: adminstore.RateLimitScopeKey, SubjectID: keyID},
	}
	if rpm > 0 {
		limits[0].RPM = &rpm
	}
	if tpm > 0 {
		limits[0].TPM = &tpm
	}
	// Limiter logs (fail-open WARNs) surface through t.Log: a script error
	// degrading to fail-open must never be silent in these tests.
	return newKeyRateLimiter(rdb, &stubRateSource{limits: limits},
		slog.New(slog.NewTextHandler(tLogWriter{t}, nil)))
}

// tLogWriter forwards limiter logs to the test log.
type tLogWriter struct{ t *testing.T }

func (w tLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// admitOnce posts one request through the middleware and reports whether it
// passed.
func admitOnce(t *testing.T, rl *keyRateLimiter, keyID, body string) bool {
	t.Helper()
	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key-Id", keyID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK
}

// TestKeyRateLimiter_ExactlyNUnderConcurrency is the core acceptance
// scenario: 1/10/100 concurrent requests against an N limit — exactly N
// pass, denied requests consume nothing.
func TestKeyRateLimiter_ExactlyNUnderConcurrency(t *testing.T) {
	addr := keyRLRedisAddr(t)
	for _, n := range []int{1, 10, 100} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			// A fresh key id per case: independent windows.
			keyID := fmt.Sprintf("conc-key-%d", n)
			rl := keyRLKeyOnly(t, keyRLRedisClient(t, addr), keyID, int64(n), 0)

			results := make([]bool, 3*n)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					results[i] = admitOnce(t, rl, keyID, "")
				}(i)
			}
			close(start)
			wg.Wait()

			passed := 0
			for _, ok := range results {
				if ok {
					passed++
				}
			}
			assert.Equal(t, n, passed, "exactly %d of %d concurrent requests must pass", n, 3*n)
		})
	}
}

// TestKeyRateLimiter_TwoReplicasShareLimit: two limiter instances over
// separate Redis connections (two gateway replicas) admit exactly the
// configured total, not double.
func TestKeyRateLimiter_TwoReplicasShareLimit(t *testing.T) {
	addr := keyRLRedisAddr(t)
	const limit = 7
	const keyID = "replica-key"
	a := keyRLKeyOnly(t, keyRLRedisClient(t, addr), keyID, limit, 0)
	b := keyRLKeyOnly(t, keyRLRedisClient(t, addr), keyID, limit, 0)

	allowed := 0
	for i := 0; i < limit*3; i++ {
		l := a
		if i%2 == 1 {
			l = b
		}
		if admitOnce(t, l, keyID, "") {
			allowed++
		}
	}
	assert.Equal(t, limit, allowed, "the limit must be shared across replicas")
}

// TestKeyRateLimiter_StrictestScopeBinds: a key limit of 10 binds before the
// org limit of 100 for the same identity.
func TestKeyRateLimiter_StrictestScopeBinds(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	orgRPM, keyRPM := int64(100), int64(10)
	rl := newKeyRateLimiter(rdb, &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
		{Scope: adminstore.RateLimitScopeKey, SubjectID: "strict-key", RPM: &keyRPM},
		{Scope: adminstore.RateLimitScopeOrg, SubjectID: "strict-org", RPM: &orgRPM},
	}}, nil)

	passed := 0
	for i := 0; i < 50; i++ {
		if admitOnce(t, rl, "strict-key", "") {
			passed++
		}
	}
	assert.Equal(t, 10, passed, "the strictest (key) limit must bind")
}

// TestKeyRateLimiter_TPMCorrectedByActualUsage: the input estimate is
// reserved before the request; after the actual usage arrives, the window
// holds the real total, so a stream counts by fact.
func TestKeyRateLimiter_TPMCorrectedByActualUsage(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	const tpm = 1000
	const keyID = "tpm-key"
	rl := keyRLKeyOnly(t, rdb, keyID, 0, tpm)

	// Request 1: 3600-byte body → estimate 900. Admitted.
	var gotCtx context.Context
	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(strings.Repeat("x", 3600)))
	req.Header.Set("X-API-Key-Id", keyID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, gotCtx)
	assert.Equal(t, "1000", rec.Header().Get("x-ratelimit-limit-tokens"))

	// Without correction the window now holds 900; a second 900-estimate
	// request (900+900 > 1000) would be denied. The finish path corrects to
	// the ACTUAL usage (prompt+completion = 100), so it must be admitted.
	reconcileRateLimitUsage(gotCtx, 60, 40)
	require.True(t, admitOnce(t, rl, keyID, strings.Repeat("x", 3600)),
		"after the actual-usage correction the second request must fit")

	// The window now holds 100 (corrected) + 900 (second estimate) = 1000:
	// a third request is denied — the TPM budget is exhausted by fact.
	assert.False(t, admitOnce(t, rl, keyID, strings.Repeat("x", 3600)),
		"the corrected window must be full")

	// The stream-fact contract cuts both ways: usage ABOVE the estimate is
	// charged too. Fresh window: reserve 100 (400-byte body), spend 900 —
	// then a further 200-token request (900+200 > 1000) must be denied.
	const keyID2 = "tpm-key-2"
	rl2 := keyRLKeyOnly(t, keyRLRedisClient(t, addr), keyID2, 0, tpm)
	gotCtx2 := tpMAdmitWithCapture(t, rl2, keyID2, 400)
	reconcileRateLimitUsage(gotCtx2, 800, 100)
	assert.False(t, admitOnce(t, rl2, keyID2, strings.Repeat("x", 800)),
		"actual usage above the estimate must consume the window")
}

func tpMAdmitWithCapture(t *testing.T, rl *keyRateLimiter, keyID string, bodyLen int) context.Context {
	t.Helper()
	var gotCtx context.Context
	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(strings.Repeat("x", bodyLen)))
	req.Header.Set("X-API-Key-Id", keyID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, gotCtx)
	return gotCtx
}

// TestKeyRateLimiter_FailOpenWhenRedisDown verifies the OD-07 degradation
// contract on the data plane: Redis unavailability never denies a request,
// every fallback increments gateway_key_ratelimit_fallback_total.
func TestKeyRateLimiter_FailOpenWhenRedisDown(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	rl := keyRLKeyOnly(t, rdb, "failopen-key", 2, 0)
	rl.warnEvery = time.Millisecond

	require.True(t, admitOnce(t, rl, "failopen-key", ""), "healthy path admits")

	before := testutil.ToFloat64(keyRateLimitFallbackTotal)
	require.NoError(t, rdb.Close()) // simulate an outage on this connection

	assert.True(t, admitOnce(t, rl, "failopen-key", ""), "fail-open must admit when Redis is down")
	assert.True(t, admitOnce(t, rl, "failopen-key", ""))
	after := testutil.ToFloat64(keyRateLimitFallbackTotal)
	assert.GreaterOrEqual(t, after-before, float64(2), "each fallback decision must count once")

	// Recovery: a fresh client on the same Redis enforces the limit again.
	rl2 := keyRLKeyOnly(t, keyRLRedisClient(t, addr), "failopen-key-2", 1, 0)
	assert.True(t, admitOnce(t, rl2, "failopen-key-2", ""))
	assert.False(t, admitOnce(t, rl2, "failopen-key-2", ""), "limits bind again once Redis returns")
}

// TestKeyRateLimiter_RPMWindowDeniesWithRetryAfter: at an RPM limit the 429
// carries Retry-After and the OpenAI-style header set.
func TestKeyRateLimiter_RPMWindowDeniesWithRetryAfter(t *testing.T) {
	addr := keyRLRedisAddr(t)
	const keyID = "retry-key"
	rl := keyRLKeyOnly(t, keyRLRedisClient(t, addr), keyID, 2, 0)

	require.True(t, admitOnce(t, rl, keyID, ""))
	require.True(t, admitOnce(t, rl, keyID, ""))

	handler := rl.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("denied request must not reach the handler")
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", http.NoBody)
	req.Header.Set("X-API-Key-Id", keyID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, "2", rec.Header().Get("x-ratelimit-limit-requests"))
	assert.Equal(t, "0", rec.Header().Get("x-ratelimit-remaining-requests"))
	assert.NotEmpty(t, rec.Header().Get("x-ratelimit-reset-requests"))
	assert.Contains(t, rec.Body.String(), "rate_limit_exceeded")
}

// ---------------------------------------------------------------------------
// windows and the light per-key caps override, on a real Redis — the fake-
// script unit tests pin the request shapes; these pin the WINDOW semantics.
// ---------------------------------------------------------------------------

// capsIntLimiter builds a limiter with the caps layer (enforce or shadow)
// over a real Redis and the given effective caps for every org.
func capsIntLimiter(t *testing.T, rdb rateLimitScripter, caps *adminstore.EffectiveOrgCaps, mode string) *keyRateLimiter {
	t.Helper()
	rl := newKeyRateLimiter(rdb, &stubRateSource{},
		slog.New(slog.NewTextHandler(tLogWriter{t}, nil)))
	rl.caps = newOrgCapsEnforcer(rdb, &stubCapsSource{
		caps:  map[string]*adminstore.EffectiveOrgCaps{"org-1": caps},
		spend: map[string]int64{"": 0},
	}, mode, slog.New(slog.NewTextHandler(tLogWriter{t}, nil)))
	return rl
}

// capsAdmit posts one request with the full identity and reports pass/fail.
func capsAdmit(t *testing.T, rl *keyRateLimiter, keyID, body string) bool {
	t.Helper()
	handler := rl.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key-Id", keyID)
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK
}

// capsAdmitCapture is capsAdmit plus the request context for the reconcile.
func capsAdmitCapture(t *testing.T, rl *keyRateLimiter, keyID, body string) (bool, context.Context) {
	t.Helper()
	var gotCtx context.Context
	handler := rl.middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotCtx = r.Context()
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key-Id", keyID)
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK, gotCtx
}

// TestOrgCaps_ITPMReservedAndCorrected: the input window reserves the
// estimate and the reconcile corrects it to the PROMPT fact; the aggregate
// TPM stays a separate window.
func TestOrgCaps_ITPMReservedAndCorrected(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	caps := betaCaps("org-1")
	caps.InputTPM = 1000
	rl := capsIntLimiter(t, rdb, caps, config.OrgCapsEnforce)

	// Request 1: 3600-byte body → est 900 reserved in the ITPM window.
	ok, ctx := capsAdmitCapture(t, rl, "key-1", strings.Repeat("x", 3600))
	require.True(t, ok)

	// Actual usage: prompt 100 + completion 500. The ITPM window drops from
	// 900 to 100 (the completion never enters it).
	reconcileRateLimitUsage(ctx, 100, 500)

	// est 950 would exceed ITPM (100 + 950 > 1000) → denied BY ITPM even
	// though the aggregate TPM (200k) is nowhere near full.
	assert.False(t, capsAdmit(t, rl, "key-1", strings.Repeat("x", 3800)),
		"the ITPM window must bind on the corrected prompt fact")

	// est 890 fits (100 + 890 ≤ 1000) → admitted.
	assert.True(t, capsAdmit(t, rl, "key-1", strings.Repeat("x", 3560)),
		"an input estimate within the corrected ITPM window must pass")
}

// TestOrgCaps_OTPMCreditedByReconcile: the output window admits against the
// accumulated completion facts; each request's own output is credited after
// the response, so the denial lands on a LATER request.
func TestOrgCaps_OTPMCreditedByReconcile(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	caps := betaCaps("org-1")
	caps.OutputTPM = 1000
	rl := capsIntLimiter(t, rdb, caps, config.OrgCapsEnforce)

	ok, ctx1 := capsAdmitCapture(t, rl, "key-1", "")
	require.True(t, ok, "the first request cannot be denied by an empty output window")
	reconcileRateLimitUsage(ctx1, 0, 900)

	// 900 accumulated; est 250 output unknown → still admitted (post-fact
	// dimension), and its completion pushes the window to 1050.
	ok, ctx2 := capsAdmitCapture(t, rl, "key-1", "")
	require.True(t, ok)
	reconcileRateLimitUsage(ctx2, 0, 150)

	// The window now holds 1050 > 1000: the next request is denied BY OTPM.
	assert.False(t, capsAdmit(t, rl, "key-1", ""),
		"the credited completion facts must exhaust the OTPM window")
}

// TestOrgCaps_PerKeyOverrideIsolation: the org's per-key TPM cap gives every
// key its OWN window — one key's usage never consumes another key's budget.
func TestOrgCaps_PerKeyOverrideIsolation(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	caps := betaCaps("org-1")
	caps.KeyTPM = 1000
	rl := capsIntLimiter(t, rdb, caps, config.OrgCapsEnforce)

	// key-a: est 900, corrected to a total of 100 → window holds 100.
	ok, ctxA := capsAdmitCapture(t, rl, "key-a", strings.Repeat("x", 3600))
	require.True(t, ok)
	reconcileRateLimitUsage(ctxA, 60, 40)

	// key-a: est 950 more → 100 + 950 > 1000 → denied by its own window.
	assert.False(t, capsAdmit(t, rl, "key-a", strings.Repeat("x", 3800)),
		"key-a must be bound by its per-key window")

	// key-b never touched its window: the same request passes.
	assert.True(t, capsAdmit(t, rl, "key-b", strings.Repeat("x", 3800)),
		"key-b's per-key window is independent of key-a's usage")
}

// TestOrgCaps_ShadowWindowsPassAndAccount: in shadow mode NO caps window
// denies; would-denies are counted and the shadow windows accumulate the
// real traffic (request 3 would have been denied and says so).
func TestOrgCaps_ShadowWindowsPassAndAccount(t *testing.T) {
	addr := keyRLRedisAddr(t)
	rdb := keyRLRedisClient(t, addr)
	caps := betaCaps("org-1")
	caps.TPM = 1000
	rl := capsIntLimiter(t, rdb, caps, config.OrgCapsShadow)

	before := testutil.ToFloat64(orgCapsWouldDenyTotal.WithLabelValues(orgCapsKindTPM))

	// est 500 each: req 1 → 500, req 2 → 1000 (exactly at limit), req 3
	// would exceed → counted, still admitted.
	require.True(t, capsAdmit(t, rl, "key-1", strings.Repeat("x", 2000)))
	require.True(t, capsAdmit(t, rl, "key-1", strings.Repeat("x", 2000)))
	assert.True(t, capsAdmit(t, rl, "key-1", strings.Repeat("x", 2000)),
		"shadow must pass even past the caps limit")

	after := testutil.ToFloat64(orgCapsWouldDenyTotal.WithLabelValues(orgCapsKindTPM))
	assert.InDelta(t, before+1, after, 0.0001, "exactly the overflowing request counts as a would-deny")
}
