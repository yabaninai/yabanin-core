package cli

// fair-share acceptance coverage: the split ITPM/OTPM org-caps windows
// (input reserved from the estimate and corrected by the reconcile, output
// credited post-fact), the light per-key TPM caps override and its window
// isolation, shadow/enforce inheritance for every new dimension, and the
// priority-scaled Retry-After (reject-policy fairness, not a scheduler).
// Real-Redis window semantics live in ratelimit_int_test.go.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
)

// stubPrioritySource serves fixed per-key priorities (it doubles as a
// rateLimitsSource with no limits so it can slot into the limiter directly).
type stubPrioritySource struct {
	priorities map[string]int
	err        error
}

func (s *stubPrioritySource) EffectiveKeyRateLimits(context.Context, string, string, string) ([]adminstore.KeyRateScopeLimits, error) {
	return nil, nil
}

func (s *stubPrioritySource) APIKeyPriority(_ context.Context, keyID string) (int, error) {
	if s.err != nil {
		return adminstore.DefaultAPIKeyPriority, s.err
	}
	if p, ok := s.priorities[keyID]; ok {
		return p, nil
	}
	return adminstore.DefaultAPIKeyPriority, nil
}

func splitCaps(orgID string, in, out, perKey int64) *adminstore.EffectiveOrgCaps {
	c := betaCaps(orgID)
	c.InputTPM = in
	c.OutputTPM = out
	c.KeyTPM = perKey
	return c
}

// TestOrgCapsITPMExceededAnswers429: the input-token window is its own
// dimension — a deny names ITPM (never the aggregate TPM), reserves nothing,
// and answers 429 with a retry hint.
func TestOrgCapsITPMExceededAnswers429(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": splitCaps("org-1", 5_000, 0, 0),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(false, -1, 60, 0, -1, 200000, 0, 8000, "itpm"),
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	rec := capsRequest(t, rl, "org-1", strings.Repeat("x", 40_000))
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "input tokens per minute (ITPM)")
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))

	// The caps scope carried the ITPM window, not just rpm/tpm.
	call := script.calls[0]
	found := false
	for _, k := range call.keys {
		if strings.Contains(k, "gwrl:itpm:orgcaps:org-1") {
			found = true
		}
	}
	assert.True(t, found, "the itpm window must ride the caps scope")
}

// TestOrgCapsITPMReservationCorrectedByReconcile: the admitted request
// reserves the input estimate in the ITPM window and the finish-path
// reconcile swaps it for the actual prompt tokens.
func TestOrgCapsITPMReservationCorrectedByReconcile(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": splitCaps("org-1", 100_000, 0, 0),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 59, 60, 0, 199000, 200000, 0, 0, ""),
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	var ctx context.Context
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(strings.Repeat("x", 4000))) // est 1000
	req.Header.Set("X-Org-Id", "org-1")
	req.Header.Set("X-API-Key-Id", "key-1")
	rec := httptest.NewRecorder()
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	tr, _ := ctx.Value(tokenReconcileCtxKey{}).(*tokenReservation)
	require.NotNil(t, tr)
	require.Len(t, tr.scopes, 1)
	assert.Equal(t, int64(100_000), tr.scopes[0].itpm)

	// Reconcile: total 700 = prompt 400 + completion 300 → the ITPM weight
	// must become the PROMPT fact, not the total.
	script.results = []interface{}{int64(1)}
	reconcileRateLimitUsage(ctx, 400, 300)
	require.Equal(t, 2, script.evalCount())
	call := script.calls[1]
	require.Len(t, call.keys, 6)
	assert.Equal(t, "gwrl:itpm:orgcaps:org-1", call.keys[2])
	assert.Equal(t, "gwrl:itpmw:orgcaps:org-1", call.keys[3])
	assert.Equal(t, int64(700), call.args[1], "aggregate TPM gets the total")
	assert.Equal(t, int64(400), call.args[2], "ITPM gets the prompt fact")
	assert.Equal(t, int64(300), call.args[3], "OTPM gets the completion fact")
}

// TestOrgCapsOTPMCreditedViaReconcile: output tokens cannot be known
// pre-flight — the request is admitted against the accumulated output, the
// member is recorded with weight 0, and the reconcile credits the actual
// completion tokens so the NEXT request sees the fact.
func TestOrgCapsOTPMCreditedViaReconcile(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": splitCaps("org-1", 0, 1_000, 0),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 59, 60, 0, -1, 0, 0, 0, ""),
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	var ctx context.Context
	// Empty body: est = 0, yet the OTPM member must be recorded (weight 0).
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(""))
	req.Header.Set("X-Org-Id", "org-1")
	req.Header.Set("X-API-Key-Id", "key-1")
	rec := httptest.NewRecorder()
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	tr, _ := ctx.Value(tokenReconcileCtxKey{}).(*tokenReservation)
	require.NotNil(t, tr, "an OTPM-windowing request carries the reconcile even with a zero estimate")
	assert.True(t, tr.active)

	// The finish path credits the completion fact.
	script.results = []interface{}{int64(1)}
	reconcileRateLimitUsage(ctx, 0, 900)
	require.Equal(t, 2, script.evalCount())
	call := script.calls[1]
	assert.Equal(t, "gwrl:otpm:orgcaps:org-1", call.keys[4])
	assert.Equal(t, int64(900), call.args[3])

	// The next admission sees the credited output and denies on OTPM.
	script.results = []interface{}{
		admitResult(false, -1, 60, 0, -1, 0, 0, 60000, "otpm"),
	}
	rec = capsRequest(t, rl, "org-1", "")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "output tokens per minute (OTPM)")
}

// TestOrgCapsPerKeyOverrideIsolation: the light RM-71 override builds ONE
// window per API key (orgcapskey namespace) — the org-wide caps scope stays
// separate, and another key's request never touches key-1's window.
func TestOrgCapsPerKeyOverrideIsolation(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": splitCaps("org-1", 0, 0, 1_000),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(true, 59, 60, 0, -1, 0, 0, 0, ""), // key-1
		admitResult(true, 59, 60, 0, -1, 0, 0, 0, ""), // key-2
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	reqKey := func(keyID string) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader("{}"))
		req.Header.Set("X-Org-Id", "org-1")
		req.Header.Set("X-API-Key-Id", keyID)
		rec := httptest.NewRecorder()
		rl.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	reqKey("key-1")
	reqKey("key-2")

	var key1Win, key2Win bool
	for _, k := range script.calls[0].keys {
		if strings.Contains(k, "gwrl:tpm:orgcapskey:key-1") {
			key1Win = true
		}
		if strings.Contains(k, "orgcapskey:key-2") {
			key2Win = true
		}
	}
	assert.True(t, key1Win, "key-1 carries its own per-key caps window")
	assert.False(t, key2Win, "key-2's request must not touch key-1's window")
	for _, k := range script.calls[1].keys {
		assert.NotContains(t, k, "orgcapskey:key-1", "key-2's windows are separate")
	}
	// Scopes: [orgcaps (args 4..7), orgcapskey (args 8..11)] — the per-key
	// tpm limit rides the second scope.
	assert.Equal(t, int64(0), script.calls[0].args[8], "per-key scope has no rpm dimension")
	assert.Equal(t, int64(1_000), script.calls[0].args[9], "per-key tpm limit rides the key caps scope")
}

// TestOrgCapsShadowInheritanceForNewDimensions: shadow mode inherits for
// every caps dimension — ITPM/OTPM/per-key exhaustion counts a would-deny
// and PASSES, while key-level limits keep enforcing.
func TestOrgCapsShadowInheritanceForNewDimensions(t *testing.T) {
	newRL := func(script *fakeRateScript, caps *adminstore.EffectiveOrgCaps) *keyRateLimiter {
		src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
			"org-1": caps,
		}, spend: map[string]int64{"": 0}}
		return capsTestLimiter(script, src, config.OrgCapsShadow)
	}

	t.Run("caps window exhaustion passes and is counted", func(t *testing.T) {
		script := &fakeRateScript{results: []interface{}{"itpm"}} // shadow observe answer
		rl := newRL(script, splitCaps("org-1", 5_000, 0, 0))

		before := metricValue(t, orgCapsWouldDenyTotal, orgCapsKindITPM)
		rec := capsRequest(t, rl, "org-1", strings.Repeat("x", 40_000))
		require.Equal(t, http.StatusOK, rec.Code, "shadow must never deny on caps windows")
		assert.Greater(t, metricValue(t, orgCapsWouldDenyTotal, orgCapsKindITPM), before)
		// The enforcing admit never ran: the only EVAL was the shadow check.
		require.Equal(t, 1, script.evalCount())
		assert.Contains(t, script.calls[0].script, "denyDimension = ''", "the shadow script answers the would-deny dimension")
	})

	t.Run("per-key override counted in shadow too", func(t *testing.T) {
		script := &fakeRateScript{results: []interface{}{"tpm"}}
		rl := newRL(script, splitCaps("org-1", 0, 0, 1_000))

		before := metricValue(t, orgCapsWouldDenyTotal, orgCapsKindTPM)
		rec := capsRequest(t, rl, "org-1", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Greater(t, metricValue(t, orgCapsWouldDenyTotal, orgCapsKindTPM), before)
	})

	t.Run("key-level limits still enforce in shadow", func(t *testing.T) {
		script := &fakeRateScript{results: []interface{}{
			admitResult(false, -1, 1, 42000, -1, 0, 0, 42000, "rpm"),
		}}
		rl := newRL(script, betaCaps("org-1"))
		rl.source = &stubRateSource{limits: []adminstore.KeyRateScopeLimits{
			keyLimit(adminstore.RateLimitScopeKey, "key-1", int64ptr(1), nil),
		}}

		rec := capsRequest(t, rl, "org-1", "")
		require.Equal(t, http.StatusTooManyRequests, rec.Code, "legacy key limits deny regardless of the caps mode")
	})

	t.Run("shadow otpm accumulates through reconcile", func(t *testing.T) {
		script := &fakeRateScript{results: []interface{}{
			"", // shadow observe: nothing denied
		}}
		rl := newRL(script, splitCaps("org-1", 0, 100, 0))

		var ctx context.Context
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(""))
		req.Header.Set("X-Org-Id", "org-1")
		req.Header.Set("X-API-Key-Id", "key-1")
		rec := httptest.NewRecorder()
		rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx = r.Context()
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		tr, _ := ctx.Value(tokenReconcileCtxKey{}).(*tokenReservation)
		require.NotNil(t, tr)
		require.Len(t, tr.scopes, 1, "the shadow-recorded caps scope rides the reconcile")
		assert.Equal(t, int64(100), tr.scopes[0].otpm)

		script.results = []interface{}{int64(1)}
		reconcileRateLimitUsage(ctx, 0, 900)
		require.Equal(t, 2, script.evalCount())
		assert.Equal(t, "gwrl:otpm:orgcaps:org-1", script.calls[1].keys[4])
	})
}

// TestFairShareRetryAfterScaling: on identical binding windows only the
// Retry-After hint differs — higher priority retries sooner. The DEFAULT
// priority leaves the hint byte-for-byte as before the feature.
func TestFairShareRetryAfterScaling(t *testing.T) {
	tests := []struct {
		priority int
		want     string
	}{
		{priority: 0, want: "60"}, // 30000ms × 2.0
		{priority: 4, want: "36"}, // 30000ms × 1.2
		{priority: 5, want: "30"}, // default: exactly the unscaled hint
		{priority: 6, want: "24"}, // 30000ms × 0.8
		{priority: 9, want: "6"},  // 30000ms × 0.2
	}
	for _, tt := range tests {
		t.Run("priority="+strconv.Itoa(tt.priority), func(t *testing.T) {
			src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
				"org-1": betaCaps("org-1"),
			}, spend: map[string]int64{"": 0}}
			script := &fakeRateScript{results: []interface{}{
				admitResult(false, -1, 60, 30000, -1, 200000, 0, 30000, "rpm"),
			}}
			rl := capsTestLimiter(script, src, config.OrgCapsEnforce)
			rl.source = &stubPrioritySource{priorities: map[string]int{"key-1": tt.priority}}

			rec := capsRequest(t, rl, "org-1", "")
			require.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Equal(t, tt.want, rec.Header().Get("Retry-After"))
		})
	}

	t.Run("priority resolution error degrades to the default", func(t *testing.T) {
		src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
			"org-1": betaCaps("org-1"),
		}, spend: map[string]int64{"": 0}}
		script := &fakeRateScript{results: []interface{}{
			admitResult(false, -1, 60, 30000, -1, 200000, 0, 30000, "rpm"),
		}}
		rl := capsTestLimiter(script, src, config.OrgCapsEnforce)
		rl.source = &stubPrioritySource{err: assert.AnError}

		rec := capsRequest(t, rl, "org-1", "")
		require.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "30", rec.Header().Get("Retry-After"), "fail-open to the unscaled default")
	})
}

func TestFairShareRetryAfterSeconds(t *testing.T) {
	assert.Equal(t, int64(1), fairShareRetryAfterSeconds(0, 0), "never below one second")
	assert.Equal(t, int64(3), fairShareRetryAfterSeconds(2500, 5), "default priority keeps the legacy rounding")
	assert.Equal(t, int64(1), fairShareRetryAfterSeconds(2500, 9), "2500ms × 0.2 = 500ms → ceil 1s")
	assert.Equal(t, int64(12), fairShareRetryAfterSeconds(60_000, 9))
	assert.Equal(t, int64(120), fairShareRetryAfterSeconds(60_000, 0))
	assert.Equal(t, int64(30), fairShareRetryAfterSeconds(30_000, 5))
	assert.Equal(t, int64(1), fairShareRetryAfterSeconds(-5, 5), "negative input clamps")
}

func TestAPIKeyPriorityCacheAndFailOpen(t *testing.T) {
	script := &fakeRateScript{}
	rl := newKeyRateLimiter(script, &stubPrioritySource{priorities: map[string]int{"key-1": 8}}, nil)

	assert.Equal(t, 8, rl.priorityFor(context.Background(), "key-1"))
	assert.Equal(t, adminstore.DefaultAPIKeyPriority, rl.priorityFor(context.Background(), "key-9"),
		"unknown key → default")
	assert.Equal(t, adminstore.DefaultAPIKeyPriority, rl.priorityFor(context.Background(), ""),
		"no key identity → default")

	// The cache serves the second read without another resolution error path
	// (same value; the stub would error if consulted with err set).
	rl.source = &stubPrioritySource{err: assert.AnError}
	assert.Equal(t, 8, rl.priorityFor(context.Background(), "key-1"), "cached priority survives a source outage")
}

func TestPriorityDeniedMetricCarriesDimension(t *testing.T) {
	src := &stubCapsSource{caps: map[string]*adminstore.EffectiveOrgCaps{
		"org-1": splitCaps("org-1", 0, 500, 0),
	}, spend: map[string]int64{"": 0}}
	script := &fakeRateScript{results: []interface{}{
		admitResult(false, -1, 60, 0, -1, 0, 0, 60000, "otpm"),
	}}
	rl := capsTestLimiter(script, src, config.OrgCapsEnforce)

	before := testutil.ToFloat64(keyRateLimitDeniedTotal.WithLabelValues("otpm"))
	rec := capsRequest(t, rl, "org-1", "")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.InDelta(t, before+1, testutil.ToFloat64(keyRateLimitDeniedTotal.WithLabelValues("otpm")), 0.0001)
}
