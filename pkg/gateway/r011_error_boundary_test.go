package cli

// hold under every refusal shape the packet names — a policy store outage, a
// canceled control evaluation, a repeated denied hit, a corrupt cached
// document, the shadow-mode kill switch and the tenant boundary. An unknown
// or partial control state never counts as success: enforce+fail-closed
// answers 503 before the warm document is consulted, and recovery re-enters
// the live control on the very next hit.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r011CorruptDoc is a truncated completion document: invalid JSON whose raw
// bytes still carry the deny marker. Detectors scan the payload Body text,
// so a corrupt sealed entry must not slip past word matching.
const r011CorruptDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"leaked-ssn inside"`

// r011PostCtx is rt02Post with an explicit request context — cancellation
// scenarios drive the real production handler under a dead client context.
func r011PostCtx(t *testing.T, gw *gateway, ctx context.Context, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-a")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// TestR011_CacheHit_PolicyStoreOutage_FailClosedNeverServesWarm: with the
// policy store offline (enforce + default fail-closed) the pre-upstream gate
// answers 503 before the cache branch — the warm document is never consulted,
// never served, and the control is never routed around.
func TestR011_CacheHit_PolicyStoreOutage_FailClosedNeverServesWarm(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	store.listErr = errors.New("policystore offline")
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	gw.cache = c

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-outage"}]}`, nil)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	// The envelope type is the 503 family; the specific gate code rides the
	// optional "code" field — its presence proves this 503 is the policy
	// gate's fail-closed answer, not an unrelated outage.
	assert.Equal(t, "service_unavailable_error", errorType(t, rec))
	assert.Contains(t, rec.Body.String(), "policy_temporarily_unavailable")
	assert.NotContains(t, rec.Body.String(), "leaked-ssn")
	assert.NotContains(t, rec.Body.String(), "from-cache",
		"an unavailable control must never degrade into serving the warm document")
	assert.Equal(t, 0, u.totalCalls(), "an unavailable control must not be routed around")
	assert.Equal(t, 0, c.lookups, "the 503 is answered before the cache is consulted")
}

// TestR011_CacheHit_PolicyStoreOutage_Recovery: outage → recovery → policy
// change. While the store is down the warm entry stays sealed (503); the
// moment the store heals without an attached policy the same entry serves
// (the live control says allow); after the org attaches the deny policy the
// SAME warm entry is denied — recovery always re-enters the current control.
func TestR011_CacheHit_PolicyStoreOutage_Recovery(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	store.listErr = errors.New("policystore offline")
	versions := &fakePolicyVersions{}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}

	outage := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-recover-outage"}]}`, nil)
	require.Equal(t, http.StatusServiceUnavailable, outage.Code, outage.Body.String())
	assert.NotContains(t, outage.Body.String(), "leaked-ssn")

	store.listErr = nil
	healthy := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-recover-healthy"}]}`, nil)
	require.Equal(t, http.StatusOK, healthy.Code, healthy.Body.String())
	assert.Equal(t, "EXACT", healthy.Header().Get("X-Cache"))
	assert.Contains(t, healthy.Body.String(), "leaked-ssn",
		"with the control healthy and no policy attached the warm entry serves verbatim")

	store.add("org-a", adminstore.PolicyPipeline{
		ID: "r011-recover", OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions.bump()

	denied := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-recover-denied"}]}`, nil)
	require.Equal(t, http.StatusBadRequest, denied.Code, denied.Body.String())
	assert.Contains(t, denied.Body.String(), "content_policy_violation")
	assert.NotContains(t, denied.Body.String(), "leaked-ssn",
		"recovery must re-enter the live control, not exempt the previously shielded entry")
	assert.Equal(t, 0, u.totalCalls(), "no phase of the outage/recovery arc touches upstream")
}

// TestR011_CacheHit_DeniedRetry_IsDeterministic: repeating a denied cache-hit
// request yields the identical terminal envelope every time — no sticky
// state, no verdict corruption, no cache write, no upstream refetch; every
// attempt re-consults the cache and re-applies the live control.
func TestR011_CacheHit_DeniedRetry_IsDeterministic(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	gw.cache = c
	events := captureEvents(t)

	body := `{"model":"m","messages":[{"role":"user","content":"r011-retry"}]}`
	for i := 0; i < 2; i++ {
		rec := rt02Post(t, gw, body, nil)
		require.Equal(t, http.StatusBadRequest, rec.Code, "attempt %d: %s", i+1, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "content_policy_violation", "attempt %d", i+1)
		assert.NotContains(t, rec.Body.String(), "leaked-ssn", "attempt %d", i+1)
	}

	assert.Equal(t, 0, u.totalCalls())
	assert.Equal(t, 2, c.lookups, "each retry re-consults the cache — the denial is not sticky state")
	assert.Equal(t, 0, c.writes, "a denied hit must not rewrite the cache")

	failed := 0
	for _, ev := range events() {
		if ev.EventType != "request.failed" {
			continue
		}
		failed++
		assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
		assert.Equal(t, "exact", ev.CacheHitType)
		assert.Contains(t, ev.Policy, `"verdict":"deny"`, "attempt %d carries the decision record", failed)
	}
	assert.Equal(t, 2, failed, "each retry emits its own diagnosable request.failed event")
}

// TestR011_CacheHit_CorruptEntry_DenyStillApplies: a corrupt (invalid JSON)
// cached document is governed by its raw bytes — the deny marker still fires
// the terminal envelope; corruption is not an enforcement bypass and never
// reaches the client.
func TestR011_CacheHit_CorruptEntry_DenyStillApplies(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011CorruptDoc), SourceType: "semantic", Similarity: 0.97}}
	gw.cache = c

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-corrupt"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "content_policy_violation")
	assert.NotContains(t, rec.Body.String(), "leaked-ssn")
	assert.Equal(t, 0, u.totalCalls(), "a corrupt denied entry must not silently refetch")
	assert.Equal(t, 0, c.writes)
}

// TestR011_CacheHit_CancelDuringStoreLoad_FailClosed: a request whose context
// dies while the control is being evaluated is an UNKNOWN state, never a
// success — the fail-closed gate answers 503 and the warm document is not
// consulted; a healed store with the deny policy attached denies the same
// entry on the next live request.
func TestR011_CacheHit_CancelDuringStoreLoad_FailClosed(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	store.listCtxBlock = true
	versions := &fakePolicyVersions{}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	gw.cache = c

	ctxCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := r011PostCtx(t, gw, ctxCanceled,
		`{"model":"m","messages":[{"role":"user","content":"r011-cancel"}]}`, nil)

	require.Equal(t, http.StatusServiceUnavailable, canceled.Code, canceled.Body.String())
	assert.Equal(t, "service_unavailable_error", errorType(t, canceled))
	assert.Contains(t, canceled.Body.String(), "policy_temporarily_unavailable")
	assert.NotContains(t, canceled.Body.String(), "leaked-ssn")
	assert.NotContains(t, canceled.Body.String(), "from-cache")
	assert.Equal(t, 0, c.lookups, "an interrupted control evaluation must not reach the cache")
	assert.Equal(t, 0, u.totalCalls())

	store.listCtxBlock = false
	store.add("org-a", adminstore.PolicyPipeline{
		ID: "r011-cancel", OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions.bump()

	healed := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-cancel-healed"}]}`, nil)
	require.Equal(t, http.StatusBadRequest, healed.Code, healed.Body.String())
	assert.Contains(t, healed.Body.String(), "content_policy_violation")
	assert.NotContains(t, healed.Body.String(), "leaked-ssn",
		"recovery after the interruption re-enters the live control")
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_ShadowMode_NeverBlocksWarmEntry: the shadow kill switch
// downgrades every policy at compile time — the cache-hit seam observes and
// records the verdict but must never block, mask or refetch the warm entry.
func TestR011_CacheHit_ShadowMode_NeverBlocksWarmEntry(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	store.add("org-a", adminstore.PolicyPipeline{
		ID: "r011-shadow", OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeShadow)
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	events := captureEvents(t)

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-shadow"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	assert.Contains(t, rec.Body.String(), "leaked-ssn",
		"shadow mode observes the cached document but must never block it")
	assert.Equal(t, 0, u.totalCalls(), "shadow must not turn the hit into a refetch")

	shadowVerdicts := 0
	for _, ev := range events() {
		if ev.EventType == "request.completed" && ev.Policy != "" {
			shadowVerdicts++
			assert.Contains(t, ev.Policy, `"verdict":"allow"`,
				"the downgrade is observable: the recorded verdict never raises to deny")
		}
	}
	assert.Positive(t, shadowVerdicts, "the shadow decision record rides the completed event")
}

// TestR011_CacheHit_PolicyIsTenantScoped: the enforcement seam evaluates the
// request org's plans only — org-b's deny policy must not govern org-a's warm
// hit, while the identical entry under org-b's own control is denied.
func TestR011_CacheHit_PolicyIsTenantScoped(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	store.add("org-b", adminstore.PolicyPipeline{
		ID: "r011-tenant", OrgID: "org-b", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	gw.cache = c

	orgA := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-tenant-a"}]}`, nil)
	require.Equal(t, http.StatusOK, orgA.Code, orgA.Body.String())
	assert.Equal(t, "EXACT", orgA.Header().Get("X-Cache"))
	assert.Contains(t, orgA.Body.String(), "leaked-ssn",
		"org-b's control must not govern org-a's cache hit")

	orgB := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-tenant-b"}]}`,
		map[string]string{"X-Org-Id": "org-b"})
	require.Equal(t, http.StatusBadRequest, orgB.Code, orgB.Body.String())
	assert.Contains(t, orgB.Body.String(), "content_policy_violation")
	assert.NotContains(t, orgB.Body.String(), "leaked-ssn")

	assert.Equal(t, 0, u.totalCalls())
	assert.Equal(t, 2, c.lookups)
}
