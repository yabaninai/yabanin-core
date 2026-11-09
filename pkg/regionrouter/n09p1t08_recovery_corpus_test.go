package regionrouter

// N09-P01-T08 recovery corpus — the region failover seam (pkg/regionrouter).
//
// The packet acceptance, per-kind selection and the failover-only policy
// consult boundary are pinned by failover_policy_test.go and the T07
// boundary corpus. This corpus adds the recovery dimension those leave
// open: how the failover decision behaves when the decision itself is
// interrupted or its inputs were rebuilt.
//
// Three properties are pinned here:
//  1. An interrupted RE-evaluation decides identically to the live one: the
//     health snapshot is cached for 5s, so a re-run with a dying context
//     (shutdown race, superseded request) reads the same evidence and
//     reaches the same redirect — same refusal/redirect text, fresh policy
//     consult, no sticky grant.
//  2. A COLD evaluation whose probes all die with the cancelled context
//     refuses instead of redirecting: unknown health never becomes a
//     failover grant — the policy may be consulted, but with no live peer
//     evidence there is nothing to fail over TO.
//  3. Recovery is temporary by construction: when the home region's health
//     comes back, a restarted process (fresh checker, cold cache) serves
//     locally again — and the recovered local path reads no policy, so an
//     outage of the policy source cannot linger as a route change.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/sovereign"
)

// t08DeadCtx returns an already-cancelled context: the shape of a request
// whose owner died while the decision was being made.
func t08DeadCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestN09P1T08_Recovery_InterruptedReevaluationDecidesIdentically re-runs a
// failover decision with a cancelled context while the health snapshot is
// still warm: the interrupted evaluation must reach the SAME decision as the
// live one, and must re-consult the policy source rather than inheriting a
// cached grant.
func TestN09P1T08_Recovery_InterruptedReevaluationDecidesIdentically(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in"},
	}}
	router := New(store, newMemKV())
	// EU is excluded; sg (the best peer) stays allowed, so the live
	// decision is a redirect to sg.
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"EU"}},
	}}
	sg := healthyServer(t)
	eu := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: eu.URL},
	})
	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).
		WithPolicySource(src)

	// Live evaluation: home down → redirect to sg.
	err1 := fe.Decide(context.Background(), "org-1")
	require.Error(t, err1)
	assert.Contains(t, err1.Error(), "redirect to sg")
	consultsLive := src.calls
	assert.GreaterOrEqual(t, consultsLive, 1)

	// Interrupted re-evaluation, snapshot still warm: identical decision,
	// fresh policy consult — no sticky grant, no half-answer.
	err2 := fe.Decide(t08DeadCtx(), "org-1")
	require.Error(t, err2)
	assert.Equal(t, err1.Error(), err2.Error(),
		"the interrupted re-evaluation must decide identically to the live one")
	assert.Greater(t, src.calls, consultsLive,
		"the re-evaluation consults the policy source again instead of inheriting a grant")
}

// TestN09P1T08_Recovery_ColdProbeUnderInterruptionRefusesInsteadOfRedirect
// pins the cold path under interruption: a fresh checker whose probes all
// die with the cancelled context has NO peer evidence — the decision refuses
// with "no healthy peer" and never manufactures a redirect. The policy
// source may be consulted (the consult precedes peer selection), but it
// cannot enable a failover that no live peer supports.
func TestN09P1T08_Recovery_ColdProbeUnderInterruptionRefusesInsteadOfRedirect(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in"},
	}}
	router := New(store, newMemKV())
	// A maximally permissive policy: if anything could enable a redirect,
	// this would.
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": sovereign.DefaultPolicy(),
	}}
	sg := healthyServer(t) // the peer IS up — only the probes are dead
	checker := NewHealthChecker([]PeerURL{{Region: "sg", URL: sg.URL}})
	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).
		WithPolicySource(src)

	err := fe.Decide(t08DeadCtx(), "org-1")
	require.Error(t, err, "unknown health must not decide to serve locally")
	assert.Contains(t, err.Error(), "no healthy peer")
	assert.NotContains(t, err.Error(), "redirect",
		"a dead probe run must never become a failover grant")
	assert.GreaterOrEqual(t, src.calls, 1,
		"the consult happened — and still could not enable a redirect")
}

// TestN09P1T08_Recovery_HealthRecoveryReturnsToLocalServe flips the home
// region's health back up and re-decides with a fresh checker — the
// restarted-process shape, since the old checker's 5s snapshot would
// otherwise keep serving the stale "down" evidence. The recovery path must
// serve locally again and must read no policy: the recovered home decision
// is made on health alone.
func TestN09P1T08_Recovery_HealthRecoveryReturnsToLocalServe(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in"},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"EU"}},
	}}

	var inUp atomic.Bool
	inSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !inUp.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(inSrv.Close)
	sg := healthyServer(t)

	peers := []PeerURL{{Region: "in", URL: inSrv.URL}, {Region: "sg", URL: sg.URL}}
	checkerDown := NewHealthChecker(peers)
	feDown := NewFailoverEvaluator(router, checkerDown, regions3(), "sg", nil).
		WithPolicySource(src)

	// Outage: home down → redirect to sg, one policy consult.
	inUp.Store(false)
	err := feDown.Decide(context.Background(), "org-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to sg")
	assert.Equal(t, 1, src.calls, "the failover decision consulted the policy once")

	// Recovery: the home region's health returns; a restarted process
	// re-decides with a fresh checker (cold cache — the live evidence) and
	// serves locally again, without any policy consult.
	inUp.Store(true)
	checkerUp := NewHealthChecker(peers)
	feUp := NewFailoverEvaluator(router, checkerUp, regions3(), "sg", nil).
		WithPolicySource(src)

	require.NoError(t, feUp.Decide(context.Background(), "org-1"),
		"the recovered home region is served locally again — failover is temporary")
	assert.Equal(t, 1, src.calls,
		"the recovered local path reads no policy — the consult count is unchanged")
}
