package cli

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// They run through the REAL load path (policystore snapshot → compiled
// policies → policyPreUpstream) and the REAL routing call site
// (executeFallback), so each assertion pins observable behavior, not
// implementation text. Only boundary/negative cases not covered by
// r017_route_hint_test.go live here.

// Composition semantics through the real load path: two enforce policies
// carrying different hints, attached at different priorities. Policies run in
// attachment-priority order (lower number first) and the FIRST recorded hint
// wins, so the higher-priority policy's target steers the chain and the lower
// one cannot silently override it. This is also the broken-vs-fixed pair for
// empty and the chain would run in declaration order.
func TestRouteHintRegression_HighestPriorityHintWins(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-high", OrgID: testOrg, Name: "hint-high", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-high", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(5)})
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-low", OrgID: testOrg, Name: "hint-low", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-low", "meta")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})

	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	w, r := policyRequest(string(body))
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok, "hint policies must not block: %s", w.Body.String())

	require.Equal(t, "anthropic", routehint.HintFrom(r.Context()),
		"the higher-priority policy's hint is applied, the lower one cannot override")
	assert.Equal(t, []string{"anthropic", "openai", "meta"},
		providersOf(t, gw, r.Context(), primary), "the winning hint steers the chain")

	decisions := parseDecisions(t, policyEvent)
	require.Len(t, decisions, 2)
	assert.Equal(t, "hint-high", decisions[0].PolicyID, "policies ran in attachment-priority order")
	assert.Equal(t, "hint-low", decisions[1].PolicyID)
	for i, dec := range decisions {
		require.Len(t, dec.Findings, 1, "decision %d (%s) shows its applied route_hint step", i, dec.PolicyID)
		assert.Equal(t, routehint.FindingCategory, dec.Findings[0].Category)
	}
}

// Kill-switch baseline (the observable pre-fix shape): with the policy
// runtime off, no hint reaches the routing call site and the chain runs in
// declaration order. This is exactly the behavior a regression to the no-op
// placeholder would produce — the steer checks above are what distinguish it
// from the fixed behavior.
func TestRouteHintRegression_RuntimeOffKeepsDeclarationOrder(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeOff)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})

	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	w, r := policyRequest(string(body))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok)

	assert.Empty(t, routehint.HintFrom(r.Context()), "the kill-switch must leave no hint on the request")
	assert.Equal(t, []string{"openai", "anthropic", "meta"}, providersOf(t, gw, r.Context(), primary))
}

// Boundary of the refusal semantics: the hop bound limits which candidates
// are allowed, and the refusal is evaluated against that ACTUAL candidate
// set — a hint naming a provider that only appears beyond maxHops is
// unsatisfiable (400 route_hint_unsatisfiable, no dial) even though the raw
// failover list mentions it.
func TestRouteHintRegression_HintBeyondMaxHopsRefused(t *testing.T) {
	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)
	gw.fallback = router.NewFallbackExecutor(hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}}, 2, testLogger())
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "openai",
		FailoverModels: []string{"secondary", "tertiary"},
	}

	ctx := routehint.WithHint(context.Background(), "meta")
	var calls []string
	_, status, attempts, err := gw.executeFallback(ctx, primary, func(_ context.Context, _ resolver.ModelInfo) (int, error) {
		calls = append(calls, "dialed")
		return http.StatusInternalServerError, assert.AnError
	})

	require.Error(t, err)
	var refusal *router.PolicyError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, http.StatusBadRequest, refusal.Status)
	assert.Equal(t, router.HintUnsatisfiableErrType, refusal.ErrType)
	assert.Equal(t, router.HintUnsatisfiableCode, refusal.ErrCode)
	assert.Contains(t, refusal.Message, "meta")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, attempts, "a refusal must not produce attempt outcomes")
	assert.Empty(t, calls, "no provider may be dialed for a hint outside the hop bound")
}

// User-access violation (the RT-03 whitelist gate, distinct from the region
// case): the hint moves the hinted candidate to the front, but the API key's
// model whitelist is re-checked per attempt. A hinted candidate the key may
// not call is a TERMINAL 403 permission_denied refusal — the hint must never
// route around the denial onto an allowed candidate.
func TestRouteHintRegression_HintedCandidateWhitelistDeniedIsTerminal(t *testing.T) {
	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})
	access := &rt02Access{deny: map[string]bool{"secondary": true}}
	gw.wl = access

	ctx := routehint.WithHint(context.Background(), "anthropic")
	var gated, dials []string
	_, _, attempts, err := gw.executeFallback(ctx, primary, func(fnCtx context.Context, info resolver.ModelInfo) (int, error) {
		gated = append(gated, info.ModelName)
		_, pol := gw.gateAttemptCandidate(fnCtx, candidateIdentity{OrgID: "org-1", APIKeyID: "key-1"}, "m", info)
		if pol != nil {
			return pol.Status, pol
		}
		dials = append(dials, info.Provider)
		return http.StatusInternalServerError, assert.AnError
	})
	require.Error(t, err)
	var pol *router.PolicyError
	require.ErrorAs(t, err, &pol)
	assert.Equal(t, http.StatusForbidden, pol.Status, "a whitelist denial stays the gate's 403 refusal")
	assert.Equal(t, apierrors.ErrorCodePermissionDenied, pol.ErrType)
	_, _, checked := access.seen()
	assert.Equal(t, []string{"secondary"}, checked, "only the hinted candidate is whitelist-checked — no routing around the denial")
	assert.Equal(t, []string{"secondary"}, gated)
	assert.Empty(t, dials, "the denied candidate must not be called")
	// The denied candidate surfaces as one failed, terminal attempt (RT-03).
	require.Len(t, attempts, 1)
	assert.Equal(t, "anthropic", attempts[0].Provider)
	assert.False(t, attempts[0].Success)
}
