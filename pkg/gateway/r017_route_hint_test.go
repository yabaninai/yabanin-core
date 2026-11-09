package cli

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// hintProviderResolver resolves failover names to fixed providers (no DB).
type hintProviderResolver struct {
	providerByModel map[string]string
}

func (r hintProviderResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	p := r.providerByModel[name]
	return resolver.ModelInfo{ModelName: name, Provider: p}
}

// routeHintYAML is the minimal enforce policy carrying one route_hint step
func routeHintYAML(name, target string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: pick\n    route_hint: " + target + "\n"
}

// hintChainGateway returns a hook-test gateway with the fallback executor
// wired over a primary ("openai") and two failover candidates.
func hintChainGateway(rt *PolicyRuntime, res router.ModelResolver) (*gateway, resolver.ModelInfo) {
	gw := testHookGateway(rt)
	gw.fallback = router.NewFallbackExecutor(res, 3, testLogger())
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "openai",
		FailoverModels: []string{"secondary", "tertiary"},
	}
	return gw, primary
}

// providersOf runs the chain and records the provider order attempted.
func providersOf(t *testing.T, gw *gateway, ctx context.Context, primary resolver.ModelInfo) []string {
	t.Helper()
	var calls []string
	_, _, _, err := gw.executeFallback(ctx, primary, func(_ context.Context, info resolver.ModelInfo) (int, error) {
		calls = append(calls, info.Provider)
		return http.StatusInternalServerError, assert.AnError
	})
	require.Error(t, err)
	return calls
}

// influences real provider selection — the hinted provider's candidate is
// attempted first. Before this card the step was a no-op placeholder and the
// chain ran in declaration order (openai first).
func TestRouteHint_EnforcePolicySteersProviderSelection(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})

	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	w, r := policyRequest(string(body))
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok, "hint policy must not block: %s", w.Body.String())

	// The hint rode the request context after evaluation.
	require.Equal(t, "anthropic", routehint.HintFrom(r.Context()))

	// The decision record shows the applied hint (OP-9 visibility).
	decisions := parseDecisions(t, policyEvent)
	require.Len(t, decisions, 1)
	require.Len(t, decisions[0].Findings, 1)
	assert.Equal(t, routehint.FindingCategory, decisions[0].Findings[0].Category)

	// The fallback chain prefers the hinted provider, keeping every
	// candidate: anthropic first, then the original declaration order.
	assert.Equal(t, []string{"anthropic", "openai", "meta"},
		providersOf(t, gw, r.Context(), primary))
}

// Global shadow mode must not change routing: the downgraded policy never
// records a hint and the chain stays in declaration order.
func TestRouteHint_GlobalShadowNeverSteers(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeShadow)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})

	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	w, r := policyRequest(string(body))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok)

	assert.Empty(t, routehint.HintFrom(r.Context()))
	assert.Equal(t, []string{"openai", "anthropic", "meta"},
		providersOf(t, gw, r.Context(), primary))
}

// the route and must refuse explicitly — 400 route_hint_unsatisfiable, raised
// before any provider is attempted (no dial, no partial outcome), and
// deterministic when the same request repeats.
func TestRouteHint_UnmatchedHintRefusedExplicitly(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "vertex")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})

	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	w, r := policyRequest(string(body))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok)

	require.Equal(t, "vertex", routehint.HintFrom(r.Context()))

	var calls []string
	_, status, attempts, err := gw.executeFallback(r.Context(), primary, func(_ context.Context, info resolver.ModelInfo) (int, error) {
		calls = append(calls, info.Provider)
		return http.StatusInternalServerError, assert.AnError
	})
	require.Error(t, err)
	var refusal *router.PolicyError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, http.StatusBadRequest, refusal.Status)
	assert.Equal(t, router.HintUnsatisfiableErrType, refusal.ErrType)
	assert.Equal(t, router.HintUnsatisfiableCode, refusal.ErrCode)
	assert.Contains(t, refusal.Message, "vertex")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, attempts, "a refusal must not produce attempt outcomes")
	assert.Empty(t, calls, "a refusal must not dial any provider")

	// Repeat determinism: the same request refuses identically.
	_, status2, attempts2, err2 := gw.executeFallback(r.Context(), primary, func(_ context.Context, info resolver.ModelInfo) (int, error) {
		calls = append(calls, info.Provider)
		return http.StatusInternalServerError, assert.AnError
	})
	require.ErrorAs(t, err2, &refusal)
	assert.Equal(t, status, status2)
	assert.Len(t, attempts2, len(attempts))
	assert.Empty(t, calls, "the repeated request must still not dial any provider")
}

// front, but every candidate still passes the per-attempt gate. A hinted
// provider the identity may not use is a TERMINAL gate refusal — the hint
// must never route around the denial onto an allowed provider.
func TestRouteHint_HintedCandidateAccessDeniedIsTerminal(t *testing.T) {
	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce)
	gw, primary := hintChainGateway(rt, hintProviderResolver{providerByModel: map[string]string{
		"secondary": "anthropic",
		"tertiary":  "meta",
	}})
	gw.residencyEnforcer = r017DenyProvider{deny: "anthropic"}

	ctx := routehint.WithHint(context.Background(), "anthropic")
	var gated, dials []string
	_, _, attempts, err := gw.executeFallback(ctx, primary, func(fnCtx context.Context, info resolver.ModelInfo) (int, error) {
		gated = append(gated, info.ModelName)
		_, pol := gw.gateAttemptCandidate(fnCtx, candidateIdentity{OrgID: "org-1"}, "m", info)
		if pol != nil {
			return pol.Status, pol
		}
		dials = append(dials, info.Provider)
		return http.StatusInternalServerError, assert.AnError
	})
	require.Error(t, err)
	var pol *router.PolicyError
	require.ErrorAs(t, err, &pol)
	assert.Equal(t, http.StatusForbidden, pol.Status, "an access denial stays the gate's 403 refusal")
	assert.Equal(t, "residency_policy_violation", pol.ErrType)
	assert.Equal(t, []string{"secondary"}, gated, "only the hinted candidate is gated — no routing around the denial")
	assert.Empty(t, dials, "the denied candidate must not be called")
	// The denied candidate surfaces as one failed, terminal attempt (RT-03).
	require.Len(t, attempts, 1)
	assert.Equal(t, "anthropic", attempts[0].Provider)
	assert.False(t, attempts[0].Success)
}

// r017DenyProvider is a residency enforcer double denying one provider.
type r017DenyProvider struct{ deny string }

func (d r017DenyProvider) Enforce(_ context.Context, _ string, _ string, _ policy.Region, provider string) policy.Decision {
	if provider == d.deny {
		return policy.Decision{Allowed: false, Region: policy.Region("GLOBAL"), Reason: "provider outside region"}
	}
	return policy.Decision{Allowed: true, Region: policy.Region("GLOBAL")}
}

// no fallback chain, so an enforce-mode hint foreign to the serving provider
// is unsatisfiable and refuses with the same 400 envelope; an empty hint and
// a hint matching the serving provider proceed.
func TestEnforceSingularRouteHint(t *testing.T) {
	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	// No hint (no policy / shadow / runtime off) → proceed untouched.
	rec, r := policyRequest("{}")
	assert.True(t, gw.enforceSingularRouteHint(rec, r, "openai"))
	assert.Empty(t, rec.Body.String(), "no hint must not write anything")

	// Hint naming the serving provider → proceed untouched.
	rec, r = policyRequest("{}")
	r = r.WithContext(routehint.WithHint(r.Context(), "anthropic"))
	assert.True(t, gw.enforceSingularRouteHint(rec, r, "anthropic"))
	assert.Empty(t, rec.Body.String())

	// Foreign hint → explicit refusal before any reservation.
	rec, r = policyRequest("{}")
	r = r.WithContext(routehint.WithHint(r.Context(), "vertex"))
	assert.False(t, gw.enforceSingularRouteHint(rec, r, "openai"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), router.HintUnsatisfiableCode)
	assert.Contains(t, rec.Body.String(), router.HintUnsatisfiableErrType)
	assert.Contains(t, rec.Body.String(), "vertex")
}

// The chat JSON entrypoint carries the hint from the request onto the
// downstream context (withRequestRouteHint), which is what the stream path
// reads through streamCtx.
func TestWithRequestRouteHint_CopiesFromRequest(t *testing.T) {
	base := context.Background()
	r, err := http.NewRequestWithContext(base, http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	require.NoError(t, err)
	assert.Empty(t, routehint.HintFrom(withRequestRouteHint(base, r)))

	r = r.WithContext(routehint.WithHint(r.Context(), "anthropic"))
	ctx := withRequestRouteHint(base, r)
	assert.Equal(t, "anthropic", routehint.HintFrom(ctx))
	assert.Empty(t, routehint.HintFrom(base), "source context untouched")
}
