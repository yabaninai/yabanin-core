package regionrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// fakePolicySource is a static org→Policy map implementing PolicySource.
type fakePolicySource struct {
	policies map[string]sovereign.Policy
	calls    int
}

func (f *fakePolicySource) Get(_ context.Context, orgID string) sovereign.Policy {
	f.calls++
	if p, ok := f.policies[orgID]; ok {
		return p
	}
	return sovereign.DefaultPolicy()
}

// Compile-time check: *sovereign.PolicyStore must satisfy PolicySource.
var _ PolicySource = (*sovereign.PolicyStore)(nil)

func healthyServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// regions3 is sg (priority 1) < eu (priority 3) with country codes set.
func regions3() config.RegionMap {
	return config.RegionMap{
		"sg": {Name: "sg", Country: "SG", Priority: 1, GatewayURL: "http://sg:8082"},
		"in": {Name: "in", Country: "IN", Priority: 2, GatewayURL: "http://in:8082"},
		"eu": {Name: "eu", Country: "EU", Priority: 3, GatewayURL: "http://eu:8082"},
	}
}

// TestFailoverEvaluator_DeniedPeerNotUsedDuringOutage is the packet
// acceptance: a denied region is NOT used even when the primary route is
// down and the denied peer is the only healthy one. The org gets a 503
// (error) instead of a residency violation.
func TestFailoverEvaluator_DeniedPeerNotUsedDuringOutage(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"SG", "EU"}},
	}}

	// Only sg (denied) is healthy; eu is down.
	srv := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: srv.URL},
		{Region: "eu", URL: "http://localhost:1"},
	})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-1")
	if err == nil {
		t.Fatal("expected error: the only healthy peer is denied by residency policy")
	}
	if !strings.Contains(err.Error(), "denied by egress policy") {
		t.Errorf("error must explain the policy denial, got: %v", err)
	}
	if strings.Contains(err.Error(), "redirect to") {
		t.Errorf("denied peer must never be selected, got: %v", err)
	}
	if src.calls == 0 {
		t.Error("policy source was never consulted")
	}
	if got := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.WithLabelValues("inference", "SG", "org_excluded")); got < 1 {
		t.Errorf("residency_egress_denied_total{inference,SG,org_excluded} = %v, want >= 1", got)
	}
}

// TestFailoverEvaluator_PerKindAllowlistChoosesPermittedPeer: with a
// per-inference allowlist, the failover peer must satisfy the kind profile,
// even when a better-priority peer is denied for that kind.
func TestFailoverEvaluator_PerKindAllowlistChoosesPermittedPeer(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-2": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		// sg has higher failover priority (1 < 3) but inference may only
		// egress to EU for this org.
		"org-2": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference: {AllowedCountries: []string{"EU"}},
		}},
	}}

	sg := healthyServer(t)
	eu := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: eu.URL},
	})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-2")
	if err == nil {
		t.Fatal("expected redirect error")
	}
	if !strings.Contains(err.Error(), "redirect to eu") {
		t.Errorf("must redirect to the permitted eu peer, got: %v", err)
	}
	if got := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.WithLabelValues("inference", "SG", "kind_not_allowed")); got < 1 {
		t.Errorf("residency_egress_denied_total{inference,SG,kind_not_allowed} = %v, want >= 1", got)
	}
}

// TestFailoverEvaluator_CustomEgressKind: WithEgressKind switches the profile
// consulted (e.g. an export coordinator failover uses the export profile).
func TestFailoverEvaluator_CustomEgressKind(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-3": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		// inference denied everywhere, export allowed to SG only.
		"org-3": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressExport: {AllowedCountries: []string{"SG"}},
		}},
	}}

	sg := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{{Region: "sg", URL: sg.URL}})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).
		WithPolicySource(src).
		WithEgressKind(sovereign.EgressExport)

	err := fe.Decide(context.Background(), "org-3")
	if err == nil || !strings.Contains(err.Error(), "redirect to sg") {
		t.Fatalf("export kind must permit sg, got: %v", err)
	}
}

// TestFailoverEvaluator_InvalidEgressKindIgnored: WithEgressKind keeps the
// previous kind on invalid input (defensive; callers pass constants).
func TestFailoverEvaluator_InvalidEgressKindIgnored(t *testing.T) {
	fe := NewFailoverEvaluator(New(&fakeStore{rows: map[string]Assignment{}}, newMemKV()),
		NewHealthChecker([]PeerURL{}), regions3(), "sg", nil)
	fe.WithEgressKind("bogus")
	if fe.egressKind != sovereign.EgressInference {
		t.Errorf("invalid kind must be ignored, got %q", fe.egressKind)
	}
}

// TestFailoverEvaluator_NoPolicySource_BackwardCompat: without a policy
// source the evaluator behaves exactly as before the change (best healthy
// peer wins, no residency filtering).
func TestFailoverEvaluator_NoPolicySource_BackwardCompat(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-4": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())

	sg := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: "http://localhost:1"},
	})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil)

	err := fe.Decide(context.Background(), "org-4")
	if err == nil || !strings.Contains(err.Error(), "redirect to sg") {
		t.Fatalf("expected legacy redirect to best-priority peer sg, got: %v", err)
	}
}

// TestFailoverEvaluator_UnknownOrgUsesDefaultPolicy: an org with no policy
// row keeps the fail-open default (no extra egress constraints).
func TestFailoverEvaluator_UnknownOrgUsesDefaultPolicy(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-5": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{}} // no row

	sg := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{{Region: "sg", URL: sg.URL}})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-5")
	if err == nil || !strings.Contains(err.Error(), "redirect to sg") {
		t.Fatalf("default policy must not restrict failover, got: %v", err)
	}
}

func TestFailoverEvaluator_RegionWithoutCountryAndAllowlist(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-6": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		// Allowlist set but the peer region has no Country configured —
		// fail-closed: the peer cannot prove residency, so it is denied.
		"org-6": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference: {AllowedCountries: []string{"SG"}},
		}},
	}}

	srv := healthyServer(t)
	noCountry := config.RegionMap{
		"sg": {Name: "sg", Priority: 1, GatewayURL: "http://sg:8082"}, // Country unset
		"in": {Name: "in", Priority: 2},
	}
	checker := NewHealthChecker([]PeerURL{{Region: "sg", URL: srv.URL}})

	fe := NewFailoverEvaluator(router, checker, noCountry, "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-6")
	if err == nil || !strings.Contains(err.Error(), "denied by egress policy") {
		t.Fatalf("peer without country must fail closed against an allowlist, got: %v", err)
	}
	if got := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.WithLabelValues("inference", "", "kind_not_allowed")); got < 1 {
		t.Errorf("residency_egress_denied_total{inference,\"\",kind_not_allowed} = %v, want >= 1", got)
	}
}
