package regionrouter

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// atomicPolicySource is a race-free static org→Policy source for concurrent
// tests (fakePolicySource's calls counter is not atomic).
type atomicPolicySource struct {
	policies map[string]sovereign.Policy
	calls    atomic.Int64
}

func (s *atomicPolicySource) Get(_ context.Context, orgID string) sovereign.Policy {
	s.calls.Add(1)
	if p, ok := s.policies[orgID]; ok {
		return p
	}
	return sovereign.DefaultPolicy()
}

// newChainFixture builds an evaluator whose home region ("in" by default —
// pass another in rows) is NOT in the peer health set — i.e. the primary
// route is down — while the given peers answer health checks.
func newChainFixture(t *testing.T, rows map[string]Assignment, src PolicySource, regions config.RegionMap, peers []PeerURL) *FailoverEvaluator {
	t.Helper()
	router := New(&fakeStore{rows: rows}, newMemKV())
	fe := NewFailoverEvaluator(router, NewHealthChecker(peers), regions, "sg", nil)
	if src != nil {
		fe.WithPolicySource(src)
	}
	return fe
}

// TestPlanFailoverChain_DeniedPeerExcludedDuringOutage is the packet
// acceptance at chain level: the home region is down, one healthy peer is
// denied by the org's egress policy — it is excluded from the WHOLE chain
// while the permitted peer is chosen. Health never resurrects a denied
// region.
func TestPlanFailoverChain_DeniedPeerExcludedDuringOutage(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"SG"}},
	}}
	sg := healthyServer(t)
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-1": {HomeRegion: "in"}},
		src,
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	// Planning must not touch the denial counters (read-only surface).
	before := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.WithLabelValues("inference", "SG", "org_excluded"))
	plan := fe.PlanFailoverChain(context.Background(), "org-1", ClassInference)
	after := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.WithLabelValues("inference", "SG", "org_excluded"))
	if before != after {
		t.Errorf("planning mutated residency_egress_denied_total: %v → %v", before, after)
	}

	if !plan.HomeAllowed {
		t.Fatalf("home region in must be policy-permitted for inference, denial=%+v", plan.HomeDenial)
	}
	if plan.HomeCountry != "IN" {
		t.Errorf("plan.HomeCountry = %q, want IN", plan.HomeCountry)
	}
	wantHops := []string{"eu"}
	if got := plan.Route(); !reflect.DeepEqual(got, append([]string{"in"}, wantHops...)) {
		t.Errorf("Route() = %v, want [in eu]", got)
	}
	if len(plan.Fallbacks) != 1 || plan.Fallbacks[0].Region != "eu" {
		t.Errorf("Fallbacks = %+v, want [eu]", plan.Fallbacks)
	}
	if plan.Fallbacks[0].Country != "EU" || plan.Fallbacks[0].Priority != 3 {
		t.Errorf("fallback hop metadata wrong: %+v", plan.Fallbacks[0])
	}
	wantDenied := []EgressDenial{{Region: "sg", Country: "SG", Kind: sovereign.EgressInference, Rule: sovereign.DenialOrgExcluded}}
	if !reflect.DeepEqual(plan.Denied, wantDenied) {
		t.Errorf("Denied = %+v, want %+v", plan.Denied, wantDenied)
	}
	for _, r := range plan.Route() {
		if r == "sg" {
			t.Error("denied region sg leaked into the route chain")
		}
	}
	if err := plan.Err(); err != nil {
		t.Errorf("plan.Err() = %v, want nil (route exists)", err)
	}
	if plan.Disclosure() != ResidencyDisclosure {
		t.Error("plan must surface the non-legal-guarantee disclosure")
	}

	// The serving decision path agrees with the plan and names no endpoint
	// as a guarantee.
	err := fe.Decide(context.Background(), "org-1")
	if err == nil || !strings.Contains(err.Error(), "redirect to eu") {
		t.Fatalf("Decide must redirect to the permitted peer eu, got: %v", err)
	}
	if !strings.Contains(err.Error(), ResidencyDisclosure) {
		t.Errorf("redirect surface must carry the non-guarantee disclosure, got: %v", err)
	}
}

// TestPlanFailoverChain_DeniedOnlyPeerNotUsedEvenWhenHealthy: the ONLY
// healthy peer is denied by policy — the plan is empty and the error is the
// 503-shaped refusal, never a redirect into the denied region. This holds
// precisely because the peer is healthy: an outage must not turn a denied
// region into a valid target (fail-closed on outage).
func TestPlanFailoverChain_DeniedOnlyPeerNotUsedEvenWhenHealthy(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-2": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference: {AllowedCountries: []string{"EU"}},
		}},
	}}
	sg := healthyServer(t) // sg is healthy but denied for inference
	fe := newChainFixture(t,
		map[string]Assignment{"org-2": {HomeRegion: "in"}},
		src,
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}},
	)

	plan := fe.PlanFailoverChain(context.Background(), "org-2", ClassInference)
	if plan.HomeAllowed {
		t.Fatal("home in must be denied by the inference allowlist [EU]")
	}
	if plan.HomeDenial == nil || plan.HomeDenial.Kind != sovereign.EgressInference ||
		plan.HomeDenial.Rule != sovereign.DenialKindNotAllowed {
		t.Errorf("home denial must be explainable, got %+v", plan.HomeDenial)
	}
	if len(plan.Fallbacks) != 0 || len(plan.Route()) != 0 {
		t.Errorf("denied-only topology must yield an empty chain, got route=%v hops=%+v", plan.Route(), plan.Fallbacks)
	}
	wantDenied := []EgressDenial{{Region: "sg", Country: "SG", Kind: sovereign.EgressInference, Rule: sovereign.DenialKindNotAllowed}}
	if !reflect.DeepEqual(plan.Denied, wantDenied) {
		t.Errorf("Denied = %+v, want %+v", plan.Denied, wantDenied)
	}

	err := plan.Err()
	if err == nil {
		t.Fatal("empty plan must produce ErrNoPermittedRegion")
	}
	if _, ok := err.(*ErrNoPermittedRegion); !ok {
		t.Fatalf("Err() type = %T, want *ErrNoPermittedRegion", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "no policy-permitted region") {
		t.Errorf("error must explain the refusal, got: %s", msg)
	}
	if !strings.Contains(msg, "kind_not_allowed") {
		t.Errorf("error must carry the per-peer rule, got: %s", msg)
	}
	if strings.Contains(msg, "redirect to") {
		t.Errorf("refusal must never propose a redirect, got: %s", msg)
	}
	if !strings.Contains(msg, ResidencyDisclosure) {
		t.Errorf("refusal must carry the non-guarantee disclosure, got: %s", msg)
	}
}

// TestPlanFailoverChain_AllClasses_Table: the same org + topology resolves
// DIFFERENT chains per data class — inference, embeddings, logs, tools,
// export each honor their own profile; detectors honor the compound
// (inference AND logs) profile.
func TestPlanFailoverChain_AllClasses_Table(t *testing.T) {
	pol := sovereign.Policy{
		ExcludedCountries: []string{"US"},
		Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference:  {AllowedCountries: []string{"SG", "EU"}},
			sovereign.EgressEmbeddings: {AllowedCountries: []string{"EU"}},
			sovereign.EgressLogs:       {ExcludedCountries: []string{"EU"}},
			sovereign.EgressTools:      {AllowedCountries: []string{"SG"}},
			sovereign.EgressExport:     {AllowedCountries: []string{"EU"}},
		},
	}
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{"org-x": pol}}
	sg := healthyServer(t)
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-x": {HomeRegion: "in"}},
		src,
		regions3(), // in(IN, prio2) sg(SG, prio1) eu(EU, prio3)
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	cases := []struct {
		class     DataClass
		wantRoute []string
		wantDeny  map[string]EgressDenial
	}{
		// The home region "in" is denied by every ALLOWLIST-based profile
		// (IN ∉ {SG,EU}), so allowlisted classes start their route at the
		// first permitted hop; exclusion/exclusion-free profiles keep "in".
		{ClassInference, []string{"sg", "eu"}, map[string]EgressDenial{}},
		{ClassEmbeddings, []string{"eu"}, map[string]EgressDenial{
			"sg": {Region: "sg", Country: "SG", Kind: sovereign.EgressEmbeddings, Rule: sovereign.DenialKindNotAllowed},
		}},
		{ClassLogs, []string{"in", "sg"}, map[string]EgressDenial{
			"eu": {Region: "eu", Country: "EU", Kind: sovereign.EgressLogs, Rule: sovereign.DenialKindExcluded},
		}},
		{ClassTools, []string{"sg"}, map[string]EgressDenial{
			"eu": {Region: "eu", Country: "EU", Kind: sovereign.EgressTools, Rule: sovereign.DenialKindNotAllowed},
		}},
		{ClassExport, []string{"eu"}, map[string]EgressDenial{
			"sg": {Region: "sg", Country: "SG", Kind: sovereign.EgressExport, Rule: sovereign.DenialKindNotAllowed},
		}},
		// detectors: needs inference AND logs — sg passes both, eu fails logs.
		{ClassDetectors, []string{"sg"}, map[string]EgressDenial{
			"eu": {Region: "eu", Country: "EU", Kind: sovereign.EgressLogs, Rule: sovereign.DenialKindExcluded},
		}},
	}
	for _, tc := range cases {
		t.Run(string(tc.class), func(t *testing.T) {
			plan := fe.PlanFailoverChain(context.Background(), "org-x", tc.class)
			got := plan.Route()
			if !reflect.DeepEqual(got, tc.wantRoute) {
				t.Errorf("Route() = %v, want %v", got, tc.wantRoute)
			}
			if len(plan.Denied) != len(tc.wantDeny) {
				t.Fatalf("Denied = %+v, want regions %v", plan.Denied, tc.wantDeny)
			}
			for _, d := range plan.Denied {
				want, ok := tc.wantDeny[d.Region]
				if !ok || d != want {
					t.Errorf("denial %+v, want %+v", d, want)
				}
			}
			if err := plan.Err(); err != nil {
				t.Errorf("plan.Err() = %v, want nil", err)
			}
		})
	}
}

// TestPlanFailoverChain_Deterministic: repeated planning over the same
// inputs yields byte-identical plans, including equal-priority tie-breaks
// (health snapshots iterate a map — order must never leak into the plan).
func TestPlanFailoverChain_Deterministic(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-d": {ExcludedCountries: []string{"US"}}, // permits both peers
	}}
	sg := healthyServer(t)
	eu := healthyServer(t)
	// Equal priorities force the name tie-break.
	regions := config.RegionMap{
		"sg": {Name: "sg", Country: "SG", Priority: 1, GatewayURL: "http://sg:8082"},
		"eu": {Name: "eu", Country: "EU", Priority: 1, GatewayURL: "http://eu:8082"},
		"in": {Name: "in", Country: "IN", Priority: 2, GatewayURL: "http://in:8082"},
	}
	fe := newChainFixture(t,
		map[string]Assignment{"org-d": {HomeRegion: "in"}},
		src,
		regions,
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	want := fe.PlanFailoverChain(context.Background(), "org-d", ClassEmbeddings)
	if !reflect.DeepEqual(want.Route(), []string{"in", "eu", "sg"}) {
		t.Fatalf("equal-priority tie-break must order by name: %v", want.Route())
	}
	for i := 0; i < 15; i++ {
		got := fe.PlanFailoverChain(context.Background(), "org-d", ClassEmbeddings)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("plan #%d differs:\n got %+v\nwant %+v", i, got, want)
		}
	}
}

// TestPlanFailoverChain_HomeDeniedForClass: the home region itself may be
// denied for a NON-inference class (e.g. logs must not even be processed in
// the home country) — the plan marks it, explains why, and still routes
// permitted hops.
func TestPlanFailoverChain_HomeDeniedForClass(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-h": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressLogs: {ExcludedCountries: []string{"SG"}},
		}},
	}}
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-h": {HomeRegion: "sg"}},
		src,
		regions3(), // local region is sg == home
		[]PeerURL{{Region: "eu", URL: eu.URL}},
	)

	plan := fe.PlanFailoverChain(context.Background(), "org-h", ClassLogs)
	if plan.HomeAllowed {
		t.Fatal("home sg must be denied for the logs class")
	}
	if plan.HomeDenial == nil || plan.HomeDenial.Rule != sovereign.DenialKindExcluded || plan.HomeDenial.Kind != sovereign.EgressLogs {
		t.Errorf("home denial = %+v, want logs/kind_excluded", plan.HomeDenial)
	}
	if !reflect.DeepEqual(plan.Route(), []string{"eu"}) {
		t.Errorf("Route() = %v, want [eu]", plan.Route())
	}
	if err := plan.Err(); err != nil {
		t.Errorf("permitted fallback exists, Err() must be nil, got %v", err)
	}

	// With the permitted peer gone too, the class has no legal route.
	fe2 := newChainFixture(t,
		map[string]Assignment{"org-h": {HomeRegion: "sg"}},
		src,
		regions3(),
		[]PeerURL{},
	)
	plan2 := fe2.PlanFailoverChain(context.Background(), "org-h", ClassLogs)
	if err := plan2.Err(); err == nil {
		t.Fatal("home denied and no fallbacks must yield ErrNoPermittedRegion")
	}
}

// TestPlanFailoverChain_PinnedOrgNeverFailsOver: residency-pinned orgs keep
// the home-region-only chain — failover peers are not even consulted.
func TestPlanFailoverChain_PinnedOrgNeverFailsOver(t *testing.T) {
	sg := healthyServer(t)
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-p": {HomeRegion: "in", ResidencyPinned: true}},
		&atomicPolicySource{},
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	plan := fe.PlanFailoverChain(context.Background(), "org-p", ClassInference)
	if !reflect.DeepEqual(plan.Route(), []string{"in"}) {
		t.Errorf("pinned org route = %v, want [in]", plan.Route())
	}
	if len(plan.Fallbacks) != 0 || len(plan.Denied) != 0 {
		t.Errorf("pinned org must not consider peers: hops=%+v denied=%+v", plan.Fallbacks, plan.Denied)
	}
}

// TestPlanFailoverChain_UnknownOrgDefaultPolicy: an org without a policy
// row keeps the fail-open default — every healthy peer is a permitted hop.
func TestPlanFailoverChain_UnknownOrgDefaultPolicy(t *testing.T) {
	sg := healthyServer(t)
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-u": {HomeRegion: "in"}},
		&atomicPolicySource{policies: map[string]sovereign.Policy{}},
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	plan := fe.PlanFailoverChain(context.Background(), "org-u", ClassInference)
	if !reflect.DeepEqual(plan.Route(), []string{"in", "sg", "eu"}) {
		t.Errorf("default policy route = %v, want [in sg eu]", plan.Route())
	}
}

// TestPlanFailoverChain_InvalidClassFailsClosed: an unknown class yields an
// empty denying plan — a future category can never bypass egress policy.
func TestPlanFailoverChain_InvalidClassFailsClosed(t *testing.T) {
	sg := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{"org-i": {HomeRegion: "in"}},
		&atomicPolicySource{},
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}},
	)

	plan := fe.PlanFailoverChain(context.Background(), "org-i", DataClass("widgets"))
	if plan.HomeAllowed || len(plan.Fallbacks) != 0 || len(plan.Route()) != 0 {
		t.Errorf("invalid class must yield an empty plan, got %+v", plan)
	}
	if err := plan.Err(); err == nil {
		t.Fatal("invalid class plan must deny")
	}

	ok, denial := fe.AllowsClass(context.Background(), "org-i", DataClass("widgets"), "sg")
	if ok {
		t.Error("AllowsClass with an invalid class must deny (fail-closed)")
	}
	if denial.Kind != "" || denial.Rule != "" {
		t.Errorf("invalid-class denial markers = (%q, %q), want empty", denial.Kind, denial.Rule)
	}
}

// TestFailoverEvaluator_AllowsClass: per-class region permission including
// the LOCAL region (non-inference surfaces evaluate the region they would
// use — e.g. tools results processed in the local country) and unknown
// regions (fail-closed against allowlists).
func TestFailoverEvaluator_AllowsClass(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-a": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressTools: {ExcludedCountries: []string{"SG"}},
		}},
	}}
	fe := newChainFixture(t,
		map[string]Assignment{"org-a": {HomeRegion: "in"}},
		src,
		regions3(),
		[]PeerURL{},
	)

	ok, denial := fe.AllowsClass(context.Background(), "org-a", ClassTools, "sg")
	if ok {
		t.Error("tools must be denied in SG (kind_excluded)")
	}
	if denial.Rule != sovereign.DenialKindExcluded || denial.Country != "SG" || denial.Region != "sg" {
		t.Errorf("tools denial = %+v, want sg/SG/kind_excluded", denial)
	}
	if ok, _ := fe.AllowsClass(context.Background(), "org-a", ClassInference, "sg"); !ok {
		t.Error("inference must stay permitted in SG")
	}

	// Unknown region: no country known — fails closed against an allowlist.
	src2 := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-b": {Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressLogs: {AllowedCountries: []string{"EU"}},
		}},
	}}
	fe2 := newChainFixture(t,
		map[string]Assignment{"org-b": {HomeRegion: "in"}},
		src2,
		regions3(),
		[]PeerURL{},
	)
	ok, denial = fe2.AllowsClass(context.Background(), "org-b", ClassLogs, "xx")
	if ok {
		t.Error("unknown region must fail closed against an allowlist")
	}
	if denial.Country != "" || denial.Rule != sovereign.DenialKindNotAllowed {
		t.Errorf("unknown-region denial = %+v, want empty country + kind_not_allowed", denial)
	}
}

// TestPlanFailoverChain_MatchesDecideSelection: the chain head agrees with
// the serving decision path (single source of truth for "best permitted
// peer"), for both the permitted and the fully-denied topology.
func TestPlanFailoverChain_MatchesDecideSelection(t *testing.T) {
	cases := []struct {
		name       string
		policy     sovereign.Policy
		wantTarget string // "" → Decide must refuse
	}{
		{"no policy", sovereign.DefaultPolicy(), "sg"},
		{"sg denied", sovereign.Policy{ExcludedCountries: []string{"SG"}}, "eu"},
		{"only eu allowed", sovereign.Policy{Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference: {AllowedCountries: []string{"EU"}},
		}}, "eu"},
		{"everything denied", sovereign.Policy{ExcludedCountries: []string{"SG", "EU"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &atomicPolicySource{policies: map[string]sovereign.Policy{"org-m": tc.policy}}
			sg := healthyServer(t)
			eu := healthyServer(t)
			fe := newChainFixture(t,
				map[string]Assignment{"org-m": {HomeRegion: "in"}},
				src,
				regions3(),
				[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
			)

			plan := fe.PlanFailoverChain(context.Background(), "org-m", ClassInference)
			err := fe.Decide(context.Background(), "org-m")
			if tc.wantTarget == "" {
				if err == nil || !strings.Contains(err.Error(), "denied by egress policy") {
					t.Fatalf("Decide must refuse, got: %v", err)
				}
				// Home "in" is policy-permitted (org-wide excludes cover only
				// SG/EU), so the plan still routes [in] — home health is the
				// local monitor's concern — but offers no fallback hop.
				if plan.Err() != nil {
					t.Errorf("home-permitted plan must not refuse: %v", plan.Err())
				}
				if len(plan.Fallbacks) != 0 || len(plan.Denied) != 2 {
					t.Errorf("both peers must be policy-denied: hops=%+v denied=%+v", plan.Fallbacks, plan.Denied)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "redirect to "+tc.wantTarget) {
				t.Fatalf("Decide redirect = %v, want target %s", err, tc.wantTarget)
			}
			if len(plan.Fallbacks) == 0 || plan.Fallbacks[0].Region != tc.wantTarget {
				t.Errorf("plan head = %+v, want %s", plan.Fallbacks, tc.wantTarget)
			}
		})
	}
}

// TestResidencyDisclosure_NoAffirmativeGuaranteeClaims is the packet
// NEGATIVE criterion: no routing surface presents a country endpoint as a
// legal residency guarantee. Every "guarantee" occurrence on a produced
// surface must sit inside the exact non-claim phrase.
func TestResidencyDisclosure_NoAffirmativeGuaranteeClaims(t *testing.T) {
	surfaces := map[string]string{
		"disclosure":      ResidencyDisclosure,
		"plan-disclosure": (&FallbackPlan{}).Disclosure(),
		"refusal-error": (&ErrNoPermittedRegion{
			OrgID: "o", Class: ClassLogs, Home: "in",
			Denied: []EgressDenial{{Region: "sg", Country: "SG", Kind: sovereign.EgressLogs, Rule: sovereign.DenialOrgExcluded}},
		}).Error(),
		"redirect-error": redirectError("sg", "http://sg:8082").Error(),
	}
	for name, s := range surfaces {
		if strings.Contains(s, "legal residency guarantee") && !strings.Contains(s, "not a legal residency guarantee") {
			t.Errorf("%s claims a legal residency guarantee: %q", name, s)
		}
		if got, want := strings.Count(s, "guarantee"), strings.Count(s, ResidencyDisclosure); got != want {
			t.Errorf("%s has %d guarantee mentions but %d disclosure phrases (unqualified claim?): %q", name, got, want, s)
		}
	}
}

// TestPlanFailoverChain_Concurrent: planners run concurrently for mixed
// orgs/classes (plus the serving path) without data races and without
// diverging from the sequential expectation.
func TestPlanFailoverChain_Concurrent(t *testing.T) {
	src := &atomicPolicySource{policies: map[string]sovereign.Policy{
		"org-denied": {ExcludedCountries: []string{"SG"}},
	}}
	sg := healthyServer(t)
	eu := healthyServer(t)
	fe := newChainFixture(t,
		map[string]Assignment{
			"org-open":   {HomeRegion: "in"},
			"org-denied": {HomeRegion: "in"},
		},
		src,
		regions3(),
		[]PeerURL{{Region: "sg", URL: sg.URL}, {Region: "eu", URL: eu.URL}},
	)

	type key struct {
		org   string
		class DataClass
	}
	want := map[key][]string{}
	for _, org := range []string{"org-open", "org-denied"} {
		for _, class := range []DataClass{ClassInference, ClassLogs, ClassDetectors} {
			want[key{org, class}] = fe.PlanFailoverChain(context.Background(), org, class).Route()
		}
	}

	var wg sync.WaitGroup
	classes := []DataClass{ClassInference, ClassLogs, ClassDetectors}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				org := []string{"org-open", "org-denied"}[(g+i)%2]
				class := classes[(g+i)%len(classes)]
				got := fe.PlanFailoverChain(context.Background(), org, class).Route()
				if !reflect.DeepEqual(got, want[key{org, class}]) {
					t.Errorf("concurrent plan %s/%s = %v, want %v", org, class, got, want[key{org, class}])
					return
				}
			}
		}(g)
	}
	// The serving decision path coexists with planners.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = fe.Decide(context.Background(), "org-open")
		}
	}()
	wg.Wait()
}
