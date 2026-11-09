package regionrouter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// N09-P05-T05 negative-scenario battery (packet kind=negative). Two teeth:
//
//  1. ACCEPTANCE «Denied region не используется даже при outage основного
//     маршрута» — pinned as a TEMPORAL regression: health flips between
//     decision phases, and a policy-denied region is never selected at ANY
//     phase (an outage cannot resurrect it, and restoration cannot leak it).
//     T04's tests pin static topologies; this battery pins the transitions.
//
//  2. NEGATIVE criterion «Country endpoint не выдаётся за юридическую
//     гарантию residency» — pinned as a cross-package process control: every
//     routing surface that names a country-bound endpoint or a country-
//     scoped exclusion (regionrouter + sovereign + router) carries the exact
//     canonical non-claim sentence and never an affirmative guarantee claim.

// healthToggleServer is an httptest peer whose /health answers according to
// an atomic toggle, so a battery can flip the health snapshot between
// decision phases (what a real peer outage does between two decisions).
type healthToggleServer struct {
	srv     *httptest.Server
	healthy atomic.Bool
}

func newHealthToggleServer(t *testing.T) *healthToggleServer {
	t.Helper()
	s := &healthToggleServer{}
	s.healthy.Store(false)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s.healthy.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// evaluatorForPhase builds a fresh evaluator over the same store, policy and
// peer set. A fresh HealthChecker holds no cache, so the phase's decision
// consumes a fresh health snapshot — exactly what the 5s TTL expiry yields
// between two real decisions around an outage. No wall-clock sleeps.
func evaluatorForPhase(store *fakeStore, src PolicySource, peers []PeerURL) *FailoverEvaluator {
	r := New(store, newMemKV())
	fe := NewFailoverEvaluator(r, NewHealthChecker(peers), regions3(), "sg", nil)
	return fe.WithPolicySource(src)
}

// TestN09P5T05_OutageTransitionNeverResurrectsDeniedRegion is the packet
// acceptance as a temporal regression. Org policy excludes SG; the home
// region "in" is down throughout (not in the peer health set); peers are
// sg (DENIED) and eu (permitted). Four phases:
//
//	1: eu healthy, sg down            → redirect to eu
//	2: eu down, sg healthy (denied!)  → typed refusal, never redirect to sg
//	3: both down                      → plain no-healthy-peer refusal
//	4: eu restored, sg down           → redirect to eu again
//
// At every phase the serving error must never propose "redirect to sg" and
// the plan's route chain must never contain sg: health transitions cannot
// resurrect a denied region, and the refusal is never hidden.
func TestN09P5T05_OutageTransitionNeverResurrectsDeniedRegion(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-n09p5": {HomeRegion: "in", ResidencyPinned: false},
	}}
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-n09p5": {ExcludedCountries: []string{"SG"}},
	}}

	sg := newHealthToggleServer(t)
	eu := newHealthToggleServer(t)
	peers := []PeerURL{{Region: "sg", URL: sg.srv.URL}, {Region: "eu", URL: eu.srv.URL}}

	setPhase := func(sgHealthy, euHealthy bool) *FailoverEvaluator {
		sg.healthy.Store(sgHealthy)
		eu.healthy.Store(euHealthy)
		return evaluatorForPhase(store, src, peers)
	}
	// denyLeak asserts the negative invariant for one phase outcome.
	denyLeak := func(t *testing.T, phase string, err error, plan FallbackPlan) {
		t.Helper()
		if err != nil && strings.Contains(err.Error(), "redirect to sg") {
			t.Errorf("phase %s: denied region sg became a redirect target: %v", phase, err)
		}
		for _, r := range plan.Route() {
			if r == "sg" {
				t.Errorf("phase %s: denied region sg leaked into the route chain %v", phase, plan.Route())
			}
		}
	}

	// Phase 1: permitted peer healthy → redirect to eu.
	fe := setPhase(false, true)
	err := fe.Decide(context.Background(), "org-n09p5")
	plan := fe.PlanFailoverChain(context.Background(), "org-n09p5", ClassInference)
	denyLeak(t, "1", err, plan)
	if err == nil || !strings.Contains(err.Error(), "redirect to eu") {
		t.Fatalf("phase 1: want redirect to eu, got %v", err)
	}
	if !strings.Contains(err.Error(), ResidencyDisclosure) {
		t.Errorf("phase 1: redirect surface must carry the non-claim disclosure, got %v", err)
	}
	if got := plan.Route(); len(got) != 2 || got[0] != "in" || got[1] != "eu" {
		t.Errorf("phase 1: Route() = %v, want [in eu]", got)
	}

	// Phase 2: the OUTAGE hits the permitted peer; the only healthy peer is
	// the denied one. The refusal must be typed, explainable and disclosed —
	// not a silent failure and never a fallback into sg.
	fe = setPhase(true, false)
	err = fe.Decide(context.Background(), "org-n09p5")
	plan = fe.PlanFailoverChain(context.Background(), "org-n09p5", ClassInference)
	denyLeak(t, "2", err, plan)
	var denied *ErrFailoverPeersDenied
	if !errors.As(err, &denied) {
		t.Fatalf("phase 2: want *ErrFailoverPeersDenied, got %v (%T)", err, err)
	}
	if len(denied.Denied) != 1 || denied.Denied[0].Region != "sg" ||
		denied.Denied[0].Country != "SG" || denied.Denied[0].Rule != sovereign.DenialOrgExcluded {
		t.Errorf("phase 2: denial records = %+v, want sg=SG/inference/org_excluded", denied.Denied)
	}
	msg := err.Error()
	for _, want := range []string{"denied by egress policy", "sg=SG/inference/org_excluded", ResidencyDisclosure} {
		if !strings.Contains(msg, want) {
			t.Errorf("phase 2: refusal must contain %q, got %q", want, msg)
		}
	}
	if got := plan.Route(); len(got) != 1 || got[0] != "in" {
		t.Errorf("phase 2: Route() = %v, want [in] only", got)
	}

	// Phase 3: everything is down — still no denied fallback, still a
	// surfaced refusal.
	fe = setPhase(false, false)
	err = fe.Decide(context.Background(), "org-n09p5")
	plan = fe.PlanFailoverChain(context.Background(), "org-n09p5", ClassInference)
	denyLeak(t, "3", err, plan)
	if err == nil || !strings.Contains(err.Error(), "no healthy peer") {
		t.Fatalf("phase 3: want no-healthy-peer refusal, got %v", err)
	}

	// Phase 4: the permitted peer is restored — routing resumes through eu,
	// the denied region stays out.
	fe = setPhase(false, true)
	err = fe.Decide(context.Background(), "org-n09p5")
	plan = fe.PlanFailoverChain(context.Background(), "org-n09p5", ClassInference)
	denyLeak(t, "4", err, plan)
	if err == nil || !strings.Contains(err.Error(), "redirect to eu") {
		t.Fatalf("phase 4: want redirect restored to eu, got %v", err)
	}
	if got := plan.Route(); len(got) != 2 || got[1] != "eu" {
		t.Errorf("phase 4: Route() = %v, want [in eu]", got)
	}
}

// TestN09P5T05_CrossSurface_NonClaimGuard is the verifiable process control
// for the packet negative criterion: EVERY routing surface that names a
// country-bound endpoint or a country-scoped exclusion — across
// regionrouter, sovereign and router — must (a) carry the exact canonical
// non-claim sentence, (b) never make an affirmative guarantee claim (every
// "guarantee" mention sits inside the sentence), and (c) the package alias
// must stay byte-identical to the canonical source of truth.
func TestN09P5T05_CrossSurface_NonClaimGuard(t *testing.T) {
	// (c) alias integrity: one source of truth, no local drift.
	if ResidencyDisclosure != sovereign.ResidencyDisclosure {
		t.Fatalf("regionrouter alias drifted from sovereign canonical:\n alias %q\n canonical %q",
			ResidencyDisclosure, sovereign.ResidencyDisclosure)
	}

	plan := FallbackPlan{OrgID: "org-x", Class: ClassLogs, Home: "in"}
	surfaces := map[string]string{
		"canonical":          sovereign.ResidencyDisclosure,
		"alias":              ResidencyDisclosure,
		"plan-disclosure":    plan.Disclosure(),
		"redirect-error":     redirectError("sg", "http://sg:8082").Error(),
		"redirect-error-alt": redirectError("eu-central", "http://eu-gw.internal:9").Error(),
		"peers-denied-error": (&ErrFailoverPeersDenied{
			OrgID: "org-x", Home: "in", Kind: sovereign.EgressInference,
			Denied: []EgressDenial{{Region: "sg", Country: "SG", Kind: sovereign.EgressInference, Rule: sovereign.DenialOrgExcluded}},
		}).Error(),
		"no-region-error": (&ErrNoPermittedRegion{
			OrgID: "org-x", Class: ClassLogs, Home: "in",
			Denied: []EgressDenial{{Region: "sg", Country: "SG", Kind: sovereign.EgressLogs, Rule: sovereign.DenialOrgExcluded}},
		}).Error(),
		"sovereign-providers-excluded": (&sovereign.ErrProvidersExcluded{
			OrgID: "org-x",
			Excluded: []sovereign.ProviderDenial{{
				ModelName: "m-ru", Provider: "prov-c", Country: "RU",
				VendorHQ: "RU", Reason: sovereign.DenialProviderCountryExcluded,
			}},
		}).Error(),
		"router-no-permitted-provider": (&router.ErrNoPermittedProvider{
			Excluded: []router.ExcludedCandidate{{
				Region: "RU",
				Denial: sovereign.ProviderDenial{
					ModelName: "m-ru", Provider: "ru-model",
					Country: "RU", VendorHQ: "RU", Reason: sovereign.DenialProviderCountryExcluded,
				},
			}},
		}).Error(),
	}

	for name, s := range surfaces {
		if !strings.Contains(s, sovereign.ResidencyDisclosure) {
			t.Errorf("%s: surface must carry the canonical non-claim sentence, got %q", name, s)
		}
		if strings.Contains(s, "legal residency guarantee") && !strings.Contains(s, "not a legal residency guarantee") {
			t.Errorf("%s: claims a legal residency guarantee: %q", name, s)
		}
		if got, want := strings.Count(s, "guarantee"), strings.Count(s, sovereign.ResidencyDisclosure); got != want {
			t.Errorf("%s: %d guarantee mentions vs %d non-claim sentences (unqualified claim?): %q",
				name, got, want, s)
		}
		if strings.Contains(s, "residency guaranteed") || strings.Contains(s, "guarantees residency") {
			t.Errorf("%s: affirmative residency phrasing leaked: %q", name, s)
		}
	}
}

// Compile-time guard: the cross-surface battery reads only exported router
// API; the import must stay dependency-clean (router must never import
// regionrouter, or the routing layer would grow an import cycle).
var (
	_ = router.ErrNoPermittedProvider{}
	_ config.RegionMap
)
