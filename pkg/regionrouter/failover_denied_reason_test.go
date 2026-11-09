package regionrouter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/sovereign"
)

// TestDecide_AllPeersDenied_TypedDenialRecords: when EVERY healthy failover
// peer is denied by the org's egress policy, Decide refuses with
// *ErrFailoverPeersDenied carrying one structured record per denied peer —
// the serving-path 503 becomes explainable per region/country/kind/rule
// (N09-P05-T04). The legacy "denied by egress policy" anchor pinned by the
// earlier policy tests stays in the message.
func TestDecide_AllPeersDenied_TypedDenialRecords(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in", ResidencyPinned: false},
	}}
	r := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"SG", "EU"}},
	}}

	// BOTH peers healthy — and both denied (SG, EU on the exclusion list).
	sg := healthyServer(t)
	eu := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: eu.URL},
	})

	fe := NewFailoverEvaluator(r, checker, regions3(), "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-1")
	var denied *ErrFailoverPeersDenied
	if !errors.As(err, &denied) {
		t.Fatalf("Decide()=%v (%T), want *ErrFailoverPeersDenied", err, err)
	}
	if denied.OrgID != "org-1" || denied.Home != "in" || denied.Kind != sovereign.EgressInference {
		t.Fatalf("fields: org=%q home=%q kind=%q", denied.OrgID, denied.Home, denied.Kind)
	}
	if len(denied.Denied) != 2 {
		t.Fatalf("denied peers=%d, want 2 (%+v)", len(denied.Denied), denied.Denied)
	}
	byRegion := map[string]EgressDenial{}
	for _, d := range denied.Denied {
		byRegion[d.Region] = d
	}
	for region, country := range map[string]string{"sg": "SG", "eu": "EU"} {
		d, ok := byRegion[region]
		if !ok {
			t.Fatalf("peer %s missing from denial records: %+v", region, denied.Denied)
		}
		if d.Country != country || d.Kind != sovereign.EgressInference || d.Rule != sovereign.DenialOrgExcluded {
			t.Fatalf("%s denial=%+v, want country=%s kind=inference rule=org_excluded", region, d, country)
		}
	}

	msg := err.Error()
	for _, want := range []string{
		"denied by egress policy", // legacy anchor (existing message pins)
		"home region in",
		"org=org-1",
		"kind=inference",
		"sg=SG/inference/org_excluded",
		"eu=EU/inference/org_excluded",
		ResidencyDisclosure,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "redirect to") {
		t.Fatalf("denied peers must never be selected, got: %q", msg)
	}
}

// TestDecide_PartialDenialRedirects: a typed all-peers-denied refusal is
// raised ONLY when no permitted peer remains — one permitted peer wins and
// the evaluator redirects as before.
func TestDecide_PartialDenialRedirects(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-2": {HomeRegion: "in", ResidencyPinned: false},
	}}
	r := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-2": {ExcludedCountries: []string{"SG"}}, // eu stays permitted
	}}

	sg := healthyServer(t)
	eu := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: eu.URL},
	})

	fe := NewFailoverEvaluator(r, checker, regions3(), "sg", nil).WithPolicySource(src)

	err := fe.Decide(context.Background(), "org-2")
	var denied *ErrFailoverPeersDenied
	if errors.As(err, &denied) {
		t.Fatalf("permitted peer eu exists, got typed refusal: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "redirect to eu") {
		t.Fatalf("expected redirect to eu, got: %v", err)
	}
}

// TestErrFailoverPeersDenied_Rendering: the empty denial set renders as
// [none] (defensive), populated sets render one record per peer and always
// carry the disclosure.
func TestErrFailoverPeersDenied_Rendering(t *testing.T) {
	empty := (&ErrFailoverPeersDenied{OrgID: "org-3", Home: "zz", Kind: sovereign.EgressInference}).Error()
	if !strings.Contains(empty, "denied=[none]") {
		t.Fatalf("empty denial set must render [none], got %q", empty)
	}

	full := (&ErrFailoverPeersDenied{
		OrgID: "org-4",
		Home:  "in",
		Kind:  sovereign.EgressEmbeddings,
		Denied: []EgressDenial{
			{Region: "eu", Country: "EU", Kind: sovereign.EgressEmbeddings, Rule: sovereign.DenialKindNotAllowed},
		},
	}).Error()
	for _, want := range []string{
		"denied by egress policy",
		"eu=EU/embeddings/kind_not_allowed",
		ResidencyDisclosure,
	} {
		if !strings.Contains(full, want) {
			t.Fatalf("error %q must contain %q", full, want)
		}
	}
}
