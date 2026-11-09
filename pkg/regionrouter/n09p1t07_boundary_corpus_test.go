package regionrouter

// N09-P01-T07 boundary regression corpus — the region failover seam
// (pkg/regionrouter).
//
// The packet acceptance and per-kind selection are pinned by
// failover_policy_test.go (denied peer never used during outage, per-kind
// allowlist selection, custom egress kind). This corpus adds the regression
// dimension those leave open: WHEN the policy source is consulted at all —
// the failover-only boundary — and whether the refusal message counts every
// denied peer when several healthy candidates are all excluded.
//
// Two properties are pinned here:
//  1. The org's policy is read only on the failover path. A healthy home
//     region (local or remote) and a pinned org with a down home region all
//     decide WITHOUT a policy consult — zero reads means zero chances for
//     a policy-source outage to turn a healthy route into an incident.
//     Only a non-pinned org whose home region is down reaches the policy.
//  2. When several healthy peers are all denied, the explanation accounts
//     for them all — every denied peer appears in the refusal, not just the
//     first one (N09-P05-T04: one typed reason record per peer, so
//     operators size the outage per region).

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// TestN09P1T07_Boundary_PolicyConsultedOnlyOnFailoverPath pins the consult
// boundary: three decide-without-consulting paths (home==local, healthy
// remote home, pinned+down) and the one path that must consult (non-pinned
// org, home down, failover permitted).
func TestN09P1T07_Boundary_PolicyConsultedOnlyOnFailoverPath(t *testing.T) {
	tests := []struct {
		name        string
		assignment  Assignment
		healthy     []string // regions with a live health probe
		policy      sovereign.Policy
		wantErrSub  string // empty means no error expected
		wantConsult bool   // whether the policy source must be consulted
	}{
		{
			// A policy that would deny sg must not flip the healthy-local
			// decision — proving it was never read.
			name:       "home is the local region — decided without policy",
			assignment: Assignment{HomeRegion: "sg"},
			healthy:    []string{"sg"},
			policy:     sovereign.Policy{ExcludedCountries: []string{"SG"}},
			wantErrSub: "",
		},
		{
			name:       "remote home is healthy — decided without policy",
			assignment: Assignment{HomeRegion: "in"},
			healthy:    []string{"in"},
			policy:     sovereign.Policy{ExcludedCountries: []string{"SG"}},
			wantErrSub: "",
		},
		{
			name:        "pinned org with down home — refused before policy",
			assignment:  Assignment{HomeRegion: "in", ResidencyPinned: true},
			healthy:     []string{"sg"},
			policy:      sovereign.Policy{ExcludedCountries: []string{"SG"}},
			wantErrSub:  "pinned org cannot failover",
			wantConsult: false,
		},
		{
			name:        "non-pinned org with down home — the only consult path",
			assignment:  Assignment{HomeRegion: "in"},
			healthy:     []string{"sg"},
			policy:      sovereign.Policy{},
			wantErrSub:  "redirect to sg",
			wantConsult: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStore{rows: map[string]Assignment{
				"org-1": tt.assignment,
			}}
			router := New(store, newMemKV())
			// The per-row policy: on no-failover rows it would deny sg —
			// if any of those paths consulted it, the decision would flip
			// and the consult counter would move.
			src := &fakePolicySource{policies: map[string]sovereign.Policy{
				"org-1": tt.policy,
			}}
			var peers []PeerURL
			for _, region := range tt.healthy {
				srv := healthyServer(t)
				peers = append(peers, PeerURL{Region: region, URL: srv.URL})
			}
			checker := NewHealthChecker(peers)

			fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).
				WithPolicySource(src)
			err := fe.Decide(context.Background(), "org-1")

			if tt.wantErrSub == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSub,
					"the decision error must carry the expected explanation")
			}
			if tt.wantConsult {
				assert.GreaterOrEqual(t, src.calls, 1,
					"the failover path must consult the org policy")
			} else {
				assert.Equal(t, 0, src.calls,
					"no-failover decisions must never read the policy source")
			}
		})
	}
}

// TestN09P1T07_Boundary_RefusalCountsEveryDeniedPeer pins the multi-peer
// refusal accounting: home region down, BOTH healthy peers excluded by the
// org-wide residency list — the refusal must account for EVERY denied peer,
// not silently stop at the first one. N09-P05-T04 upgraded the refusal from
// a bare count (denied=2) to a typed *ErrFailoverPeersDenied carrying one
// reason record per denied peer; the pin asserts the same intent in the
// richer form (both peers present in the typed records).
func TestN09P1T07_Boundary_RefusalCountsEveryDeniedPeer(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in"},
	}}
	router := New(store, newMemKV())
	src := &fakePolicySource{policies: map[string]sovereign.Policy{
		"org-1": {ExcludedCountries: []string{"SG", "EU"}},
	}}

	sg := healthyServer(t)
	eu := healthyServer(t)
	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: sg.URL},
		{Region: "eu", URL: eu.URL},
	})

	fe := NewFailoverEvaluator(router, checker, regions3(), "sg", nil).
		WithPolicySource(src)
	err := fe.Decide(context.Background(), "org-1")

	require.Error(t, err, "every healthy peer is denied — no redirect may happen")
	assert.NotContains(t, err.Error(), "redirect to",
		"a denied peer must never be selected")
	var denied *ErrFailoverPeersDenied
	require.ErrorAs(t, err, &denied,
		"the refusal must be the typed all-peers-denied error, got: %v", err)
	regions := map[string]bool{}
	for _, d := range denied.Denied {
		regions[d.Region] = true
	}
	assert.True(t, regions["sg"] && regions["eu"],
		"the refusal must account for every denied peer, got: %+v", denied.Denied)
	assert.GreaterOrEqual(t, src.calls, 1)

	// Both denials are metered with the org-wide reason, one per excluded
	// healthy peer.
	for _, country := range []string{"SG", "EU"} {
		got := testutil.ToFloat64(metrics.ResidencyEgressDeniedTotal.
			WithLabelValues("inference", country, "org_excluded"))
		assert.GreaterOrEqual(t, got, float64(1),
			"residency_egress_denied_total{inference,%s,org_excluded} must be counted", country)
	}
}
