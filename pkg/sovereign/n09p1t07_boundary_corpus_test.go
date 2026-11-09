package sovereign

// N09-P01-T07 boundary regression corpus — the sovereignty seam
// (pkg/sovereign).
//
// The pairwise composition rules are pinned by egress_test.go
// (TestCheckEgress_PerKindProfile and the allowlist/exclusion cases). This
// corpus adds the regression dimension those pairwise cases leave open: the
// FULL precedence ORDER when every rule fires at once, and the one
// all-clear combination. The order is load-bearing for operator surface:
// kind_excluded is the most specific explanation, kind_not_allowed the
// next, org_excluded the catch-all — a drift in the order silently changes
// which reason admin screens and alerts report for the same config.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestN09P1T07_Boundary_DenialReasonPrecedenceOrder pins the documented
// precedence chain of CheckEgress for a country that every rule condemns:
// per-kind exclusion wins over the per-kind allowlist gap, which wins over
// the org-wide exclusion; with no per-kind profile the org-wide exclusion
// alone explains the denial; and an allowlisted country with an empty
// org-wide list is allowed — the org-wide list applies on top, never
// instead.
func TestN09P1T07_Boundary_DenialReasonPrecedenceOrder(t *testing.T) {
	tests := []struct {
		name       string
		policy     Policy
		country    string
		wantOK     bool
		wantReason DenialReason
	}{
		{
			name: "kind_excluded wins over allowlist gap and org-wide exclusion",
			policy: Policy{
				ExcludedCountries: []string{"CN", "RU"},
				Egress: map[EgressKind]EgressProfile{
					EgressInference: {
						AllowedCountries:  []string{"SG", "IN"},
						ExcludedCountries: []string{"RU"},
					},
				},
			},
			country:    "ru",
			wantOK:     false,
			wantReason: DenialKindExcluded,
		},
		{
			name: "kind_not_allowed wins over org-wide exclusion",
			policy: Policy{
				ExcludedCountries: []string{"CN", "RU"},
				Egress: map[EgressKind]EgressProfile{
					EgressInference: {AllowedCountries: []string{"SG", "IN"}},
				},
			},
			country:    "RU",
			wantOK:     false,
			wantReason: DenialKindNotAllowed,
		},
		{
			name: "org_excluded alone explains it without a per-kind profile",
			policy: Policy{
				ExcludedCountries: []string{"CN", "RU"},
			},
			country:    "RU",
			wantOK:     false,
			wantReason: DenialOrgExcluded,
		},
		{
			name: "allowlist match with empty org-wide list is allowed",
			policy: Policy{
				Egress: map[EgressKind]EgressProfile{
					EgressInference: {AllowedCountries: []string{" sg ", "in"}},
				},
			},
			country: "SG",
			wantOK:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := tt.policy.CheckEgress(EgressInference, tt.country)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantReason, reason,
				"the reported denial reason is the regression boundary")
		})
	}
}
